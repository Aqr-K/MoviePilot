"""收集 feedback-issue 提交流程需要的本地诊断日志。"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from feedback_issue_common import (
    MAX_LOGS_CHARS,
    feedback_runtime_dir,
    result_payload,
    runtime_file,
    sanitize_logs,
    settings,
    write_json_file,
)


_MAX_READ_BYTES = 512 * 1024
_DEFAULT_TIME_WINDOW_MINUTES = 30
_MIN_TIME_WINDOW_MINUTES = 5
_MAX_TIME_WINDOW_MINUTES = 24 * 60

_LOG_TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})")
_LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
_LOG_MODULE_RE = re.compile(
    r"^【[^】]+】\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d+\s+-\s+([^\s][^\-]*?)\s+-\s+"
)

_META_NOISE_MODULES = frozenset({
    "collect_feedback_diagnostics.py",
    "prepare_feedback_issue.py",
    "submit_feedback_issue.py",
    "ask_user_choice.py",
    "base.py",
    "agent",
    "factory.py",
    "callback",
    "prompt",
    "memory.py",
    "activity_log.py",
    "message.py",
    "event.py",
    "chain",
    "discord",
    "telegram",
    "telegram.py",
    "execute_command.py",
})

_VAGUE_KEYWORDS = frozenset({
    "错误", "异常", "失败", "error", "exception", "failed", "warn", "warning",
    "日志", "问题", "bug", "log", "logs",
})

_FEEDBACK_VERB_PHRASES: tuple[str, ...] = (
    "反馈", "提交", "上报", "汇报",
    "提 issue", "提issue", "提 bug", "提bug",
    "报 bug", "报bug", "报告 bug", "报告bug",
    "新建 issue", "新建issue", "开 issue", "开issue",
    "让上游", "给上游",
    "file an issue", "report a bug", "open an upstream issue",
    "submit an issue", "raise an issue", "report this upstream",
    "report upstream",
)
_FEEDBACK_TARGET_TOKENS: tuple[str, ...] = (
    "issue", "bug", "问题", "错误报告",
    "上游", "mp", "moviepilot",
)
_FEEDBACK_STANDALONE_PHRASES: tuple[str, ...] = (
    "file an issue", "report a bug", "open an upstream issue",
    "submit an issue", "raise an issue", "report this upstream",
    "report upstream",
    "新建 issue", "新建issue", "开 issue", "开issue",
    "提 issue", "提issue", "提 bug", "提bug",
    "报 bug", "报bug", "报告 bug", "报告bug",
    "让上游", "给上游",
)
_FEEDBACK_REGEX_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"提.{0,6}(bug|issue|问题|错误报告)", re.IGNORECASE),
    re.compile(r"报.{0,6}(bug|issue|错误报告)", re.IGNORECASE),
    re.compile(r"反馈.{0,8}(issue|bug|问题|上游|错误)", re.IGNORECASE),
    re.compile(r"开.{0,4}(issue|bug)", re.IGNORECASE),
    re.compile(r"上报.{0,6}(bug|issue|问题|错误)", re.IGNORECASE),
)


def read_tail(path: Path) -> str:
    """读取日志文件尾部，避免大日志一次性进入内存。"""
    try:
        size = path.stat().st_size
        with path.open("rb") as file_obj:
            if size > _MAX_READ_BYTES:
                file_obj.seek(size - _MAX_READ_BYTES)
            return file_obj.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def candidate_log_files() -> list[Path]:
    """返回反馈诊断可读取的主日志和插件日志文件。"""
    files = [settings.LOG_PATH / "moviepilot.log"]
    plugin_log_dir = settings.LOG_PATH / "plugins"
    if plugin_log_dir.exists():
        files.extend(sorted(plugin_log_dir.rglob("*.log")))
    return [path for path in files if path.exists() and path.is_file()]


def normalize_keywords(keywords: Optional[list[str]]) -> list[str]:
    """过滤掉过短或过于宽泛的日志关键词。"""
    normalized: list[str] = []
    for item in keywords or []:
        item = str(item or "").strip()
        if len(item) < 2:
            continue
        if item.lower() in _VAGUE_KEYWORDS:
            continue
        if item not in normalized:
            normalized.append(item)
    return normalized


def has_explicit_feedback_intent(original_user_request: str) -> bool:
    """判断用户原话里是否出现明确要求提 Issue 的意图。"""
    if not original_user_request:
        return False
    normalized = original_user_request.lower().strip()
    if any(phrase in normalized for phrase in _FEEDBACK_STANDALONE_PHRASES):
        return True
    if any(pattern.search(normalized) for pattern in _FEEDBACK_REGEX_PATTERNS):
        return True
    has_verb = any(phrase in normalized for phrase in _FEEDBACK_VERB_PHRASES)
    has_target = any(token in normalized for token in _FEEDBACK_TARGET_TOKENS)
    return has_verb and has_target


def normalize_window(time_window_minutes: int) -> int:
    """把传入的时间窗限制到 5 到 1440 分钟之间。"""
    try:
        window = int(time_window_minutes or _DEFAULT_TIME_WINDOW_MINUTES)
    except (TypeError, ValueError):
        window = _DEFAULT_TIME_WINDOW_MINUTES
    return max(_MIN_TIME_WINDOW_MINUTES, min(_MAX_TIME_WINDOW_MINUTES, window))


def parse_line_timestamp(line: str) -> Optional[datetime]:
    """从一行日志开头提取时间戳；提取不到返回 None。"""
    match = _LOG_TIMESTAMP_RE.search(line[:64])
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), _LOG_TIMESTAMP_FORMAT)
    except ValueError:
        return None


def is_meta_noise(line: str) -> bool:
    """判断日志行是否来自 Agent 自身的工具调度或消息框架噪音。"""
    match = _LOG_MODULE_RE.match(line)
    if not match:
        return False
    return match.group(1).strip() in _META_NOISE_MODULES


def filter_lines(
    text: str,
    keywords: list[str],
    max_lines: int,
    window_start: datetime,
) -> list[str]:
    """按时间窗、模块噪音和关键词筛选日志行。"""
    candidates: list[str] = []
    last_seen_in_window: Optional[bool] = None
    last_seen_was_meta = False
    for line in text.splitlines():
        if not line.strip():
            continue
        timestamp = parse_line_timestamp(line)
        if timestamp is not None:
            in_window = timestamp >= window_start
            meta = is_meta_noise(line)
            last_seen_was_meta = meta
            last_seen_in_window = in_window and not meta
            if in_window and not meta:
                candidates.append(line)
        elif last_seen_in_window and not last_seen_was_meta:
            candidates.append(line)

    if not candidates:
        return []
    if keywords:
        lowered_keywords = [item.lower() for item in keywords]
        matched: list[str] = []
        keep_block = False
        for line in candidates:
            has_timestamp = parse_line_timestamp(line) is not None
            if has_timestamp:
                keep_block = any(keyword in line.lower() for keyword in lowered_keywords)
                if keep_block:
                    matched.append(line)
            elif keep_block:
                matched.append(line)
        if matched:
            return matched[-max_lines:]
    return candidates[-max_lines:]


def collect_diagnostics(
    *,
    original_user_request: str,
    keywords: list[str],
    max_lines: int,
    time_window_minutes: int,
) -> dict:
    """读取日志、筛选、脱敏并写入运行时诊断文件。"""
    if not has_explicit_feedback_intent(original_user_request):
        return {
            "success": False,
            "reason": "no_explicit_feedback_intent",
            "message": (
                "用户原话里没有明确要求向上游反馈 Issue 的短语，"
                "请先回到常规诊断路径；只有明确说出反馈 issue / 提 issue / 报 bug "
                "等意图时才运行 feedback-issue 流程。"
            ),
        }

    normalized_max_lines = min(max(int(max_lines or 80), 20), 200)
    window_minutes = normalize_window(time_window_minutes)
    window_start = datetime.now() - timedelta(minutes=window_minutes)
    normalized_keywords = normalize_keywords(keywords)
    collected: list[str] = []
    source_files: list[str] = []

    for path in candidate_log_files():
        text = read_tail(path)
        if not text:
            continue
        lines = filter_lines(
            text=text,
            keywords=normalized_keywords,
            max_lines=normalized_max_lines,
            window_start=window_start,
        )
        if not lines:
            continue
        source_files.append(str(path))
        collected.append(f"### {path.name}\n" + "\n".join(lines))

    logs = sanitize_logs("\n\n".join(collected), MAX_LOGS_CHARS)
    diagnostics_file = runtime_file("diagnostics", ".json")
    diagnostics = {
        "original_user_request": original_user_request,
        "keywords": normalized_keywords,
        "found": bool(logs.strip()),
        "logs": logs,
        "source_files": source_files,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    write_json_file(diagnostics_file, diagnostics)
    return {
        "success": True,
        "found": diagnostics["found"],
        "diagnostics_file": str(diagnostics_file),
        "runtime_dir": str(feedback_runtime_dir()),
        "source_files": source_files,
        "log_bytes": len(logs.encode("utf-8", errors="replace")),
        "log_lines": len(logs.splitlines()) if logs else 0,
        "message": (
            "已收集并写入反馈诊断日志文件。"
            if logs
            else "已完成诊断日志收集，但未找到明显相关日志。"
        ),
    }


def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="收集 MoviePilot 反馈 Issue 诊断日志")
    parser.add_argument("--original-user-request", required=True, help="触发反馈的用户原话")
    parser.add_argument("--keyword", action="append", default=[], help="用于过滤日志的具体关键词，可重复")
    parser.add_argument("--max-lines", type=int, default=80, help="最多保留的日志行数")
    parser.add_argument(
        "--time-window-minutes",
        type=int,
        default=_DEFAULT_TIME_WINDOW_MINUTES,
        help="只收集最近 N 分钟日志，默认 30",
    )
    return parser.parse_args()


def main() -> int:
    """脚本入口：输出 JSON 结果给 Agent 解析。"""
    args = parse_args()
    result = collect_diagnostics(
        original_user_request=args.original_user_request,
        keywords=args.keyword,
        max_lines=args.max_lines,
        time_window_minutes=args.time_window_minutes,
    )
    print(result_payload(**result))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
