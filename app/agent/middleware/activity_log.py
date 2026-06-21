"""
活动日志中间件 - 自动记录 Agent 每次交互的操作摘要。

按日期存储在 CONFIG_PATH/agent/activity/YYYY-MM-DD.md 中，
每次 Agent 执行完毕后自动调用 LLM 对本轮对话生成简洁的活动摘要，
并在每次 Agent 启动时注入轻量索引，完整日志由工具按需查询。
"""

import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, NotRequired, Optional, TypedDict

from anyio import Path as AsyncPath
from langchain.agents.middleware.types import (
    AgentMiddleware,
    AgentState,
    ContextT,
    ModelRequest,
    ModelResponse,
    PrivateStateAttr,  # noqa
    ResponseT,
)
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.runtime import Runtime

from app.agent.middleware.utils import append_to_system_message
from app.log import logger

# 活动日志保留天数
DEFAULT_RETENTION_DAYS = 7

# 注入系统提示词时索引的天数
PROMPT_LOAD_DAYS = 3

# 工具默认查询的天数
DEFAULT_QUERY_DAYS = 7

# 工具单次返回的最大条数
DEFAULT_QUERY_LIMIT = 20
MAX_QUERY_LIMIT = 50

# 每日日志文件最大大小 (256KB)
MAX_LOG_FILE_SIZE = 256 * 1024

# 提取本轮对话上下文的最大字符数（避免过长的对话消耗太多 token）
MAX_CONTEXT_FOR_SUMMARY = 4000

SUMMARY_SKIP_MARKER = "SKIP"

# LLM 总结的提示词
SUMMARY_PROMPT = """请判断以下 AI 助手与用户的对话是否值得写入 MoviePilot 活动日志。

如果本轮只是问候、寒暄、感谢、确认、闲聊、没有实际任务、没有工具动作、任务没有推进、纯粹的格式纠正或无意义空转，请只输出：SKIP

如果值得记录，请输出一条中文单行活动摘要，要求：
- 40 到 160 个汉字左右，信息密度高，不要写成泛泛一句话。
- 只输出摘要正文，不要标题、编号、Markdown、JSON 或解释。
- 尽量包含：用户目标、关键对象（影片/剧集/站点/路径/任务/设置）、助手采取的关键动作或工具、结果状态、失败原因或下一步。
- 如果有明确 ID、路径、站点名、任务状态、成功/失败数量，请保留关键值。
- 不要记录 API Key、Cookie、Token、密码等敏感信息；如出现请写成“敏感信息已省略”。

推荐格式示例：
用户要求整理 `/downloads/Show`，助手识别为《示例剧》TMDB 12345，并提交 transfer_file 整理，结果成功。
用户排查下载失败，助手查询 qBittorrent 任务和站点状态，发现 tracker 超时，建议更换站点或重试。

对话记录：
{conversation}"""

ACTIVITY_ENTRY_PATTERN = re.compile(r"^-\s+\*\*(?P<time>\d{2}:\d{2})\*\*\s+(?P<summary>.+)$")


def _coerce_query_limit(limit: Optional[int]) -> int:
    """规范化活动日志查询条数。"""
    if limit is None:
        return DEFAULT_QUERY_LIMIT
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_QUERY_LIMIT
    return min(max(value, 1), MAX_QUERY_LIMIT)


def _build_log_path(activity_dir: str, date_str: str) -> Path:
    """构建指定日期的活动日志路径。"""
    return Path(activity_dir) / f"{date_str}.md"


def _iter_recent_dates(days: int) -> list[str]:
    """返回从今天开始向前的日期字符串列表。"""
    normalized_days = max(1, int(days or 1))
    today = datetime.now().date()
    return [
        (today - timedelta(days=index)).strftime("%Y-%m-%d")
        for index in range(normalized_days)
    ]


def _parse_activity_entries(date_str: str, content: str) -> list[dict[str, str]]:
    """从单日活动日志 Markdown 中解析活动条目。"""
    entries: list[dict[str, str]] = []
    for line in content.splitlines():
        match = ACTIVITY_ENTRY_PATTERN.match(line.strip())
        if not match:
            continue
        entries.append(
            {
                "date": date_str,
                "time": match.group("time"),
                "summary": match.group("summary").strip(),
            }
        )
    return entries


def _activity_summary_matches_keyword(
    summary: str,
    keyword: str,
    regex_pattern: Optional[re.Pattern[str]],
) -> bool:
    """判断活动摘要是否命中普通关键词或正则表达式。"""
    if regex_pattern:
        return bool(regex_pattern.search(summary))
    return keyword.lower() in summary.lower()


def load_activity_log_index(activity_dir: str, days: int = PROMPT_LOAD_DAYS) -> dict[str, str]:
    """加载近期活动日志索引，不返回完整日志正文。"""
    index: dict[str, str] = {}
    for date_str in _iter_recent_dates(days):
        log_path = _build_log_path(activity_dir, date_str)
        if not log_path.is_file():
            continue
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"读取活动日志索引失败 {log_path}: {e}")
            continue
        entry_count = len(_parse_activity_entries(date_str, content))
        if entry_count:
            index[date_str] = f"{entry_count} 条活动记录"
    return index


def query_activity_logs(
    activity_dir: str,
    *,
    keyword: Optional[str] = None,
    use_regex: bool = False,
    date: Optional[str] = None,
    days: int = DEFAULT_QUERY_DAYS,
    limit: Optional[int] = DEFAULT_QUERY_LIMIT,
) -> dict[str, Any]:
    """
    查询活动日志条目。

    :param activity_dir: 活动日志目录
    :param keyword: 可选关键词，按摘要文本过滤
    :param use_regex: 是否将关键词按正则表达式匹配
    :param date: 可选日期，格式为 ``YYYY-MM-DD``
    :param days: 未指定日期时向前查询的天数
    :param limit: 返回条数上限
    :return: 查询结果载荷
    """
    normalized_limit = _coerce_query_limit(limit)
    normalized_keyword = str(keyword or "").strip()
    normalized_use_regex = bool(use_regex)
    regex_pattern: Optional[re.Pattern[str]] = None
    if normalized_keyword and normalized_use_regex:
        try:
            regex_pattern = re.compile(normalized_keyword, re.IGNORECASE)
        except re.error as err:
            return {
                "success": False,
                "message": f"无效的活动日志正则表达式: {err}",
                "activity_dir": activity_dir,
                "keyword": normalized_keyword,
                "use_regex": normalized_use_regex,
                "date": date,
                "days": days if not date else None,
                "searched_dates": [],
                "total_count": 0,
                "returned_count": 0,
                "truncated": False,
                "entries": [],
            }
    date_candidates = [date] if date else _iter_recent_dates(days)
    entries: list[dict[str, str]] = []
    searched_dates: list[str] = []

    for date_str in date_candidates:
        if not date_str:
            continue
        searched_dates.append(date_str)
        log_path = _build_log_path(activity_dir, date_str)
        if not log_path.is_file():
            continue
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"读取活动日志失败 {log_path}: {e}")
            continue
        for entry in _parse_activity_entries(date_str, content):
            if normalized_keyword and not _activity_summary_matches_keyword(
                entry["summary"], normalized_keyword, regex_pattern
            ):
                continue
            entries.append(entry)

    entries.sort(key=lambda item: (item["date"], item["time"]), reverse=True)
    total_count = len(entries)
    return {
        "success": True,
        "activity_dir": activity_dir,
        "keyword": normalized_keyword or None,
        "use_regex": normalized_use_regex,
        "date": date,
        "days": days if not date else None,
        "searched_dates": searched_dates,
        "total_count": total_count,
        "returned_count": min(total_count, normalized_limit),
        "truncated": total_count > normalized_limit,
        "entries": entries[:normalized_limit],
    }


class ActivityLogState(AgentState):
    """ActivityLogMiddleware 的状态模型。"""

    activity_log_contents: NotRequired[Annotated[dict[str, str], PrivateStateAttr]]
    """将日期字符串映射到日志索引摘要的字典。标记为私有，不包含在最终代理状态中。"""


class ActivityLogStateUpdate(TypedDict):
    """ActivityLogMiddleware 的状态更新。"""

    activity_log_contents: dict[str, str]


def _extract_last_round(messages: list) -> Optional[list]:
    """从完整消息列表中提取最后一轮交互。

    从最后一条 HumanMessage 到消息末尾即为本轮交互。

    参数：
        messages: Agent 执行后的完整消息列表。

    返回：
        本轮交互的消息子列表，如果无有效交互则返回 None。
    """
    if not messages:
        return None

    # 找到最后一条用户消息的索引
    last_human_idx = None
    for i in range(len(messages) - 1, -1, -1):
        if isinstance(messages[i], HumanMessage) and messages[i].content:
            last_human_idx = i
            break

    if last_human_idx is None:
        return None

    round_messages = messages[last_human_idx:]

    # 检查是否为系统心跳消息
    user_msg = round_messages[0]
    user_content = (
        user_msg.content if isinstance(user_msg.content, str) else str(user_msg.content)
    )
    if user_content.strip().startswith("[System Heartbeat]"):
        return None

    return round_messages


def _format_conversation_for_summary(round_messages: list) -> str:
    """将本轮对话消息格式化为文本，供 LLM 总结。

    参数：
        round_messages: 本轮交互的消息列表。

    返回：
        格式化后的对话文本。
    """
    lines = []
    total_len = 0

    for msg in round_messages:
        if isinstance(msg, HumanMessage):
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            line = f"用户: {content}"
        elif isinstance(msg, AIMessage):
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                tool_names = [
                    tc["name"]
                    for tc in msg.tool_calls
                    if isinstance(tc, dict) and "name" in tc
                ]
                line = f"助手调用工具: {', '.join(tool_names)}"
            elif msg.content:
                content = (
                    msg.content if isinstance(msg.content, str) else str(msg.content)
                )
                line = f"助手: {content}"
            else:
                continue
        elif isinstance(msg, ToolMessage):
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            # 工具返回可能很长，截断
            if len(content) > 200:
                content = content[:200] + "..."
            line = f"工具返回: {content}"
        else:
            continue

        # 控制总长度
        if total_len + len(line) > MAX_CONTEXT_FOR_SUMMARY:
            lines.append("...(后续对话省略)")
            break
        lines.append(line)
        total_len += len(line)

    return "\n".join(lines)


def _should_skip_activity_summary(round_messages: list) -> bool:
    """判断本轮交互是否无需生成活动日志。"""
    if not round_messages:
        return True

    has_tool_activity = any(
        isinstance(msg, ToolMessage)
        or (isinstance(msg, AIMessage) and bool(getattr(msg, "tool_calls", None)))
        for msg in round_messages
    )
    if has_tool_activity:
        return False

    return True


async def _summarize_with_llm(conversation_text: str) -> Optional[str]:
    """调用 LLM 对对话文本生成活动摘要。

    参数：
        conversation_text: 格式化后的对话文本。

    返回：
        LLM 生成的摘要字符串，失败时返回 None。
    """
    try:
        from app.agent.llm import LLMHelper

        llm = await LLMHelper.get_llm(streaming=False)
        prompt = SUMMARY_PROMPT.format(conversation=conversation_text)
        response = await llm.ainvoke(prompt)
        summary = response.content.strip()
        # 清理模型可能输出的前缀（如 "摘要：" "总结："）
        summary = re.sub(r"^(摘要|总结|活动记录)[：:]\s*", "", summary)
        if summary.strip().upper() == SUMMARY_SKIP_MARKER:
            return None
        return summary if summary else None
    except Exception as e:
        logger.debug(f"LLM 活动摘要生成失败: {e}")
        return None


ACTIVITY_LOG_SYSTEM_PROMPT = """<activity_log>
<activity_log_index>
{activity_log_index}
</activity_log_index>

<activity_log_guidelines>
    Activity logs are automatically maintained by the system and are available for continuity, but full log contents are not injected into context by default.

    **How to use this information:**
    - The <activity_log_index> above only lists which recent dates have activity records and how many entries exist.
    - Use `query_activity_log` when the user asks about previous work, asks to continue a prior task, or when recent activity is clearly relevant to the current request.
    - To find related logs, start with a broad search: use the exact date if known; otherwise query recent days with a short keyword, or omit `keyword` and inspect the latest entries. If there are no matches, retry with a larger `days` value or a shorter object/path fragment.
    - `query_activity_log.keyword` is a plain substring by default. Set `use_regex=true` only when matching alternatives or patterns such as multiple titles, paths, or task IDs.
    - Do not query activity logs for routine standalone tasks such as file organization, media recognition, downloads, subscriptions, or diagnostics unless the user explicitly references prior activity.
    - Activity logs are read-only from your perspective. Do not attempt to edit or write to activity log files.
    - For long-term preferences and knowledge, continue to use MEMORY.md.
    - Activity logs are retained for {retention_days} days and then automatically cleaned up.
</activity_log_guidelines>
</activity_log>
"""


class ActivityLogMiddleware(AgentMiddleware[ActivityLogState, ContextT, ResponseT]):  # noqa
    """自动记录 Agent 活动日志并注入轻量索引的中间件。

    - abefore_agent: 加载近几天的活动日志索引
    - awrap_model_call: 将活动日志索引和检索规则注入系统提示词
    - aafter_agent: 从本次对话中提取摘要并追加到当日日志文件

    参数：
        activity_dir: 活动日志存储目录路径。
        retention_days: 日志保留天数（默认 7 天）。
        prompt_load_days: 注入系统提示词时索引的天数（默认 3 天）。
    """

    state_schema = ActivityLogState

    def __init__(
        self,
        *,
        activity_dir: str,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        prompt_load_days: int = PROMPT_LOAD_DAYS,
    ) -> None:
        self.activity_dir = activity_dir
        self.retention_days = retention_days
        self.prompt_load_days = prompt_load_days

    def _get_log_path(self, date_str: str) -> AsyncPath:
        """获取指定日期的日志文件路径。"""
        return AsyncPath(self.activity_dir) / f"{date_str}.md"

    def _format_activity_log(self, contents: dict[str, str]) -> str:
        """格式化活动日志索引用于系统提示词注入。"""
        if not contents:
            return ACTIVITY_LOG_SYSTEM_PROMPT.format(
                activity_log_index="(近期暂无活动日志索引。需要历史上下文时可调用 query_activity_log。)",
                retention_days=self.retention_days,
            )

        # 按日期排序（最近的在前）
        sorted_dates = sorted(contents.keys(), reverse=True)
        sections = []
        for date_str in sorted_dates:
            content = contents[date_str].strip()
            if content:
                sections.append(f"### {date_str}\n{content}")

        if not sections:
            return ACTIVITY_LOG_SYSTEM_PROMPT.format(
                activity_log_index="(近期暂无活动日志索引。需要历史上下文时可调用 query_activity_log。)",
                retention_days=self.retention_days,
            )

        log_body = "\n".join(sections)
        return ACTIVITY_LOG_SYSTEM_PROMPT.format(
            activity_log_index=log_body,
            retention_days=self.retention_days,
        )

    async def _load_recent_logs(self) -> dict[str, str]:
        """加载近几天的活动日志索引。"""
        return load_activity_log_index(
            activity_dir=self.activity_dir,
            days=self.prompt_load_days,
        )

    async def _append_activity(self, summary: str) -> None:
        """将一条活动记录追加到当日日志文件。"""
        today_str = datetime.now().strftime("%Y-%m-%d")
        now_str = datetime.now().strftime("%H:%M")
        log_path = self._get_log_path(today_str)

        # 确保目录存在
        dir_path = AsyncPath(self.activity_dir)
        if not await dir_path.exists():
            await dir_path.mkdir(parents=True, exist_ok=True)

        # 检查文件大小
        if await log_path.exists():
            stat = await log_path.stat()
            if stat.st_size >= MAX_LOG_FILE_SIZE:
                logger.warning(
                    "Activity log %s exceeds size limit (%d bytes), skipping append",
                    today_str,
                    stat.st_size,
                )
                return

        # 追加记录
        entry = f"- **{now_str}** {summary}\n"
        try:
            if await log_path.exists():
                existing = await log_path.read_text(encoding="utf-8", errors="replace")
                await log_path.write_text(existing + entry, encoding="utf-8")
            else:
                header = f"# {today_str} 活动日志\n\n"
                await log_path.write_text(header + entry, encoding="utf-8")
            logger.debug("Activity logged: %s", summary[:80])
        except Exception as e:
            logger.warning("Failed to append activity log: %s", e)

    async def _cleanup_old_logs(self) -> None:
        """清理超过保留天数的旧日志文件。"""
        dir_path = AsyncPath(self.activity_dir)
        if not await dir_path.exists():
            return

        cutoff_date = datetime.now().date() - timedelta(days=self.retention_days)
        date_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2})\.md$")

        try:
            async for path in dir_path.iterdir():
                if not await path.is_file():
                    continue
                match = date_pattern.match(path.name)
                if not match:
                    continue
                try:
                    file_date = datetime.strptime(match.group(1), "%Y-%m-%d").date()
                    if file_date < cutoff_date:
                        await path.unlink()
                        logger.debug("Cleaned up old activity log: %s", path.name)
                except ValueError:
                    continue
        except Exception as e:
            logger.warning("Failed to cleanup old activity logs: %s", e)

    async def abefore_agent(
        self, state: ActivityLogState, runtime: Runtime
    ) -> Optional[ActivityLogStateUpdate]:
        """在 Agent 执行前加载近期活动日志。"""
        # 如果已经加载则跳过
        if "activity_log_contents" in state:
            return None

        contents = await self._load_recent_logs()

        # 趁机清理旧日志（低频操作，不影响性能）
        await self._cleanup_old_logs()

        return ActivityLogStateUpdate(activity_log_contents=contents)

    def modify_request(self, request: ModelRequest[ContextT]) -> ModelRequest[ContextT]:
        """将活动日志注入系统消息。"""
        contents = request.state.get("activity_log_contents", {})  # noqa
        activity_log_prompt = self._format_activity_log(contents)

        new_system_message = append_to_system_message(
            request.system_message, activity_log_prompt
        )
        return request.override(system_message=new_system_message)

    async def awrap_model_call(
        self,
        request: ModelRequest[ContextT],
        handler: Callable[
            [ModelRequest[ContextT]], Awaitable[ModelResponse[ResponseT]]
        ],
    ) -> ModelResponse[ResponseT]:
        """异步包装模型调用，注入活动日志到系统提示词。"""
        modified_request = self.modify_request(request)
        return await handler(modified_request)

    async def aafter_agent(
        self, state: ActivityLogState, runtime: Runtime
    ) -> Optional[dict[str, Any]]:
        """Agent 执行完毕后，调用 LLM 对本轮对话生成摘要并追加到当日活动日志。"""
        try:
            messages = state.get("messages", [])
            if not messages:
                return None

            # 提取本轮交互
            round_messages = _extract_last_round(messages)
            if not round_messages:
                return None
            if _should_skip_activity_summary(round_messages):
                return None

            # 格式化对话文本
            conversation_text = _format_conversation_for_summary(round_messages)
            if not conversation_text:
                return None

            # 调用 LLM 生成摘要
            summary = await _summarize_with_llm(conversation_text)
            if summary:
                await self._append_activity(summary)
        except Exception as e:
            logger.warning("Failed to record activity: %s", e)

        return None


__all__ = [
    "ActivityLogMiddleware",
    "load_activity_log_index",
    "query_activity_logs",
]
