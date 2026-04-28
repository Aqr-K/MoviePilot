"""Agent 根层运行时配置管理。"""

from __future__ import annotations

import re
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from string import Formatter
from typing import Any, Iterable, Optional

import yaml

from app.core.config import settings
from app.log import logger

CURRENT_PERSONA_FILE = "CURRENT_PERSONA.md"
USER_PREFERENCES_FILE = "USER_PREFERENCES.md"
SYSTEM_TASKS_FILE = "SYSTEM_TASKS.md"
LEGACY_WAKE_FORMAT_FILE = "WAKE_FORMAT.md"
SYSTEM_RUNTIME_DIR = "runtime"
MEMORY_DIR = "memory"
SKILLS_DIR = "skills"
JOBS_DIR = "jobs"
ACTIVITY_DIR = "activity"
SYSTEM_TASKS_SCHEMA_VERSION = 2

ROOT_LEVEL_RUNTIME_FILES = {
    CURRENT_PERSONA_FILE,
    "AGENT_PROFILE.md",
    "AGENT_WORKFLOW.md",
    "AGENT_HOOKS.md",
    USER_PREFERENCES_FILE,
    SYSTEM_TASKS_FILE,
    LEGACY_WAKE_FORMAT_FILE,
}

FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


class AgentRuntimeConfigError(ValueError):
    """根层配置加载异常。"""


@dataclass
class ParsedMarkdownDocument:
    """解析后的 Markdown 文档。"""

    metadata: dict[str, Any]
    body: str


@dataclass
class HookDefinition:
    """结构化执行钩子定义。"""

    path: Path
    pre_task: list[str]
    in_task: list[str]
    post_task: list[str]


@dataclass
class SystemTaskTypeDefinition:
    """单个后台系统任务定义。"""

    header: str
    objective: str
    context_title: Optional[str] = None
    context_lines: list[str] = field(default_factory=list)
    steps_title: Optional[str] = None
    steps: list[str] = field(default_factory=list)
    task_rules: list[str] = field(default_factory=list)
    empty_result: Optional[str] = None


@dataclass
class SystemTasksDefinition:
    """统一的后台系统任务定义源。"""

    path: Path
    version: int
    shared_rules: list[str]
    task_types: dict[str, SystemTaskTypeDefinition]


@dataclass
class AgentRuntimeConfig:
    """一次加载后的根层配置快照。"""

    source_root: Path
    active_persona: str
    current_persona_path: Path
    profile_path: Path
    workflow_path: Path
    hooks_path: Path
    user_preferences_path: Optional[Path]
    system_tasks_path: Path
    extra_context_paths: list[Path]
    profile_text: str
    workflow_text: str
    user_preferences_text: str
    extra_contexts: list[tuple[Path, str]]
    hooks: HookDefinition
    system_tasks: SystemTasksDefinition
    warnings: list[str] = field(default_factory=list)
    used_fallback: bool = False

    def render_prompt_sections(self) -> str:
        """渲染进入系统提示词的根层配置片段。"""
        sections: list[str] = [
            "<agent_root_config>",
            f"- Active persona: `{self.active_persona}`",
            f"- Profile source: `{self.profile_path}`",
            f"- Workflow source: `{self.workflow_path}`",
        ]
        if self.user_preferences_path:
            sections.append(f"- Root preferences source: `{self.user_preferences_path}`")
        sections.append(f"- System task source: `{self.system_tasks_path}`")
        sections.append("</agent_root_config>")
        sections.append("")
        sections.append("<agent_profile>")
        sections.append(self.profile_text.strip() or "(No agent profile configured.)")
        sections.append("</agent_profile>")
        sections.append("")
        sections.append("<agent_workflow>")
        sections.append(self.workflow_text.strip() or "(No agent workflow configured.)")
        sections.append("</agent_workflow>")
        if self.user_preferences_text.strip():
            sections.append("")
            sections.append("<agent_user_preferences>")
            sections.append(self.user_preferences_text.strip())
            sections.append("</agent_user_preferences>")
        for path, text in self.extra_contexts:
            if not text.strip():
                continue
            sections.append("")
            sections.append(f'<agent_extra_context source="{path.name}">')
            sections.append(text.strip())
            sections.append("</agent_extra_context>")
        return "\n".join(sections).strip()

    def render_hooks_prompt(self) -> str:
        """渲染结构化 hooks 提示词。"""
        blocks = [
            "<agent_execution_hooks>",
            f"- Hook source: `{self.hooks.path}`",
            "- These hooks are loaded structurally by the runtime and must be followed at the matching lifecycle stage.",
            "",
            "Pre-Task Hooks:",
            self._format_hook_list(self.hooks.pre_task),
            "",
            "In-Task Hooks:",
            self._format_hook_list(self.hooks.in_task),
            "",
            "Post-Task Hooks:",
            self._format_hook_list(self.hooks.post_task),
            "</agent_execution_hooks>",
        ]
        return "\n".join(blocks)

    def render_system_task_message(
        self,
        task_type: str,
        *,
        template_context: Optional[dict[str, Any]] = None,
        extra_rules: Optional[list[str]] = None,
    ) -> str:
        """根据统一的后台系统任务定义渲染提示词。"""
        task_definition = self.system_tasks.task_types.get(task_type)
        if not task_definition:
            raise AgentRuntimeConfigError(f"未定义的后台系统任务类型: {task_type}")

        rendered_context = self._render_template_lines(
            task_definition.context_lines,
            template_context,
            task_type,
            "context_lines",
        )
        rendered_steps = self._render_template_lines(
            task_definition.steps,
            template_context,
            task_type,
            "steps",
        )
        rendered_task_rules = self._render_template_lines(
            task_definition.task_rules,
            template_context,
            task_type,
            "task_rules",
        )

        sections = [
            self._render_template_text(
                task_definition.header,
                template_context,
                task_type,
                "header",
            ).strip(),
            self._render_template_text(
                task_definition.objective,
                template_context,
                task_type,
                "objective",
            ).strip(),
        ]
        if rendered_context:
            sections.append(
                self._format_titled_lines(
                    task_definition.context_title or "Task context",
                    rendered_context,
                )
            )
        if rendered_steps:
            sections.append(
                self._format_titled_lines(
                    task_definition.steps_title or "Follow these steps",
                    rendered_steps,
                )
            )

        rules = list(self.system_tasks.shared_rules)
        if task_definition.empty_result:
            rules.append(task_definition.empty_result)
        rules.extend(rendered_task_rules)
        if extra_rules:
            rules.extend(rule.strip() for rule in extra_rules if rule and rule.strip())
        if rules:
            sections.append(self._format_numbered_rules("IMPORTANT", rules))
        return "\n\n".join(section for section in sections if section).strip()

    @classmethod
    def _render_template_text(
        cls,
        text: str,
        template_context: Optional[dict[str, Any]],
        task_type: str,
        field_name: str,
    ) -> str:
        if not text:
            return ""

        formatter = Formatter()
        required_fields = {
            placeholder_name
            for _, placeholder_name, _, _ in formatter.parse(text)
            if placeholder_name
        }
        if not required_fields:
            return text

        context = cls._normalize_template_context(template_context)
        missing_fields = sorted(field for field in required_fields if field not in context)
        if missing_fields:
            raise AgentRuntimeConfigError(
                f"系统任务定义 `{task_type}` 的 `{field_name}` 缺少变量: "
                + ", ".join(f"`{field}`" for field in missing_fields)
            )

        # 这里统一做字符串替换，让模板文件成为后台任务文案的唯一行为来源。
        return text.format_map(context)

    @classmethod
    def _render_template_lines(
        cls,
        items: list[str],
        template_context: Optional[dict[str, Any]],
        task_type: str,
        field_name: str,
    ) -> list[str]:
        return [
            cls._render_template_text(
                item,
                template_context,
                task_type,
                f"{field_name}[{index}]",
            ).rstrip()
            for index, item in enumerate(items, start=1)
            if item and item.rstrip()
        ]

    @staticmethod
    def _normalize_template_context(
        template_context: Optional[dict[str, Any]],
    ) -> dict[str, str]:
        if not template_context:
            return {}
        return {
            str(key): "" if value is None else str(value)
            for key, value in template_context.items()
        }

    @staticmethod
    def _format_hook_list(items: list[str]) -> str:
        if not items:
            return "(No hooks configured.)"
        return "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=1))

    @staticmethod
    def _format_numbered_rules(title: str, items: list[str]) -> str:
        return "\n".join(
            [f"{title}:"]
            + [f"{index}. {item}" for index, item in enumerate(items, start=1)]
        )

    @staticmethod
    def _format_titled_lines(title: str, items: list[str]) -> str:
        cleaned = [item.rstrip() for item in items if item and item.rstrip()]
        return "\n".join([f"{title}:"] + cleaned)


class AgentRuntimeManager:
    """统一管理 agent 根层配置目录、迁移、校验与模板渲染。"""

    def __init__(
        self,
        *,
        agent_root_dir: Optional[Path] = None,
        bundled_runtime_dir: Optional[Path] = None,
    ) -> None:
        self.agent_root_dir = agent_root_dir or (settings.CONFIG_PATH / "agent")
        self.runtime_dir = self.agent_root_dir / SYSTEM_RUNTIME_DIR
        self.memory_dir = self.agent_root_dir / MEMORY_DIR
        self.skills_dir = self.agent_root_dir / SKILLS_DIR
        self.jobs_dir = self.agent_root_dir / JOBS_DIR
        self.activity_dir = self.agent_root_dir / ACTIVITY_DIR
        self.bundled_runtime_dir = bundled_runtime_dir or (
            Path(__file__).parent / "runtime_defaults"
        )
        self._cache_lock = threading.Lock()
        self._cached_signature: Optional[tuple[tuple[str, int, int], ...]] = None
        self._cached_config: Optional[AgentRuntimeConfig] = None

    def ensure_layout(self) -> None:
        """创建目录、同步默认文件，并迁移旧版 memory/runtime 文件。"""
        self.agent_root_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.activity_dir.mkdir(parents=True, exist_ok=True)
        self._migrate_root_runtime_files()
        self._sync_bundled_runtime_defaults()
        self._migrate_root_memory_files()

    def load_runtime_config(self) -> AgentRuntimeConfig:
        """加载配置。用户目录损坏时自动回退到内置默认配置。"""
        self.ensure_layout()
        signature = self._build_signature()
        with self._cache_lock:
            if self._cached_signature == signature and self._cached_config:
                return self._cached_config

            try:
                config = self._load_from_root(self.runtime_dir)
            except AgentRuntimeConfigError as err:
                logger.warning("Agent 根层配置无效，回退到内置默认配置: %s", err)
                config = self._load_from_root(self.bundled_runtime_dir)
                config.used_fallback = True
                config.warnings.insert(
                    0, f"用户运行时配置加载失败，已回退到内置默认配置: {err}"
                )

            self._cached_signature = signature
            self._cached_config = config
            return config

    def invalidate_cache(self) -> None:
        """供测试或手动刷新时清理缓存。"""
        with self._cache_lock:
            self._cached_signature = None
            self._cached_config = None

    def _build_signature(self) -> tuple[tuple[str, int, int], ...]:
        """基于运行时配置和内置默认配置生成文件签名。"""
        entries: list[tuple[str, int, int]] = []
        for prefix, root in (("runtime", self.runtime_dir), ("bundled", self.bundled_runtime_dir)):
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                stat = path.stat()
                relative = path.relative_to(root).as_posix()
                entries.append((f"{prefix}:{relative}", stat.st_mtime_ns, stat.st_size))
        return tuple(entries)

    def _sync_bundled_runtime_defaults(self) -> None:
        """仅复制缺失的默认根层配置，避免覆盖用户自定义。"""
        if not self.bundled_runtime_dir.exists():
            return
        for path in sorted(self.bundled_runtime_dir.rglob("*")):
            relative = path.relative_to(self.bundled_runtime_dir)
            target = self.runtime_dir / relative
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            logger.info("已同步默认 Agent 运行时文件: %s", target)

    def _migrate_root_runtime_files(self) -> None:
        """兼容早期直接放在 `config/agent` 根目录的 RFC 文件。"""
        migration_targets = {
            CURRENT_PERSONA_FILE: self.runtime_dir / CURRENT_PERSONA_FILE,
            USER_PREFERENCES_FILE: self.runtime_dir / USER_PREFERENCES_FILE,
            SYSTEM_TASKS_FILE: self.runtime_dir / "system_tasks" / SYSTEM_TASKS_FILE,
            LEGACY_WAKE_FORMAT_FILE: self.runtime_dir / "system_tasks" / SYSTEM_TASKS_FILE,
            "AGENT_PROFILE.md": self.runtime_dir / "personas" / "default" / "AGENT_PROFILE.md",
            "AGENT_WORKFLOW.md": self.runtime_dir / "personas" / "default" / "AGENT_WORKFLOW.md",
            "AGENT_HOOKS.md": self.runtime_dir / "personas" / "default" / "AGENT_HOOKS.md",
        }
        for filename, target in migration_targets.items():
            source = self.agent_root_dir / filename
            if not source.exists() or target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source.rename(target)
            logger.info("已迁移旧版 Agent 根配置文件: %s -> %s", source, target)

    def _migrate_root_memory_files(self) -> None:
        """将旧版根目录 memory 文件移入 `config/agent/memory`。"""
        for path in sorted(self.agent_root_dir.glob("*.md")):
            if path.name in ROOT_LEVEL_RUNTIME_FILES:
                continue
            target = self.memory_dir / path.name
            if target.exists():
                continue
            path.rename(target)
            logger.info("已迁移旧版 Agent memory 文件: %s -> %s", path, target)

    def _load_from_root(self, root: Path) -> AgentRuntimeConfig:
        current_persona_path = root / CURRENT_PERSONA_FILE
        current_doc = self._read_markdown(current_persona_path)
        current_meta = current_doc.metadata

        active_persona = str(current_meta.get("active_persona") or "default").strip()
        if not active_persona:
            raise AgentRuntimeConfigError("CURRENT_PERSONA.md 缺少 active_persona")

        profile_path = self._resolve_required_path(root, current_meta, "profile")
        workflow_path = self._resolve_required_path(root, current_meta, "workflow")
        hooks_path = self._resolve_required_path(root, current_meta, "hooks")
        system_tasks_path = self._resolve_required_path(root, current_meta, "system_tasks")
        user_preferences_path = self._resolve_optional_path(
            root, current_meta.get("user_preferences")
        )
        extra_context_paths = self._resolve_optional_paths(
            root, current_meta.get("extra_context_files", [])
        )

        profile_doc = self._read_markdown(profile_path)
        workflow_doc = self._read_markdown(workflow_path)
        hooks_doc = self._read_markdown(hooks_path)
        system_tasks_doc = self._read_markdown(system_tasks_path)
        preferences_doc = (
            self._read_markdown(user_preferences_path)
            if user_preferences_path and user_preferences_path.exists()
            else ParsedMarkdownDocument(metadata={}, body="")
        )
        extra_contexts = [
            (path, self._read_markdown(path).body)
            for path in extra_context_paths
        ]

        hooks = self._parse_hooks_document(hooks_path, hooks_doc)
        system_tasks = self._parse_system_tasks_document(
            system_tasks_path,
            system_tasks_doc,
        )

        warnings = self._validate_runtime_config(
            current_meta=current_meta,
            profile_path=profile_path,
            workflow_path=workflow_path,
            hooks_path=hooks_path,
            user_preferences_path=user_preferences_path,
            system_tasks_path=system_tasks_path,
            extra_context_paths=extra_context_paths,
            profile_text=profile_doc.body,
            workflow_text=workflow_doc.body,
            preferences_text=preferences_doc.body,
        )
        return AgentRuntimeConfig(
            source_root=root,
            active_persona=active_persona,
            current_persona_path=current_persona_path,
            profile_path=profile_path,
            workflow_path=workflow_path,
            hooks_path=hooks_path,
            user_preferences_path=user_preferences_path,
            system_tasks_path=system_tasks_path,
            extra_context_paths=extra_context_paths,
            profile_text=profile_doc.body,
            workflow_text=workflow_doc.body,
            user_preferences_text=preferences_doc.body,
            extra_contexts=extra_contexts,
            hooks=hooks,
            system_tasks=system_tasks,
            warnings=warnings,
        )

    @staticmethod
    def _read_markdown(path: Path) -> ParsedMarkdownDocument:
        if not path.exists():
            raise AgentRuntimeConfigError(f"缺少配置文件: {path}")
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as err:  # noqa: BLE001
            raise AgentRuntimeConfigError(f"读取配置文件失败 {path}: {err}") from err

        metadata: dict[str, Any] = {}
        body = content
        match = FRONTMATTER_PATTERN.match(content)
        if match:
            try:
                metadata = yaml.safe_load(match.group(1)) or {}
            except yaml.YAMLError as err:
                raise AgentRuntimeConfigError(f"YAML frontmatter 解析失败 {path}: {err}") from err
            if not isinstance(metadata, dict):
                raise AgentRuntimeConfigError(f"frontmatter 必须是映射类型: {path}")
            body = content[match.end():]
        return ParsedMarkdownDocument(metadata=metadata, body=body.strip())

    @staticmethod
    def _resolve_required_path(root: Path, metadata: dict[str, Any], field_name: str) -> Path:
        raw = metadata.get(field_name)
        if not raw or not str(raw).strip():
            raise AgentRuntimeConfigError(f"CURRENT_PERSONA.md 缺少必填字段 `{field_name}`")
        return AgentRuntimeManager._resolve_relative_path(root, str(raw))

    @staticmethod
    def _resolve_optional_path(root: Path, raw: Any) -> Optional[Path]:
        if not raw or not str(raw).strip():
            return None
        return AgentRuntimeManager._resolve_relative_path(root, str(raw))

    @staticmethod
    def _resolve_optional_paths(root: Path, values: Any) -> list[Path]:
        if not values:
            return []
        if not isinstance(values, list):
            raise AgentRuntimeConfigError("extra_context_files 必须是数组")
        return [AgentRuntimeManager._resolve_relative_path(root, str(value)) for value in values]

    @staticmethod
    def _resolve_relative_path(root: Path, value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else (root / candidate).resolve()

    @staticmethod
    def _normalize_string_list(values: Any, field_name: str) -> list[str]:
        if values is None:
            return []
        if not isinstance(values, list):
            raise AgentRuntimeConfigError(f"{field_name} 必须是字符串数组")
        normalized: list[str] = []
        for value in values:
            text = str(value).strip()
            if text:
                normalized.append(text)
        return normalized

    def _parse_hooks_document(
        self, path: Path, document: ParsedMarkdownDocument
    ) -> HookDefinition:
        pre_task = self._normalize_string_list(document.metadata.get("pre_task"), "pre_task")
        in_task = self._normalize_string_list(document.metadata.get("in_task"), "in_task")
        post_task = self._normalize_string_list(
            document.metadata.get("post_task"), "post_task"
        )
        if not (pre_task or in_task or post_task):
            raise AgentRuntimeConfigError(f"{path} 未定义任何结构化 hooks")
        return HookDefinition(
            path=path,
            pre_task=pre_task,
            in_task=in_task,
            post_task=post_task,
        )

    def _parse_system_tasks_document(
        self, path: Path, document: ParsedMarkdownDocument
    ) -> SystemTasksDefinition:
        """解析后台系统任务定义文件。"""
        version = self._normalize_positive_int(
            document.metadata.get("version"),
            "version",
            default=1,
        )
        if version < SYSTEM_TASKS_SCHEMA_VERSION:
            raise AgentRuntimeConfigError(
                f"{path} 的 version={version} 过旧，"
                f"当前要求 SYSTEM_TASKS schema v{SYSTEM_TASKS_SCHEMA_VERSION} 或更高版本"
            )
        shared_rules = self._normalize_string_list(
            document.metadata.get("shared_rules"), "shared_rules"
        )
        if not shared_rules:
            raise AgentRuntimeConfigError(f"{path} 缺少 shared_rules")

        raw_task_types = document.metadata.get("task_types")
        if not isinstance(raw_task_types, dict) or not raw_task_types:
            raise AgentRuntimeConfigError(f"{path} 缺少 task_types 映射")

        task_types: dict[str, SystemTaskTypeDefinition] = {}
        for key, raw in raw_task_types.items():
            if not isinstance(raw, dict):
                raise AgentRuntimeConfigError(f"task_types.{key} 必须是映射")
            header = str(raw.get("header") or "").strip()
            objective = str(raw.get("objective") or "").strip()
            if not header or not objective:
                raise AgentRuntimeConfigError(
                    f"task_types.{key} 缺少 header 或 objective"
                )
            context_lines = self._normalize_string_list(
                raw.get("context_lines"),
                f"task_types.{key}.context_lines",
            )
            steps = self._normalize_string_list(
                raw.get("steps"),
                f"task_types.{key}.steps",
            )
            task_rules = self._normalize_string_list(
                raw.get("task_rules"),
                f"task_types.{key}.task_rules",
            )
            empty_result = str(raw.get("empty_result") or "").strip() or None
            context_title = str(raw.get("context_title") or "").strip() or None
            steps_title = str(raw.get("steps_title") or "").strip() or None
            task_types[str(key)] = SystemTaskTypeDefinition(
                header=header,
                objective=objective,
                context_title=context_title,
                context_lines=context_lines,
                steps_title=steps_title,
                steps=steps,
                task_rules=task_rules,
                empty_result=empty_result,
            )
        return SystemTasksDefinition(
            path=path,
            version=version,
            shared_rules=shared_rules,
            task_types=task_types,
        )

    @staticmethod
    def _normalize_positive_int(
        value: Any,
        field_name: str,
        *,
        default: int,
    ) -> int:
        if value in (None, ""):
            return default
        try:
            normalized = int(value)
        except (TypeError, ValueError) as err:
            raise AgentRuntimeConfigError(f"{field_name} 必须是正整数") from err
        if normalized <= 0:
            raise AgentRuntimeConfigError(f"{field_name} 必须是正整数")
        return normalized

    def _validate_runtime_config(
        self,
        *,
        current_meta: dict[str, Any],
        profile_path: Path,
        workflow_path: Path,
        hooks_path: Path,
        user_preferences_path: Optional[Path],
        system_tasks_path: Path,
        extra_context_paths: list[Path],
        profile_text: str,
        workflow_text: str,
        preferences_text: str,
    ) -> list[str]:
        warnings: list[str] = []
        required_paths = [profile_path, workflow_path, hooks_path, system_tasks_path]
        if user_preferences_path:
            required_paths.append(user_preferences_path)
        duplicates = self._find_duplicate_paths(required_paths + extra_context_paths)
        if duplicates:
            warnings.append(
                "检测到重复引用的根层配置文件: "
                + ", ".join(path.as_posix() for path in duplicates)
            )

        deprecated_phrases = self._normalize_string_list(
            current_meta.get("deprecated_phrases"), "deprecated_phrases"
        )
        if deprecated_phrases:
            scan_targets = {
                "profile": profile_text,
                "workflow": workflow_text,
                "user_preferences": preferences_text,
            }
            for phrase in deprecated_phrases:
                for target_name, text in scan_targets.items():
                    if phrase and phrase in text:
                        warnings.append(
                            f"检测到已废弃短语 `{phrase}` 仍出现在 {target_name} 中"
                        )
        return warnings

    @staticmethod
    def _find_duplicate_paths(paths: Iterable[Path]) -> list[Path]:
        seen: set[Path] = set()
        duplicates: list[Path] = []
        for path in paths:
            resolved = path.resolve()
            if resolved in seen and resolved not in duplicates:
                duplicates.append(resolved)
            seen.add(resolved)
        return duplicates


agent_runtime_manager = AgentRuntimeManager()
