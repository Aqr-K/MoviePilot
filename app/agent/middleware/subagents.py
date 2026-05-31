"""MoviePilot 子代理中间件适配。"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional

from langchain.agents import create_agent
from langchain.agents.middleware.types import (
    AgentMiddleware,
    ContextT,
    ModelRequest,
    ModelResponse,
    ResponseT,
    ToolCallRequest,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field

from app.agent.middleware.utils import append_to_system_message
from app.agent.tools.tags import ToolTag
from app.log import logger


SUBAGENT_TASK_TOOL_NAME = "task"
SUBAGENT_STREAM_MARKER_KEY = "ls_agent_type"
SUBAGENT_STREAM_MARKER_VALUE = "subagent"

SUBAGENT_PARENT_PROMPT = """<subagents>
You may use the `task` tool to delegate independent research, retrieval,
diagnosis, or planning work to built-in subagents.

Rules:
- Delegate when a task benefits from focused investigation, such as media identity checks, site/resource search, subscription analysis, download/transfer diagnosis, or read-only system inspection.
- Subagent output is private context for your decision-making. Do not expose a subagent's process or final report verbatim to the user.
- Subagents must not send messages to the user, ask for interaction, or reveal their internal tool activity.
- Give the user only your synthesized final answer and the minimum necessary next step.
- If a task requires configuration changes, deletion, adding downloads, adding subscriptions, or any high-impact action, the main agent must handle it directly under the confirmation policy.
</subagents>"""

SUBAGENT_TASK_DESCRIPTION = (
    "Delegate an isolated MoviePilot investigation or planning task to a built-in "
    "subagent. The subagent result is private context for the main agent and must "
    "not be forwarded verbatim to the user."
)

SUBAGENT_BASE_PROMPT = """You are a silent subagent working for the MoviePilot main agent.

Requirements:
- Handle only the delegated subtask from the main agent. Do not converse with the user.
- Do not send messages, request user interaction, or output progress updates.
- Use tool results only for analysis, and return the final result only to the main agent.
- Unless the task explicitly requires it and your tool set permits it, limit yourself to read-only inspection and diagnosis.
- If user confirmation or a high-impact change is needed, explain why the main agent must confirm it instead of executing it yourself.
- Return a concise structured Chinese result with key evidence, judgment, and recommended next step.
"""


@dataclass(frozen=True)
class _SubAgentProfile:
    """内置子代理定义。"""

    name: str
    description: str
    prompt: str
    include_tags: frozenset[str]
    exclude_tags: frozenset[str]


class _TaskToolInput(BaseModel):
    """子代理任务工具输入。"""

    description: str = Field(..., description="Complete task description for the subagent")
    subagent_type: str = Field(
        default="general-purpose",
        description="Subagent type to invoke, such as general-purpose or media-researcher",
    )


def is_subagent_stream_metadata(metadata: Any) -> bool:
    """判断流式 token 元数据是否来自子代理。"""
    if not isinstance(metadata, dict):
        return False

    if metadata.get(SUBAGENT_STREAM_MARKER_KEY) == SUBAGENT_STREAM_MARKER_VALUE:
        return True

    nested_metadata = metadata.get("metadata")
    if isinstance(nested_metadata, dict) and nested_metadata.get(
        SUBAGENT_STREAM_MARKER_KEY
    ) == SUBAGENT_STREAM_MARKER_VALUE:
        return True

    configurable = metadata.get("configurable")
    if isinstance(configurable, dict) and configurable.get(
        SUBAGENT_STREAM_MARKER_KEY
    ) == SUBAGENT_STREAM_MARKER_VALUE:
        return True

    return bool(metadata.get("lc_agent_name") in builtin_subagent_names())


@lru_cache(maxsize=1)
def builtin_subagent_names() -> frozenset[str]:
    """返回内置子代理名称集合。"""
    return frozenset(profile.name for profile in _builtin_subagent_profiles())


@lru_cache(maxsize=1)
def _builtin_subagent_profiles() -> tuple[_SubAgentProfile, ...]:
    """构建 MoviePilot 默认内置子代理定义。"""
    default_exclude_tags = frozenset(
        {
            ToolTag.Write.value,
            ToolTag.Message.value,
            ToolTag.UserInteraction.value,
        }
    )
    general_tags = frozenset(
        {
            ToolTag.Media.value,
            ToolTag.Resource.value,
            ToolTag.Site.value,
            ToolTag.Subscription.value,
            ToolTag.Download.value,
            ToolTag.Library.value,
            ToolTag.Transfer.value,
            ToolTag.System.value,
            ToolTag.Settings.value,
            ToolTag.Plugin.value,
            ToolTag.Workflow.value,
            ToolTag.Scheduler.value,
            ToolTag.File.value,
            ToolTag.Directory.value,
            ToolTag.Web.value,
            ToolTag.Command.value,
            ToolTag.FilterRule.value,
            ToolTag.Persona.value,
            ToolTag.SlashCommand.value,
            ToolTag.Recommendation.value,
            ToolTag.Metadata.value,
        }
    )

    return (
        _SubAgentProfile(
            name="general-purpose",
            description="General read-only investigation subagent for cross-domain MoviePilot analysis and execution recommendations.",
            prompt=(
                f"{SUBAGENT_BASE_PROMPT}\n"
                "You specialize in synthesizing media, site, subscription, download, and system status signals."
            ),
            include_tags=general_tags,
            exclude_tags=default_exclude_tags,
        ),
        _SubAgentProfile(
            name="media-researcher",
            description="Media research subagent for title recognition, people, episodes, metadata, and library existence checks.",
            prompt=(
                f"{SUBAGENT_BASE_PROMPT}\n"
                "You specialize in media identity resolution, metadata validation, person credits, and library status analysis."
            ),
            include_tags=frozenset(
                {
                    ToolTag.Media.value,
                    ToolTag.Library.value,
                    ToolTag.Recommendation.value,
                    ToolTag.Metadata.value,
                    ToolTag.Web.value,
                }
            ),
            exclude_tags=default_exclude_tags,
        ),
        _SubAgentProfile(
            name="resource-searcher",
            description="Site and resource search subagent for site checks, torrent search, and resource quality analysis.",
            prompt=(
                f"{SUBAGENT_BASE_PROMPT}\n"
                "You specialize in site status, site user data, torrent search results, and resource quality judgment."
            ),
            include_tags=frozenset(
                {
                    ToolTag.Resource.value,
                    ToolTag.Site.value,
                    ToolTag.Web.value,
                    ToolTag.Media.value,
                }
            ),
            exclude_tags=default_exclude_tags,
        ),
        _SubAgentProfile(
            name="subscription-analyst",
            description="Subscription analysis subagent for subscriptions, history, filter rules, and custom identifiers.",
            prompt=(
                f"{SUBAGENT_BASE_PROMPT}\n"
                "You specialize in current subscription state, subscription history, filter rules, and subscription optimization suggestions."
            ),
            include_tags=frozenset(
                {
                    ToolTag.Subscription.value,
                    ToolTag.FilterRule.value,
                    ToolTag.Settings.value,
                    ToolTag.Media.value,
                }
            ),
            exclude_tags=default_exclude_tags,
        ),
        _SubAgentProfile(
            name="system-diagnostician",
            description="System diagnosis subagent for read-only inspection of settings, schedulers, workflows, plugins, directories, and command output.",
            prompt=(
                f"{SUBAGENT_BASE_PROMPT}\n"
                "You specialize in settings, plugins, scheduled tasks, workflows, directories, and read-only command diagnostics."
            ),
            include_tags=frozenset(
                {
                    ToolTag.System.value,
                    ToolTag.Settings.value,
                    ToolTag.Plugin.value,
                    ToolTag.Workflow.value,
                    ToolTag.Scheduler.value,
                    ToolTag.File.value,
                    ToolTag.Directory.value,
                    ToolTag.Web.value,
                    ToolTag.Command.value,
                    ToolTag.Persona.value,
                    ToolTag.SlashCommand.value,
                }
            ),
            exclude_tags=default_exclude_tags,
        ),
        _SubAgentProfile(
            name="download-diagnostician",
            description="Download and transfer diagnosis subagent for downloaders, download tasks, transfer history, and library status.",
            prompt=(
                f"{SUBAGENT_BASE_PROMPT}\n"
                "You specialize in downloaders, download tasks, transfer history, directory settings, and library ingestion state."
            ),
            include_tags=frozenset(
                {
                    ToolTag.Download.value,
                    ToolTag.Transfer.value,
                    ToolTag.Library.value,
                    ToolTag.Directory.value,
                    ToolTag.File.value,
                    ToolTag.Media.value,
                }
            ),
            exclude_tags=default_exclude_tags,
        ),
    )


def _tool_tag_values(tool: BaseTool) -> set[str]:
    """读取工具实例上的标签集合。"""
    tags = getattr(tool, "tags", None) or []
    if isinstance(tags, str):
        return {tags}
    return {str(tag) for tag in tags if tag}


def _select_tools(tools: list[BaseTool], profile: _SubAgentProfile) -> list[BaseTool]:
    """根据工具标签筛选子代理可用工具。"""
    selected_tools = []
    for tool in tools:
        tags = _tool_tag_values(tool)
        if ToolTag.Read.value not in tags:
            continue
        if profile.exclude_tags & tags:
            continue
        if profile.include_tags & tags:
            selected_tools.append(tool)
    return selected_tools


def _format_subagent_catalog(profiles: tuple[_SubAgentProfile, ...]) -> str:
    """渲染子代理目录供任务工具描述使用。"""
    return "\n".join(
        f"- {profile.name}: {profile.description}" for profile in profiles
    )


def _extract_text_content(content: Any) -> str:
    """从模型消息内容中提取可读文本。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                text_parts.append(block)
                continue
            if isinstance(block, dict):
                if block.get("thought"):
                    continue
                if block.get("type") in {
                    "thinking",
                    "reasoning_content",
                    "reasoning",
                    "thought",
                }:
                    continue
                if isinstance(block.get("text"), str):
                    text_parts.append(block["text"])
        return "".join(text_parts)
    return str(content)


def _extract_final_text(result: Any) -> str:
    """从子代理执行结果中提取最后一条 AI 文本。"""
    if isinstance(result, dict):
        messages = result.get("messages") or []
    else:
        messages = getattr(result, "messages", []) or []

    for message in reversed(messages):
        if isinstance(message, AIMessage) and message.content:
            text = _extract_text_content(message.content).strip()
            if text:
                return text

    return _extract_text_content(result).strip()


class MoviePilotSubAgentMiddleware(AgentMiddleware):
    """MoviePilot 本地子代理中间件兜底实现。"""

    def __init__(
        self,
        *,
        model: BaseChatModel,
        profiles: tuple[_SubAgentProfile, ...],
        tools: list[BaseTool],
        system_prompt: str = SUBAGENT_PARENT_PROMPT,
        task_description: str = SUBAGENT_TASK_DESCRIPTION,
    ) -> None:
        self.system_prompt = system_prompt
        self._model = model
        self._profiles = {profile.name: profile for profile in profiles}
        self._tools = tools
        self._agents = {}
        self._default_agent_name = "general-purpose"
        self.tools = [
            StructuredTool.from_function(
                coroutine=self._run_task,
                name=SUBAGENT_TASK_TOOL_NAME,
                description=(
                    f"{task_description}\n\nAvailable subagents:\n"
                    f"{_format_subagent_catalog(profiles)}"
                ),
                args_schema=_TaskToolInput,
            )
        ]

    def _get_agent(self, agent_name: str) -> Any:
        """懒加载指定名称的子代理图。"""
        profile = self._profiles.get(agent_name) or self._profiles[
            self._default_agent_name
        ]
        cached_agent = self._agents.get(profile.name)
        if cached_agent:
            return cached_agent

        subagent_tools = _select_tools(self._tools, profile)
        agent = create_agent(
            model=self._model,
            tools=subagent_tools,
            system_prompt=profile.prompt,
            name=profile.name,
        )
        self._agents[profile.name] = agent
        return agent

    async def _run_task(self, description: str, subagent_type: str) -> str:
        """调用指定子代理并只返回供主代理读取的结果。"""
        agent_name = subagent_type or self._default_agent_name
        agent = self._get_agent(agent_name)
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=description)]},
            config={
                "configurable": {
                    "thread_id": f"subagent-{agent_name}-{uuid.uuid4().hex}",
                    SUBAGENT_STREAM_MARKER_KEY: SUBAGENT_STREAM_MARKER_VALUE,
                },
                "metadata": {
                    "lc_agent_name": agent_name,
                    SUBAGENT_STREAM_MARKER_KEY: SUBAGENT_STREAM_MARKER_VALUE,
                },
            },
        )
        final_text = _extract_final_text(result)
        return final_text or "The subagent did not return a usable result."

    async def awrap_model_call(
        self,
        request: ModelRequest[ContextT],
        handler: Callable[
            [ModelRequest[ContextT]], Awaitable[ModelResponse[ResponseT]]
        ],
    ) -> ModelResponse[ResponseT]:
        """在主代理模型调用前注入子代理使用说明。"""
        new_system_message = append_to_system_message(
            request.system_message,
            self.system_prompt,
        )
        return await handler(request.override(system_message=new_system_message))


class SubAgentCallSummaryMiddleware(AgentMiddleware):
    """记录子代理调用次数的中间件。"""

    def __init__(self, *, stream_handler: Any = None) -> None:
        self.stream_handler = stream_handler
        self.tools = []

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[Any]],
    ) -> Any:
        """在子代理任务工具执行时记录聚合摘要。"""
        tool = request.tool
        if (
            tool
            and getattr(tool, "name", None) == SUBAGENT_TASK_TOOL_NAME
            and self.stream_handler
            and getattr(self.stream_handler, "is_streaming", False)
        ):
            tool_call = request.tool_call or {}
            self.stream_handler.record_tool_call(
                tool_name=SUBAGENT_TASK_TOOL_NAME,
                tool_message="Subagent invoked",
                tool_kwargs=tool_call.get("args") or {},
            )
        return await handler(request)


def _deepagents_spec(
    profiles: tuple[_SubAgentProfile, ...], tools: list[BaseTool]
) -> list[dict[str, Any]]:
    """将内置定义转换为 Deep Agents 子代理配置。"""
    specs = []
    for profile in profiles:
        specs.append(
            {
                "name": profile.name,
                "description": profile.description,
                "prompt": profile.prompt,
                "tools": _select_tools(tools, profile),
            }
        )
    return specs


def _try_create_deepagents_middleware(
    *,
    profiles: tuple[_SubAgentProfile, ...],
    tools: list[BaseTool],
    model: BaseChatModel,
) -> Optional[AgentMiddleware]:
    """优先创建 Deep Agents 官方子代理中间件。"""
    try:
        from deepagents.backends import StateBackend
        from deepagents.middleware.subagents import SubAgentMiddleware

        return SubAgentMiddleware(
            backend=StateBackend(),
            subagents=_deepagents_spec(profiles, tools),
            default_model=model,
            system_prompt=SUBAGENT_PARENT_PROMPT,
            task_description=SUBAGENT_TASK_DESCRIPTION,
        )
    except ImportError:
        return None
    except Exception as err:
        logger.debug(f"Deep Agents 子代理中间件不可用，使用本地实现: {err}")
        return None


def create_subagent_middlewares(
    *,
    model: BaseChatModel,
    tools: list[BaseTool],
    stream_handler: Any = None,
) -> tuple[list[AgentMiddleware], list[BaseTool]]:
    """创建子代理中间件列表和任务工具列表。"""
    profiles = _builtin_subagent_profiles()
    subagent_middleware = _try_create_deepagents_middleware(
        profiles=profiles,
        tools=tools,
        model=model,
    )
    if subagent_middleware is None:
        subagent_middleware = MoviePilotSubAgentMiddleware(
            model=model,
            profiles=profiles,
            tools=tools,
        )

    task_tools = list(getattr(subagent_middleware, "tools", []) or [])
    return [
        subagent_middleware,
        SubAgentCallSummaryMiddleware(stream_handler=stream_handler),
    ], task_tools


__all__ = [
    "SUBAGENT_TASK_TOOL_NAME",
    "create_subagent_middlewares",
    "is_subagent_stream_metadata",
]
