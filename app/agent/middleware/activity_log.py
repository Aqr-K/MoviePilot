"""
活动日志中间件 - 自动记录 Agent 每次交互的操作摘要。

按日期存储在 CONFIG_PATH/agent/activity/YYYY-MM-DD.md 中，
每次 Agent 执行完毕后自动调用 LLM 对本轮对话生成简洁的活动摘要，
并在每次 Agent 启动时加载近几天的活动日志注入系统提示词。
"""

import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Annotated, Any, NotRequired, TypedDict

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

# 注入系统提示词时加载的天数
PROMPT_LOAD_DAYS = 3

# 每日日志文件最大大小 (256KB)
MAX_LOG_FILE_SIZE = 256 * 1024

# 提取本轮对话上下文的最大字符数（避免过长的对话消耗太多 token）
MAX_CONTEXT_FOR_SUMMARY = 4000

# LLM 总结的提示词
SUMMARY_PROMPT = """请根据以下 AI 助手与用户的对话记录，生成一条简洁的活动摘要（中文，一句话，不超过80字）。
摘要应包含：用户的需求是什么、助手做了什么、结果如何。
只输出摘要内容，不要加任何前缀、标点序号或解释。

对话记录：
{conversation}"""


class ActivityLogState(AgentState):
    """ActivityLogMiddleware 的状态模型。"""

    activity_log_contents: NotRequired[Annotated[dict[str, str], PrivateStateAttr]]
    """将日期字符串映射到日志内容的字典。标记为私有，不包含在最终代理状态中。"""


class ActivityLogStateUpdate(TypedDict):
    """ActivityLogMiddleware 的状态更新。"""

    activity_log_contents: dict[str, str]


def _extract_last_round(messages: list) -> list | None:
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


async def _summarize_with_llm(conversation_text: str) -> str | None:
    """调用 LLM 对对话文本生成活动摘要。

    参数：
        conversation_text: 格式化后的对话文本。

    返回：
        LLM 生成的摘要字符串，失败时返回 None。
    """
    try:
        from app.helper.llm import LLMHelper

        llm = LLMHelper.get_llm(streaming=False)
        prompt = SUMMARY_PROMPT.format(conversation=conversation_text)
        response = await llm.ainvoke(prompt)
        summary = response.content.strip()
        # 清理模型可能输出的前缀（如 "摘要：" "总结："）
        summary = re.sub(r"^(摘要|总结|活动记录)[：:]\s*", "", summary)
        return summary if summary else None
    except Exception as e:
        logger.debug("LLM summarization failed: %s", e)
        return None


ACTIVITY_LOG_SYSTEM_PROMPT = """<activity_log>
{activity_log}
</activity_log>

<activity_log_guidelines>
    The above <activity_log> contains a record of your recent interactions with the user, automatically maintained by the system.
    
    **How to use this information:**
    - Reference past activities when relevant to provide continuity (e.g., "之前帮你订阅了《XXX》，现在有更新了")
    - Use activity history to understand ongoing tasks and user patterns
    - When the user asks "你之前帮我做了什么" or similar questions, refer to this log
    - Activity logs are automatically recorded after each interaction - you do NOT need to manually update them
    
    **What is automatically logged:**
    - Each user interaction: what was asked, which tools were used, and the outcome
    - Timestamps for all activities
    - The log is organized by date for easy reference
    
    **Important:**
    - Activity logs are READ-ONLY from your perspective - the system manages them automatically
    - Do not attempt to edit or write to activity log files
    - For long-term preferences and knowledge, continue to use MEMORY.md
    - Activity logs are retained for {retention_days} days and then automatically cleaned up
</activity_log_guidelines>
"""


class ActivityLogMiddleware(AgentMiddleware[ActivityLogState, ContextT, ResponseT]):  # noqa
    """自动记录和加载 Agent 活动日志的中间件。

    - abefore_agent: 加载近几天的活动日志
    - awrap_model_call: 将活动日志注入系统提示词
    - aafter_agent: 从本次对话中提取摘要并追加到当日日志文件

    参数：
        activity_dir: 活动日志存储目录路径。
        retention_days: 日志保留天数（默认 7 天）。
        prompt_load_days: 注入系统提示词时加载的天数（默认 3 天）。
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
        """格式化活动日志用于系统提示词注入。"""
        if not contents:
            return ACTIVITY_LOG_SYSTEM_PROMPT.format(
                activity_log="(暂无活动记录)",
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
                activity_log="(暂无活动记录)",
                retention_days=self.retention_days,
            )

        log_body = "\n\n".join(sections)
        return ACTIVITY_LOG_SYSTEM_PROMPT.format(
            activity_log=log_body,
            retention_days=self.retention_days,
        )

    async def _load_recent_logs(self) -> dict[str, str]:
        """加载近几天的活动日志。"""
        contents: dict[str, str] = {}
        today = datetime.now().date()

        for i in range(self.prompt_load_days):
            date = today - timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            log_path = self._get_log_path(date_str)

            if await log_path.exists():
                try:
                    content = await log_path.read_text(encoding="utf-8")
                    contents[date_str] = content
                    logger.debug("Loaded activity log for %s", date_str)
                except Exception as e:
                    logger.warning("Failed to load activity log %s: %s", date_str, e)

        return contents

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
                existing = await log_path.read_text(encoding="utf-8")
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
    ) -> ActivityLogStateUpdate | None:
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
        contents = request.state.get("activity_log_contents", {})
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
    ) -> dict[str, Any] | None:
        """Agent 执行完毕后，调用 LLM 对本轮对话生成摘要并追加到当日活动日志。"""
        try:
            messages = state.get("messages", [])
            if not messages:
                return None

            # 提取本轮交互
            round_messages = _extract_last_round(messages)
            if not round_messages:
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


__all__ = ["ActivityLogMiddleware"]
