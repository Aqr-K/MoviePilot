import asyncio
import traceback
import uuid
from time import strftime
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from langchain.agents import create_agent
from langchain.agents.middleware import (
    SummarizationMiddleware,
    LLMToolSelectorMiddleware,
)
from langchain_core.messages import (
    HumanMessage,
    BaseMessage,
)
from langgraph.checkpoint.memory import InMemorySaver

from app.agent.callback import StreamingHandler
from app.agent.memory import memory_manager
from app.agent.middleware.jobs import JobsMiddleware
from app.agent.middleware.memory import MemoryMiddleware
from app.agent.middleware.patch_tool_calls import PatchToolCallsMiddleware
from app.agent.middleware.skills import SkillsMiddleware
from app.agent.prompt import prompt_manager
from app.agent.tools.factory import MoviePilotToolFactory
from app.chain import ChainBase
from app.core.config import settings
from app.helper.llm import LLMHelper
from app.log import logger
from app.schemas import Notification


class AgentChain(ChainBase):
    pass


class MoviePilotAgent:
    """
    MoviePilot AI智能体（基于 LangChain v1 + LangGraph）
    """

    def __init__(
        self,
        session_id: str,
        user_id: str = None,
        channel: str = None,
        source: str = None,
        username: str = None,
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.channel = channel
        self.source = source
        self.username = username

        # 流式token管理
        self.stream_handler = StreamingHandler()

    @property
    def is_background(self) -> bool:
        """
        是否为后台任务模式（无渠道信息，如定时唤醒）
        """
        return not self.channel and not self.source

    @staticmethod
    def _initialize_llm():
        """
        初始化 LLM（带流式回调）
        """
        return LLMHelper.get_llm(streaming=True)

    def _initialize_tools(self) -> List:
        """
        初始化工具列表
        """
        return MoviePilotToolFactory.create_tools(
            session_id=self.session_id,
            user_id=self.user_id,
            channel=self.channel,
            source=self.source,
            username=self.username,
            stream_handler=self.stream_handler,
        )

    def _create_agent(self):
        """
        创建 LangGraph Agent（使用 create_agent + SummarizationMiddleware）
        """
        try:
            # 系统提示词
            system_prompt = prompt_manager.get_agent_prompt(
                channel=self.channel
            ).format(current_date=strftime("%Y-%m-%d"))

            # LLM 模型（用于 agent 执行）
            llm = self._initialize_llm()

            # 工具列表
            tools = self._initialize_tools()

            # 中间件
            middlewares = [
                # Skills
                SkillsMiddleware(
                    sources=[str(settings.CONFIG_PATH / "agent" / "skills")],
                ),
                # Jobs 任务管理
                JobsMiddleware(
                    sources=[str(settings.CONFIG_PATH / "agent" / "jobs")],
                ),
                # 记忆管理
                MemoryMiddleware(
                    sources=[str(settings.CONFIG_PATH / "agent" / "MEMORY.md")]
                ),
                # 上下文压缩
                SummarizationMiddleware(model=llm, trigger=("fraction", 0.85)),
                # 错误工具调用修复
                PatchToolCallsMiddleware(),
            ]

            # 工具选择
            if settings.LLM_MAX_TOOLS > 0:
                middlewares.append(
                    LLMToolSelectorMiddleware(
                        model=llm, max_tools=settings.LLM_MAX_TOOLS
                    )
                )

            return create_agent(
                model=llm,
                tools=tools,
                system_prompt=system_prompt,
                middleware=middlewares,
                checkpointer=InMemorySaver(),
            )
        except Exception as e:
            logger.error(f"创建 Agent 失败: {e}")
            raise e

    async def process(self, message: str) -> str:
        """
        处理用户消息，流式推理并返回 Agent 回复
        """
        try:
            logger.info(f"Agent推理: session_id={self.session_id}, input={message}")

            # 获取历史消息
            messages = memory_manager.get_agent_messages(
                session_id=self.session_id, user_id=self.user_id
            )

            # 增加用户消息
            messages.append(HumanMessage(content=message))

            # 执行推理
            await self._execute_agent(messages)

        except Exception as e:
            error_message = f"处理消息时发生错误: {str(e)}"
            logger.error(error_message)
            await self.send_agent_message(error_message)
            return error_message

    @staticmethod
    async def _stream_agent_tokens(
        agent, messages: dict, config: dict, on_token: Callable[[str], None]
    ):
        """
        流式运行智能体，过滤工具调用token，将模型生成的内容通过回调输出。
        :param agent: LangGraph Agent 实例
        :param messages: Agent 输入消息
        :param config: Agent 运行配置
        :param on_token: 收到有效 token 时的回调
        """
        async for chunk in agent.astream(
            messages,
            stream_mode="messages",
            config=config,
            subgraphs=False,
            version="v2",
        ):
            if chunk["type"] == "messages":
                token, metadata = chunk["data"]
                if (
                    token
                    and hasattr(token, "tool_call_chunks")
                    and not token.tool_call_chunks
                ):
                    if token.content:
                        on_token(token.content)

    async def _execute_agent(self, messages: List[BaseMessage]):
        """
        调用 LangGraph Agent，通过 astream 流式获取 token。
        支持流式输出：在支持消息编辑的渠道上实时推送 token。
        后台任务模式（无渠道信息）：不进行流式输出，仅广播最终结果。
        """
        try:
            # Agent运行配置
            agent_config = {
                "configurable": {
                    "thread_id": self.session_id,
                }
            }

            # 创建智能体
            agent = self._create_agent()

            if self.is_background:
                # 后台任务模式：非流式执行，等待完成后只取最后一条AI回复
                await agent.ainvoke(
                    {"messages": messages},
                    config=agent_config,
                )

                # 从最终状态中提取最后一条AI回复内容
                final_messages = agent.get_state(agent_config).values.get(
                    "messages", []
                )
                final_text = ""
                for msg in reversed(final_messages):
                    if hasattr(msg, "type") and msg.type == "ai" and msg.content:
                        final_text = msg.content
                        break

                # 后台任务仅广播最终回复，带标题
                if final_text:
                    await self.send_agent_message(final_text, title="MoviePilot助手")

            else:
                # 正常渠道模式：启动流式输出
                await self.stream_handler.start_streaming(
                    channel=self.channel,
                    source=self.source,
                    user_id=self.user_id,
                    username=self.username,
                )

                # 流式运行智能体，token 直接推送到 stream_handler
                await self._stream_agent_tokens(
                    agent=agent,
                    messages={"messages": messages},
                    config=agent_config,
                    on_token=self.stream_handler.emit,
                )

                # 停止流式输出，返回是否已通过流式编辑发送了所有内容及最终文本
                (
                    all_sent_via_stream,
                    streamed_text,
                ) = await self.stream_handler.stop_streaming()

                if not all_sent_via_stream:
                    # 流式输出未能发送全部内容（渠道不支持编辑，或发送失败）
                    # 通过常规方式发送剩余内容
                    remaining_text = await self.stream_handler.take()
                    if remaining_text:
                        await self.send_agent_message(remaining_text)
                elif streamed_text:
                    # 流式输出已发送全部内容，但未记录到数据库，补充保存消息记录
                    await self._save_agent_message_to_db(streamed_text)

            # 保存消息
            memory_manager.save_agent_messages(
                session_id=self.session_id,
                user_id=self.user_id,
                messages=agent.get_state(agent_config).values.get("messages", []),
            )

        except asyncio.CancelledError:
            logger.info(f"Agent执行被取消: session_id={self.session_id}")
            return "任务已取消", {}
        except Exception as e:
            logger.error(f"Agent执行失败: {e} - {traceback.format_exc()}")
            return str(e), {}
        finally:
            # 确保停止流式输出
            if not self.is_background:
                await self.stream_handler.stop_streaming()

    async def send_agent_message(self, message: str, title: str = ""):
        """
        通过原渠道发送消息给用户
        """
        await AgentChain().async_post_message(
            Notification(
                channel=self.channel,
                source=self.source,
                userid=self.user_id,
                username=self.username,
                title=title,
                text=message,
            )
        )

    async def _save_agent_message_to_db(self, message: str, title: str = ""):
        """
        仅保存Agent回复消息到数据库和SSE队列（不重新发送到渠道）
        用于流式输出场景：消息已通过 send_direct_message/edit_message 发送给用户，
        但未记录到数据库中，此方法补充保存消息历史记录。
        """
        chain = AgentChain()
        notification = Notification(
            channel=self.channel,
            source=self.source,
            userid=self.user_id,
            username=self.username,
            title=title,
            text=message,
        )
        # 保存到SSE消息队列（供前端展示）
        chain.messagehelper.put(notification, role="user", title=title)
        # 保存到数据库
        await chain.messageoper.async_add(**notification.model_dump())

    async def cleanup(self):
        """
        清理智能体资源
        """
        logger.info(f"MoviePilot智能体已清理: session_id={self.session_id}")


@dataclass
class _MessageTask:
    """
    待处理的消息任务
    """

    session_id: str
    user_id: str
    message: str
    channel: Optional[str] = None
    source: Optional[str] = None
    username: Optional[str] = None


class AgentManager:
    """
    AI智能体管理器
    同一会话的消息按顺序排队处理，不同会话之间互不影响。
    """

    def __init__(self):
        self.active_agents: Dict[str, MoviePilotAgent] = {}
        # 每个会话的消息队列
        self._session_queues: Dict[str, asyncio.Queue] = {}
        # 每个会话的worker任务
        self._session_workers: Dict[str, asyncio.Task] = {}

    @staticmethod
    async def initialize():
        """
        初始化管理器
        """
        memory_manager.initialize()

    async def close(self):
        """
        关闭管理器
        """
        await memory_manager.close()
        # 取消所有会话worker
        for task in self._session_workers.values():
            task.cancel()
        # 等待所有worker结束
        for session_id, task in self._session_workers.items():
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._session_workers.clear()
        self._session_queues.clear()
        for agent in self.active_agents.values():
            await agent.cleanup()
        self.active_agents.clear()

    async def process_message(
        self,
        session_id: str,
        user_id: str,
        message: str,
        channel: str = None,
        source: str = None,
        username: str = None,
    ) -> str:
        """
        处理用户消息：将消息放入会话队列，按顺序依次处理。
        同一会话的消息排队等待，不同会话之间互不影响。
        """
        task = _MessageTask(
            session_id=session_id,
            user_id=user_id,
            message=message,
            channel=channel,
            source=source,
            username=username,
        )

        # 获取或创建会话队列
        if session_id not in self._session_queues:
            self._session_queues[session_id] = asyncio.Queue()

        queue = self._session_queues[session_id]
        queue_size = queue.qsize()

        # 如果队列中已有等待的消息，通知用户消息已排队
        if queue_size > 0 or (
            session_id in self._session_workers
            and not self._session_workers[session_id].done()
        ):
            logger.info(
                f"会话 {session_id} 有任务正在处理，消息已排队等待 "
                f"(队列中待处理: {queue_size} 条)"
            )

        # 放入队列
        await queue.put(task)

        # 确保该会话有一个worker在运行
        if (
            session_id not in self._session_workers
            or self._session_workers[session_id].done()
        ):
            self._session_workers[session_id] = asyncio.create_task(
                self._session_worker(session_id)
            )

        return ""

    async def _session_worker(self, session_id: str):
        """
        会话消息处理worker：从队列中逐条取出消息并处理。
        处理完当前消息后才会处理下一条，确保同一会话的消息顺序执行。
        """
        queue = self._session_queues.get(session_id)
        if not queue:
            return

        try:
            while True:
                try:
                    # 等待消息，超时后自动退出worker
                    task = await asyncio.wait_for(queue.get(), timeout=60.0)
                except asyncio.TimeoutError:
                    # 队列空闲超时，退出worker
                    logger.debug(f"会话 {session_id} 的消息队列空闲，worker退出")
                    break

                try:
                    await self._process_message_internal(task)
                except Exception as e:
                    logger.error(f"处理会话 {session_id} 的消息失败: {e}")
                finally:
                    queue.task_done()

        except asyncio.CancelledError:
            logger.info(f"会话 {session_id} 的worker被取消")
        finally:
            # 清理已完成的worker记录
            self._session_workers.pop(session_id, None)
            # 如果队列为空，清理队列
            if (
                session_id in self._session_queues
                and self._session_queues[session_id].empty()
            ):
                self._session_queues.pop(session_id, None)

    async def _process_message_internal(self, task: _MessageTask):
        """
        实际处理单条消息
        """
        session_id = task.session_id
        if session_id not in self.active_agents:
            logger.info(
                f"创建新的AI智能体实例，session_id: {session_id}, user_id: {task.user_id}"
            )
            agent = MoviePilotAgent(
                session_id=session_id,
                user_id=task.user_id,
                channel=task.channel,
                source=task.source,
                username=task.username,
            )
            self.active_agents[session_id] = agent
        else:
            agent = self.active_agents[session_id]
            agent.user_id = task.user_id
            if task.channel:
                agent.channel = task.channel
            if task.source:
                agent.source = task.source
            if task.username:
                agent.username = task.username

        return await agent.process(task.message)

    async def clear_session(self, session_id: str, user_id: str):
        """
        清空会话
        """
        # 取消该会话的worker
        if session_id in self._session_workers:
            self._session_workers[session_id].cancel()
            try:
                await self._session_workers[session_id]
            except asyncio.CancelledError:
                pass
            self._session_workers.pop(session_id, None)

        # 清理队列
        self._session_queues.pop(session_id, None)

        # 清理agent
        if session_id in self.active_agents:
            agent = self.active_agents[session_id]
            await agent.cleanup()
            del self.active_agents[session_id]
            memory_manager.clear_memory(session_id, user_id)
            logger.info(f"会话 {session_id} 的记忆已清空")

    async def heartbeat_check_jobs(self):
        """
        心跳唤醒：检查并执行待处理的定时任务（Jobs）。
        由定时调度器周期性调用，每次使用独立的会话避免上下文干扰。
        """
        try:
            # 每次使用唯一的 session_id，避免共享上下文
            session_id = f"__agent_heartbeat_{uuid.uuid4().hex[:12]}__"
            user_id = settings.SUPERUSER

            logger.info("智能体心跳唤醒：开始检查待处理任务...")

            # 英文提示词，便于大模型理解
            heartbeat_message = (
                "[System Heartbeat] Check all jobs in your jobs directory and process pending tasks:\n"
                "1. List all jobs with status 'pending' or 'in_progress'\n"
                "2. For 'recurring' jobs, check 'last_run' to determine if it's time to run again\n"
                "3. For 'once' jobs with status 'pending', execute them now\n"
                "4. After executing each job, update its status, 'last_run' time, and execution log in the JOB.md file\n"
                "5. If there are no pending jobs, do NOT generate any response\n\n"
                "IMPORTANT: This is a background system task, NOT a user conversation. "
                "Your final response will be broadcast as a notification. "
                "Only output a brief completion summary listing each executed job and its result. "
                "Do NOT include greetings, explanations, or conversational text. "
                "If no jobs were executed, output nothing. "
                "Respond in Chinese (中文)."
            )

            await self.process_message(
                session_id=session_id,
                user_id=user_id,
                message=heartbeat_message,
                channel=None,
                source=None,
                username=settings.SUPERUSER,
            )

            # 等待消息队列处理完成
            if session_id in self._session_queues:
                await self._session_queues[session_id].join()

            # 等待worker结束
            if session_id in self._session_workers:
                try:
                    await self._session_workers[session_id]
                except asyncio.CancelledError:
                    pass

            logger.info("智能体心跳唤醒：任务检查完成")

            # 心跳会话用完即弃，清理资源
            await self.clear_session(session_id, user_id)

        except Exception as e:
            logger.error(f"智能体心跳唤醒失败: {e}")


# 全局智能体管理器实例
agent_manager = AgentManager()
