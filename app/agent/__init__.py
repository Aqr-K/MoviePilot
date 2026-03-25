import asyncio
import traceback
import uuid
from time import strftime
from typing import Callable, Dict, List

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
                # 后台任务模式：不需要流式输出，只收集最终结果
                collected: List[str] = []

                await self._stream_agent_tokens(
                    agent=agent,
                    messages={"messages": messages},
                    config=agent_config,
                    on_token=lambda t: collected.append(t),
                )

                # 后台任务仅广播最终结果，带标题
                final_text = "".join(collected)
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


class AgentManager:
    """
    AI智能体管理器
    """

    def __init__(self):
        self.active_agents: Dict[str, MoviePilotAgent] = {}

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
        处理用户消息
        """
        if session_id not in self.active_agents:
            logger.info(
                f"创建新的AI智能体实例，session_id: {session_id}, user_id: {user_id}"
            )
            agent = MoviePilotAgent(
                session_id=session_id,
                user_id=user_id,
                channel=channel,
                source=source,
                username=username,
            )
            self.active_agents[session_id] = agent
        else:
            agent = self.active_agents[session_id]
            agent.user_id = user_id
            if channel:
                agent.channel = channel
            if source:
                agent.source = source
            if username:
                agent.username = username

        return await agent.process(message)

    async def clear_session(self, session_id: str, user_id: str):
        """
        清空会话
        """
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
                "[System Heartbeat Wake-up] Please check all jobs in your jobs directory and process pending tasks:\n"
                "1. List all jobs with status 'pending' or 'in_progress'\n"
                "2. For 'recurring' jobs, check the 'last_run' timestamp to determine if it's time to run again\n"
                "3. For 'once' jobs with status 'pending', execute them now\n"
                "4. After executing each job, update its status, 'last_run' time, and execution log in the JOB.md file\n"
                "5. If there are no pending jobs, simply respond with a brief summary\n"
                "IMPORTANT: Respond in Chinese (中文). Begin checking and processing jobs now."
            )

            await self.process_message(
                session_id=session_id,
                user_id=user_id,
                message=heartbeat_message,
                channel=None,
                source=None,
                username=settings.SUPERUSER,
            )

            logger.info("智能体心跳唤醒：任务检查完成")

            # 心跳会话用完即弃，清理资源
            await self.clear_session(session_id, user_id)

        except Exception as e:
            logger.error(f"智能体心跳唤醒失败: {e}")


# 全局智能体管理器实例
agent_manager = AgentManager()
