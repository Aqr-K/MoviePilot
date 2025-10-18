"""MoviePilot AI智能体实现"""

import asyncio
import threading
from typing import Dict, List, Any

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_community.callbacks import get_openai_callback
from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.messages import HumanMessage, AIMessage, ToolCall
from langchain_core.runnables.history import RunnableWithMessageHistory

from app.agent.memory import ConversationMemoryManager
from app.agent.prompt import PromptManager
from app.agent.tools import MoviePilotToolFactory
from app.core.config import settings
from app.helper.message import MessageHelper
from app.log import logger


class StreamingCallbackHandler(AsyncCallbackHandler):
    """流式输出回调处理器"""

    def __init__(self, session_id: str):
        self._lock = threading.Lock()
        self.session_id = session_id
        self.current_message = ""
        self.message_helper = MessageHelper()

    async def get_message(self):
        """获取当前消息内容，获取后清空"""
        with self._lock:
            if not self.current_message:
                return ""
            msg = self.current_message
            logger.info(f"Agent消息: {msg}")
            self.current_message = ""
            return msg

    async def on_llm_new_token(self, token: str, **kwargs):
        """处理新的token"""
        if not token:
            return
        with self._lock:
            # 缓存当前消息
            self.current_message += token


class MoviePilotAgent:
    """MoviePilot AI智能体"""

    def __init__(self, session_id: str, user_id: str = None):
        self.session_id = session_id
        self.user_id = user_id

        # 消息助手
        self.message_helper = MessageHelper()

        # 记忆管理器
        self.memory_manager = ConversationMemoryManager()

        # 提示词管理器
        self.prompt_manager = PromptManager()

        # 回调处理器
        self.callback_handler = StreamingCallbackHandler(
            session_id=session_id
        )

        # LLM模型
        self.llm = self._initialize_llm()

        # 工具
        self.tools = self._initialize_tools()

        # 会话存储
        self.session_store = self._initialize_session_store()

        # 提示词模板
        self.prompt = self._initialize_prompt()

        # Agent执行器
        self.agent_executor = self._create_agent_executor()

    def _initialize_llm(self):
        """初始化LLM模型"""
        provider = settings.LLM_PROVIDER.lower()
        api_key = settings.LLM_API_KEY
        if not api_key:
            raise ValueError("未配置 LLM_API_KEY")

        if provider == "google":
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(
                model=settings.LLM_MODEL,
                google_api_key=api_key,
                max_retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=True,
                callbacks=[self.callback_handler]
            )
        elif provider == "deepseek":
            from langchain_deepseek import ChatDeepSeek
            return ChatDeepSeek(
                model=settings.LLM_MODEL,
                api_key=api_key,
                max_retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=True,
                callbacks=[self.callback_handler],
                stream_usage=True
            )
        else:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=settings.LLM_MODEL,
                api_key=api_key,
                max_retries=3,
                base_url=settings.LLM_BASE_URL,
                temperature=settings.LLM_TEMPERATURE,
                streaming=True,
                callbacks=[self.callback_handler],
                stream_usage=True
            )

    def _initialize_tools(self) -> List:
        """初始化工具列表"""
        return MoviePilotToolFactory.create_tools(
            session_id=self.session_id,
            user_id=self.user_id,
            message_helper=self.message_helper
        )

    @staticmethod
    def _initialize_session_store() -> Dict[str, InMemoryChatMessageHistory]:
        """初始化内存存储"""
        return {}

    def get_session_history(self, session_id: str) -> InMemoryChatMessageHistory:
        """获取会话历史"""
        if session_id not in self.session_store:
            chat_history = InMemoryChatMessageHistory()
            messages: List[dict] = self.memory_manager.get_recent_messages_for_agent(
                session_id=session_id,
                user_id=self.user_id
            )
            if messages:
                for msg in messages:
                    if msg.get("role") == "user":
                        chat_history.add_user_message(HumanMessage(content=msg.get("content", "")))
                    elif msg.get("role") == "agent":
                        chat_history.add_ai_message(AIMessage(content=msg.get("content", "")))
                    elif msg.get("role") == "tool_call":
                        metadata = msg.get("metadata", {})
                        chat_history.add_ai_message(AIMessage(
                            content=msg.get("content", ""),
                            tool_calls=[ToolCall(
                                id=metadata.get("call_id"),
                                name=metadata.get("tool_name"),
                                args=metadata.get("parameters"),
                            )]
                        ))
                    elif msg.get("role") == "tool_result":
                        chat_history.add_ai_message(AIMessage(content=msg.get("content", "")))
                    elif msg.get("role") == "system":
                        chat_history.add_ai_message(AIMessage(content=msg.get("content", "")))
            self.session_store[session_id] = chat_history
        return self.session_store[session_id]

    @staticmethod
    def _initialize_prompt() -> ChatPromptTemplate:
        """初始化提示词模板"""
        try:
            prompt = ChatPromptTemplate.from_messages([
                ("system", "{system_prompt}"),
                MessagesPlaceholder(variable_name="chat_history"),
                ("user", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ])
            logger.info("LangChain提示词模板初始化成功")
            return prompt
        except Exception as e:
            logger.error(f"初始化提示词失败: {e}")
            raise e

    def _create_agent_executor(self) -> RunnableWithMessageHistory:
        """创建Agent执行器"""
        try:
            agent = create_openai_tools_agent(
                llm=self.llm,
                tools=self.tools,
                prompt=self.prompt
            )
            executor = AgentExecutor(
                agent=agent,
                tools=self.tools,
                verbose=settings.LLM_VERBOSE,
                max_iterations=settings.LLM_MAX_ITERATIONS,
                return_intermediate_steps=True,
                handle_parsing_errors=True,
                early_stopping_method="force"
            )
            return RunnableWithMessageHistory(
                executor,
                self.get_session_history,
                input_messages_key="input",
                history_messages_key="chat_history"
            )
        except Exception as e:
            logger.error(f"创建Agent执行器失败: {e}")
            raise e

    async def process_message(self, message: str) -> str:
        """处理用户消息"""
        try:
            # 添加用户消息到记忆
            await self.memory_manager.add_memory(
                self.session_id,
                user_id=self.user_id,
                role="user",
                content=message
            )

            # 构建输入上下文
            input_context = {
                "system_prompt": self.prompt_manager.get_agent_prompt(),
                "input": message
            }

            # 执行Agent
            logger.info(f"Agent执行推理: session_id={self.session_id}, input={message}")
            result = await self._execute_agent(input_context)

            # 获取Agent回复
            agent_message = await self.callback_handler.get_message()

            # 发送Agent回复给用户
            self.message_helper.put(
                message=agent_message,
                role="system",
                title="AI助手回复"
            )

            # 添加Agent回复到记忆
            await self.memory_manager.add_memory(
                session_id=self.session_id,
                user_id=self.user_id,
                role="agent",
                content=agent_message
            )

            return agent_message

        except Exception as e:
            error_message = f"处理消息时发生错误: {str(e)}"
            logger.error(error_message)
            # 发送错误消息给用户
            self.message_helper.put(
                message=error_message,
                role="system",
                title="AI助手错误"
            )
            return error_message

    async def _execute_agent(self, input_context: Dict[str, Any]) -> Dict[str, Any]:
        """执行LangChain Agent"""
        try:
            with get_openai_callback() as cb:
                result = await self.agent_executor.ainvoke(
                    input_context,
                    config={"configurable": {"session_id": self.session_id}},
                    callbacks=[self.callback_handler]
                )
                logger.info(f"LLM调用消耗: \n{cb}")

                if cb.total_tokens > 0:
                    result["token_usage"] = {
                        "prompt_tokens": cb.prompt_tokens,
                        "completion_tokens": cb.completion_tokens,
                        "total_tokens": cb.total_tokens
                    }
            return result
        except asyncio.CancelledError:
            logger.info(f"Agent执行被取消: session_id={self.session_id}")
            return {
                "output": "任务已取消",
                "intermediate_steps": [],
                "token_usage": {}
            }
        except Exception as e:
            logger.error(f"Agent执行失败: {e}")
            return {
                "output": f"执行过程中发生错误: {str(e)}",
                "intermediate_steps": [],
                "token_usage": {}
            }

    async def cleanup(self):
        """清理智能体资源"""
        if self.session_id in self.session_store:
            del self.session_store[self.session_id]
        logger.info(f"MoviePilot智能体已清理: session_id={self.session_id}")


class AgentManager:
    """AI智能体管理器"""

    def __init__(self):
        self.active_agents: Dict[str, MoviePilotAgent] = {}
        self.memory_manager = ConversationMemoryManager()

    async def initialize(self):
        """初始化管理器"""
        await self.memory_manager.initialize()

    async def close(self):
        """关闭管理器"""
        await self.memory_manager.close()
        # 清理所有活跃的智能体
        for agent in self.active_agents.values():
            await agent.cleanup()
        self.active_agents.clear()

    async def process_message(self, session_id: str, user_id: str, message: str) -> str:
        """处理用户消息"""
        # 获取或创建Agent实例
        if session_id not in self.active_agents:
            logger.info(f"创建新的AI智能体实例，session_id: {session_id}, user_id: {user_id}")
            agent = MoviePilotAgent(
                session_id=session_id,
                user_id=user_id
            )
            agent.memory_manager = self.memory_manager
            self.active_agents[session_id] = agent
        else:
            agent = self.active_agents[session_id]
            agent.user_id = user_id  # 确保user_id是最新的

        # 处理消息
        return await agent.process_message(message)

    async def clear_session(self, session_id: str, user_id: str):
        """清空会话"""
        if session_id in self.active_agents:
            agent = self.active_agents[session_id]
            await agent.cleanup()
            del self.active_agents[session_id]
            await self.memory_manager.clear_memory(session_id, user_id)
            logger.info(f"会话 {session_id} 的记忆已清空")


# 全局智能体管理器实例
agent_manager = AgentManager()
