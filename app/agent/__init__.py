import asyncio
from typing import Dict, List, Any, Union
import json
import tiktoken

from langchain.agents import AgentExecutor
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_community.callbacks import get_openai_callback
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.messages import HumanMessage, AIMessage, ToolCall, ToolMessage, SystemMessage, trim_messages
from langchain_core.runnables import RunnablePassthrough
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain.agents.format_scratchpad.openai_tools import format_to_openai_tool_messages
from langchain.agents.output_parsers.openai_tools import OpenAIToolsAgentOutputParser

from app.agent.callback import StreamingCallbackHandler
from app.agent.memory import conversation_manager
from app.agent.prompt import prompt_manager
from app.agent.tools.factory import MoviePilotToolFactory
from app.chain import ChainBase
from app.core.config import settings
from app.helper.llm import LLMHelper
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas import Notification


class AgentChain(ChainBase):
    pass


class MoviePilotAgent:
    """
    MoviePilot AI智能体
    """

    def __init__(self, session_id: str, user_id: str = None,
                 channel: str = None, source: str = None, username: str = None):
        self.session_id = session_id
        self.user_id = user_id
        self.channel = channel  # 消息渠道
        self.source = source  # 消息来源
        self.username = username  # 用户名

        # 消息助手
        self.message_helper = MessageHelper()

        # 回调处理器
        self.callback_handler = StreamingCallbackHandler(
            session_id=session_id
        )

        # LLM模型
        self.llm = self._initialize_llm()

        # 工具
        self.tools = self._initialize_tools()

        # 提示词模板
        self.prompt = self._initialize_prompt()

        # Agent执行器
        self.agent_executor = self._create_agent_executor()

    def _initialize_llm(self):
        """
        初始化LLM模型
        """
        return LLMHelper.get_llm(streaming=True, callbacks=[self.callback_handler])

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
            callback_handler=self.callback_handler
        )

    @staticmethod
    def _initialize_session_store() -> Dict[str, InMemoryChatMessageHistory]:
        """
        初始化内存存储
        """
        return {}

    def get_session_history(self, session_id: str) -> InMemoryChatMessageHistory:
        """
        获取会话历史
        """
        chat_history = InMemoryChatMessageHistory()
        messages: List[dict] = conversation_manager.get_recent_messages_for_agent(
            session_id=session_id,
            user_id=self.user_id
        )
        if messages:
            loaded_messages = []
            for msg in messages:
                if msg.get("role") == "user":
                    loaded_messages.append(HumanMessage(content=msg.get("content", "")))
                elif msg.get("role") == "agent":
                    loaded_messages.append(AIMessage(content=msg.get("content", "")))
                elif msg.get("role") == "tool_call":
                    metadata = msg.get("metadata", {})
                    loaded_messages.append(
                        AIMessage(
                            content=msg.get("content", ""),
                            tool_calls=[
                                ToolCall(
                                    id=metadata.get("call_id"),
                                    name=metadata.get("tool_name"),
                                    args=metadata.get("parameters"),
                                )
                            ]
                        )
                    )
                elif msg.get("role") == "tool_result":
                    metadata = msg.get("metadata", {})
                    loaded_messages.append(ToolMessage(
                        content=msg.get("content", ""),
                        tool_call_id=metadata.get("call_id", "unknown")
                    ))
                elif msg.get("role") == "system":
                    loaded_messages.append(SystemMessage(content=msg.get("content", "")))
            
            # 验证并修复工具调用的完整性
            validated_messages = self._ensure_tool_call_integrity(loaded_messages)
            for msg in validated_messages:
                chat_history.add_message(msg)
        
        return chat_history

    @staticmethod
    def _initialize_prompt() -> ChatPromptTemplate:
        """
        初始化提示词模板
        """
        try:
            prompt_template = ChatPromptTemplate.from_messages([
                ("system", "{system_prompt}"),
                MessagesPlaceholder(variable_name="chat_history"),
                ("user", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ])
            logger.info("LangChain提示词模板初始化成功")
            return prompt_template
        except Exception as e:
            logger.error(f"初始化提示词失败: {e}")
            raise e

    @staticmethod
    def _token_counter(messages: List[Union[HumanMessage, AIMessage, ToolMessage, SystemMessage]]) -> int:
        """
        通用的Token计数器
        """
        try:
            # 尝试从模型获取编码集，如果失败则回退到 cl100k_base (大多数现代模型使用的编码)
            try:
                encoding = tiktoken.encoding_for_model(settings.LLM_MODEL)
            except KeyError:
                encoding = tiktoken.get_encoding("cl100k_base")

            num_tokens = 0
            for message in messages:
                # 基础开销 (每个消息大约 3 个 token)
                num_tokens += 3
                
                # 1. 处理文本内容 (content)
                if isinstance(message.content, str):
                    num_tokens += len(encoding.encode(message.content))
                elif isinstance(message.content, list):
                    for part in message.content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            num_tokens += len(encoding.encode(part.get("text", "")))

                # 2. 处理工具调用 (仅 AIMessage 包含 tool_calls)
                if getattr(message, "tool_calls", None):
                    for tool_call in message.tool_calls:
                        # 函数名
                        num_tokens += len(encoding.encode(tool_call.get("name", "")))
                        # 参数 (转为 JSON 估算)
                        args_str = json.dumps(tool_call.get("args", {}), ensure_ascii=False)
                        num_tokens += len(encoding.encode(args_str))
                        # 额外的结构开销 (ID 等)
                        num_tokens += 3

                # 3. 处理角色权重
                num_tokens += 1

            # 加上回复的起始 Token (大约 3 个 token)
            num_tokens += 3
            return num_tokens
        except Exception as e:
            logger.error(f"Token计数失败: {e}")
            # 发生错误时返回一个保守的估算值
            return len(str(messages)) // 4

    def _ensure_tool_call_integrity(self, messages: List[Union[HumanMessage, AIMessage, ToolMessage, SystemMessage]]) \
            -> List[Union[HumanMessage, AIMessage, ToolMessage, SystemMessage]]:
        """
        确保工具调用的完整性：
        1. 如果AIMessage包含tool_calls，必须后跟相应的ToolMessage
        2. 移除孤立的AIMessage（有tool_calls但没有对应的ToolMessage）
        """
        if not messages:
            return messages
        
        validated_messages = []
        i = 0
        
        while i < len(messages):
            msg = messages[i]
            
            # 检查是否是包含tool_calls的AIMessage
            if isinstance(msg, AIMessage) and getattr(msg, 'tool_calls', None):
                tool_call_ids = {tc.get('id') if isinstance(tc, dict) else tc.id 
                                for tc in msg.tool_calls}
                
                # 查找后续的ToolMessage
                j = i + 1
                found_tool_messages = []
                while j < len(messages) and isinstance(messages[j], ToolMessage):
                    found_tool_messages.append(messages[j])
                    j += 1
                
                # 检查是否所有tool_call都有对应的ToolMessage
                found_tool_call_ids = {tm.tool_call_id for tm in found_tool_messages}
                
                if not tool_call_ids.issubset(found_tool_call_ids):
                    # 如果缺少某些tool_call的响应，移除这个AIMessage
                    logger.warning(f"移除不完整的tool_call AIMessage: 缺少tool_call响应")
                    i += 1
                    continue
                else:
                    # 添加AIMessage和所有对应的ToolMessage
                    validated_messages.append(msg)
                    validated_messages.extend(found_tool_messages)
                    i = j
                    continue
            else:
                validated_messages.append(msg)
            
            i += 1
        
        return validated_messages

    def _create_agent_executor(self) -> RunnableWithMessageHistory:
        """
        创建Agent执行器
        """
        try:
            # 消息裁剪器，防止上下文超出限制
            base_trimmer = trim_messages(
                max_tokens=settings.LLM_MAX_CONTEXT_TOKENS * 1000 * 0.8,
                strategy="last",
                token_counter=self._token_counter,
                include_system=True,
                allow_partial=False,
                start_on="human",
            )
            
            # 包装trimmer，在裁剪后验证工具调用的完整性
            def validated_trimmer(messages):
                trimmed = base_trimmer(messages)
                return self._ensure_tool_call_integrity(trimmed)
            
            # 创建Agent执行链
            agent = (
                RunnablePassthrough.assign(
                    agent_scratchpad=lambda x: format_to_openai_tool_messages(
                        x["intermediate_steps"]
                    )
                )
                | self.prompt
                | validated_trimmer
                | self.llm.bind_tools(self.tools)
                | OpenAIToolsAgentOutputParser()
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
        """
        处理用户消息
        """
        try:
            # 添加用户消息到记忆
            await conversation_manager.add_conversation(
                self.session_id,
                user_id=self.user_id,
                role="user",
                content=message
            )

            # 构建输入上下文
            input_context = {
                "system_prompt": prompt_manager.get_agent_prompt(channel=self.channel),
                "input": message
            }

            # 执行Agent
            logger.info(f"Agent执行推理: session_id={self.session_id}, input={message}")

            result = await self._execute_agent(input_context)

            # 获取Agent回复
            agent_message = await self.callback_handler.get_message()

            # 发送Agent回复给用户（通过原渠道）
            if agent_message:
                # 发送回复
                await self.send_agent_message(agent_message)

                # 添加Agent回复到记忆
                await conversation_manager.add_conversation(
                    session_id=self.session_id,
                    user_id=self.user_id,
                    role="agent",
                    content=agent_message
                )
            else:
                agent_message = result.get("output") or "很抱歉，智能体出错了，未能生成回复内容。"
                await self.send_agent_message(agent_message)

            return agent_message

        except Exception as e:
            error_message = f"处理消息时发生错误: {str(e)}"
            logger.error(error_message)
            # 发送错误消息给用户（通过原渠道）
            await self.send_agent_message(error_message)
            return error_message

    async def _execute_agent(self, input_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行LangChain Agent
        """
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
                "output": str(e),
                "intermediate_steps": [],
                "token_usage": {}
            }

    async def send_agent_message(self, message: str, title: str = "MoviePilot助手"):
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
                text=message
            )
        )

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
        await conversation_manager.initialize()

    async def close(self):
        """
        关闭管理器
        """
        await conversation_manager.close()
        # 清理所有活跃的智能体
        for agent in self.active_agents.values():
            await agent.cleanup()
        self.active_agents.clear()

    async def process_message(self, session_id: str, user_id: str, message: str,
                              channel: str = None, source: str = None, username: str = None) -> str:
        """
        处理用户消息
        """
        # 获取或创建Agent实例
        if session_id not in self.active_agents:
            logger.info(f"创建新的AI智能体实例，session_id: {session_id}, user_id: {user_id}")
            agent = MoviePilotAgent(
                session_id=session_id,
                user_id=user_id,
                channel=channel,
                source=source,
                username=username
            )
            self.active_agents[session_id] = agent
        else:
            agent = self.active_agents[session_id]
            agent.user_id = user_id  # 确保user_id是最新的
            # 更新渠道信息
            if channel:
                agent.channel = channel
            if source:
                agent.source = source
            if username:
                agent.username = username

        # 处理消息
        return await agent.process_message(message)

    async def clear_session(self, session_id: str, user_id: str):
        """
        清空会话
        """
        if session_id in self.active_agents:
            agent = self.active_agents[session_id]
            await agent.cleanup()
            del self.active_agents[session_id]
            await conversation_manager.clear_memory(session_id, user_id)
            logger.info(f"会话 {session_id} 的记忆已清空")


# 全局智能体管理器实例
agent_manager = AgentManager()
