import asyncio
from typing import Dict, List, Any, Union
import json
import tiktoken

from langchain.agents import AgentExecutor
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_community.callbacks import get_openai_callback
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.messages import HumanMessage, AIMessage, ToolCall, ToolMessage, SystemMessage, trim_messages
from langchain_core.runnables import RunnablePassthrough, RunnableLambda
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
            for msg in messages:
                if msg.get("role") == "user":
                    chat_history.add_message(HumanMessage(content=msg.get("content", "")))
                elif msg.get("role") == "agent":
                    chat_history.add_message(AIMessage(content=msg.get("content", "")))
                elif msg.get("role") == "tool_call":
                    metadata = msg.get("metadata", {})
                    chat_history.add_message(
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
                    chat_history.add_message(ToolMessage(
                        content=msg.get("content", ""),
                        tool_call_id=metadata.get("call_id", "unknown")
                    ))
                elif msg.get("role") == "system":
                    chat_history.add_message(SystemMessage(content=msg.get("content", "")))
        
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
                # 如果输入是 PromptValue，转换为消息列表
                if hasattr(messages, "to_messages"):
                    messages = messages.to_messages()
                trimmed = base_trimmer.invoke(messages)

                # 二次校验：确保不出现 broken tool chains
                # 1. AIMessage with tool_calls 必须紧跟着对应的 ToolMessage
                # 2. ToolMessage 必须有对应的 AIMessage 前置
                safe_messages = []
                i = 0
                while i < len(trimmed):
                    msg = trimmed[i]

                    if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
                        # 检查工具调用序列是否完整
                        tool_calls = msg.tool_calls
                        is_valid_sequence = True
                        tool_results = []
                        
                        # 向后查找对应的 ToolMessage
                        temp_i = i + 1
                        for tool_call in tool_calls:
                            if temp_i >= len(trimmed):
                                is_valid_sequence = False
                                break
                            
                            next_msg = trimmed[temp_i]
                            if isinstance(next_msg, ToolMessage) and next_msg.tool_call_id == tool_call.get("id"):
                                tool_results.append(next_msg)
                                temp_i += 1
                            else:
                                is_valid_sequence = False
                                break
                        
                        if is_valid_sequence:
                            # 序列完整，保留消息
                            safe_messages.append(msg)
                            safe_messages.extend(tool_results)
                            i = temp_i  # 跳过已处理的工具结果
                        else:
                            # 序列不完整，丢弃该 AIMessage（后续的孤立 ToolMessage 会在下一次循环被当做 orphaned 处理掉）
                            logger.warning(f"移除无效的工具调用链: {len(tool_calls)} calls, incomplete results")
                            i += 1
                        continue

                    if isinstance(msg, ToolMessage):
                        # 如果在这里遇到 ToolMessage，说明它没有被上面的逻辑消费，则是孤立的（或者顺序错乱）
                        logger.warning("移除孤立的 ToolMessage")
                        i += 1
                        continue

                    # 其他类型的消息直接保留
                    safe_messages.append(msg)
                    i += 1

                if len(safe_messages) < len(messages):
                    logger.info(f"LangChain消息上下文已裁剪: {len(messages)} -> {len(safe_messages)}")
                return safe_messages
            
            # 创建Agent执行链
            agent = (
                RunnablePassthrough.assign(
                    agent_scratchpad=lambda x: format_to_openai_tool_messages(
                        x["intermediate_steps"]
                    )
                )
                | self.prompt
                | RunnableLambda(validated_trimmer)
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

    async def _summarize_history(self):
        """
        总结提炼之前的对话和工具执行情况，并把会话总结变成新的系统提示词取代之前的对话
        """
        try:
            # 获取当前历史记录
            chat_history = self.get_session_history(self.session_id)
            messages = chat_history.messages
            if not messages:
                return

            logger.info(f"会话 {self.session_id} 历史消息长度已超过 90%，开始总结并重置上下文...")

            # 将消息转换为摘要所需的文本格式
            history_text = ""
            for msg in messages:
                if isinstance(msg, HumanMessage):
                    history_text += f"用户: {msg.content}\n"
                elif isinstance(msg, AIMessage):
                    history_text += f"智能体: {msg.content}\n"
                    if getattr(msg, "tool_calls", None):
                        for tool_call in msg.tool_calls:
                            history_text += f"智能体调用工具: {tool_call.get('name')}，参数: {tool_call.get('args')}\n"
                elif isinstance(msg, ToolMessage):
                    history_text += f"工具响应: {msg.content}\n"
                elif isinstance(msg, SystemMessage):
                    history_text += f"系统: {msg.content}\n"

            # 摘要提示词
            summary_prompt = (
                "Please provide a comprehensive and highly informational summary of the preceding conversation and tool executions. "
                "Your goal is to condense the history while retaining all critical details for future reference. "
                "Ensure you include:\n"
                "1. User's core intents, specific requests, and any mentioned preferences.\n"
                "2. Names of movies, TV shows, or other key entities discussed.\n"
                "3. A concise log of tool calls made and their specific results/outcomes.\n"
                "4. The current status of any tasks and any pending actions.\n"
                "5. Any important context that would be necessary for the agent to continue the conversation seamlessly.\n"
                "The summary should be dense with information and serve as the primary context for the next stage of the interaction."
            )

            # 调用 LLM 进行总结 (非流式)
            summary_llm = LLMHelper.get_llm(streaming=False)
            response = await summary_llm.ainvoke([
                SystemMessage(content=summary_prompt),
                HumanMessage(content=f"Here is the conversation history to summarize:\n{history_text}")
            ])
            summary_content = str(response.content)

            if not summary_content:
                logger.warning("总结生成失败，跳过重置逻辑。")
                return

            # 清空原有的会话记录并插入新的系统总结
            await conversation_manager.clear_memory(self.session_id, self.user_id)
            await conversation_manager.add_conversation(
                session_id=self.session_id,
                user_id=self.user_id,
                role="system",
                content=f"<history_summary>\n{summary_content}\n</history_summary>"
            )
            logger.info(f"会话 {self.session_id} 历史摘要替换完成。")
        except Exception as e:
            logger.error(f"执行会话总结出错: {str(e)}")

    async def process_message(self, message: str) -> str:
        """
        处理用户消息
        """
        try:
            # 检查上下文长度是否超过 90%
            history = self.get_session_history(self.session_id)
            if self._token_counter(history.messages) > settings.LLM_MAX_CONTEXT_TOKENS * 1000 * 0.9:
                await self._summarize_history()

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
