import asyncio
from types import SimpleNamespace

from langchain_core.messages import HumanMessage

from app.agent import MoviePilotAgent
from app.agent.memory import memory_manager
from app.db.agentchat_oper import AgentChatOper


def test_agent_chat_oper_saves_display_messages_with_channel():
    """Agent 会话历史应保存展示消息与渠道标识。"""
    oper = AgentChatOper()
    oper.save_display_messages(
        session_id="session-chat",
        user_id="1",
        username="admin",
        channel="Telegram",
        source="telegram-main",
        original_chat_id="chat-1",
        messages=[
            {
                "id": "user-1",
                "role": "user",
                "content": "帮我看看下载器",
                "createdAt": 1,
                "status": "done",
                "tools": [],
                "attachments": [],
                "choices": [],
            }
        ],
    )
    chat = AgentChatOper().get(session_id="session-chat", user_id="1")

    assert chat.channel == "Telegram"
    assert chat.source == "telegram-main"
    assert chat.original_chat_id == "chat-1"
    assert chat.message_count == 1
    assert chat.title == "帮我看看下载器"


def test_agent_chat_oper_keeps_generated_title_when_saving_display_messages():
    """保存展示消息时不应覆盖已生成的模型标题。"""
    oper = AgentChatOper()
    oper.update_title_if_empty(
        session_id="session-title",
        user_id="1",
        username="admin",
        channel="WebAgent",
        source="web-agent",
        title="下载器状态排查",
    )
    oper.save_display_messages(
        session_id="session-title",
        user_id="1",
        messages=[
            {
                "id": "user-1",
                "role": "user",
                "content": "帮我看看下载器现在是不是正常",
                "createdAt": 1,
                "status": "done",
                "tools": [],
                "attachments": [],
                "choices": [],
            }
        ],
        title="帮我看看下载器现在是不是正常",
    )

    chat = AgentChatOper().get(session_id="session-title", user_id="1")
    summary = AgentChatOper.to_summary(chat)

    assert chat.title == "下载器状态排查"
    assert "preview" not in summary
    assert "messages" not in summary


def test_agent_prepare_chat_title_generates_title(monkeypatch):
    """首次调用 Agent 时应使用模型生成会话标题并写入渠道信息。"""

    class FakeTitleModel:
        """测试用标题模型。"""

        async def ainvoke(self, messages):
            """返回固定标题。"""
            assert "标题生成器" in messages[0].content
            assert messages[1].content == "帮我看看下载器现在是不是正常"
            return SimpleNamespace(content="「下载器状态排查」")

    async def fake_initialize_llm(self, streaming=False):
        """返回测试标题模型。"""
        return FakeTitleModel()

    monkeypatch.setattr(MoviePilotAgent, "_initialize_llm", fake_initialize_llm)
    agent = MoviePilotAgent(
        session_id="session-ai-title",
        user_id="3",
        channel="WebAgent",
        source="web-agent",
        username="admin",
    )

    asyncio.run(agent.prepare_chat_title("帮我看看下载器现在是不是正常"))
    chat = AgentChatOper().get(session_id="session-ai-title", user_id="3")

    assert chat.title == "下载器状态排查"
    assert chat.channel == "WebAgent"
    assert chat.source == "web-agent"


def test_memory_manager_restores_agent_messages_from_database():
    """内存缓存缺失时应从 Agent 会话历史表恢复原始 messages。"""
    session_id = "session-memory"
    user_id = "2"
    memory_manager.clear_memory(session_id, user_id)
    AgentChatOper().save_agent_messages(
        session_id=session_id,
        user_id=user_id,
        messages=[
            {
                "type": "human",
                "data": {
                    "content": "继续之前的话题",
                    "additional_kwargs": {},
                    "response_metadata": {},
                    "type": "human",
                    "name": None,
                    "id": None,
                    "example": False,
                },
            }
        ],
    )

    messages = memory_manager.get_agent_messages(session_id=session_id, user_id=user_id)

    assert len(messages) == 1
    assert isinstance(messages[0], HumanMessage)
    assert messages[0].content == "继续之前的话题"
