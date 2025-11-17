"""AI智能体相关数据模型"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict, field_serializer


class ConversationMemory(BaseModel):
    """对话记忆模型"""
    
    session_id: str = Field(description="会话ID")
    user_id: Optional[str] = Field(default=None, description="用户ID")
    title: Optional[str] = Field(default=None, description="会话标题")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="消息列表")
    context: Dict[str, Any] = Field(default_factory=dict, description="会话上下文")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    updated_at: datetime = Field(default_factory=datetime.now, description="更新时间")
    
    model_config = ConfigDict()
    
    @field_serializer('created_at', 'updated_at', when_used='json')
    def serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class AgentState(BaseModel):
    """AI智能体状态模型"""
    
    session_id: str = Field(description="会话ID")
    current_task: Optional[str] = Field(default=None, description="当前任务")
    is_thinking: bool = Field(default=False, description="是否正在思考")
    last_activity: datetime = Field(default_factory=datetime.now, description="最后活动时间")
    
    model_config = ConfigDict()
    
    @field_serializer('last_activity', when_used='json')
    def serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class UserMessage(BaseModel):
    """用户消息模型"""
    
    session_id: str = Field(description="会话ID")
    content: str = Field(description="消息内容")
    user_id: Optional[str] = Field(default=None, description="用户ID")
    channel: Optional[str] = Field(default=None, description="消息渠道")
    source: Optional[str] = Field(default=None, description="消息来源")


class ToolResult(BaseModel):
    """工具执行结果模型"""
    
    session_id: str = Field(description="会话ID")
    call_id: str = Field(description="调用ID")
    success: bool = Field(description="是否成功")
    result: Optional[str] = Field(default=None, description="执行结果")
    error: Optional[str] = Field(default=None, description="错误信息")
