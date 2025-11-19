from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ToolCallRequest(BaseModel):
    """工具调用请求模型"""
    tool_name: str = Field(..., description="工具名称")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="工具参数")


class ToolCallResponse(BaseModel):
    """工具调用响应模型"""
    success: bool = Field(..., description="是否成功")
    result: Optional[str] = Field(None, description="工具执行结果")
    error: Optional[str] = Field(None, description="错误信息")
