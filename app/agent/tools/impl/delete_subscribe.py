"""删除订阅工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.core.event import eventmanager
from app.db.subscribe_oper import SubscribeOper
from app.helper.subscribe import SubscribeHelper
from app.log import logger
from app.schemas.types import EventType


class DeleteSubscribeInput(BaseModel):
    """删除订阅工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    subscribe_id: int = Field(..., description="The ID of the subscription to delete (can be obtained from query_subscribes tool)")


class DeleteSubscribeTool(MoviePilotTool):
    name: str = "delete_subscribe"
    description: str = "Delete a media subscription by its ID. This will remove the subscription and stop automatic downloads for that media."
    args_schema: Type[BaseModel] = DeleteSubscribeInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据删除参数生成友好的提示消息"""
        subscribe_id = kwargs.get("subscribe_id")
        return f"正在删除订阅 (ID: {subscribe_id})"

    async def run(self, subscribe_id: int, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: subscribe_id={subscribe_id}")

        try:
            subscribe_oper = SubscribeOper()
            # 获取订阅信息
            subscribe = await subscribe_oper.async_get(subscribe_id)
            if not subscribe:
                return f"订阅 ID {subscribe_id} 不存在"
            
            # 在删除之前获取订阅信息（用于事件）
            subscribe_info = subscribe.to_dict()
            
            # 删除订阅
            subscribe_oper.delete(subscribe_id)
            
            # 发送事件
            await eventmanager.async_send_event(EventType.SubscribeDeleted, {
                "subscribe_id": subscribe_id,
                "subscribe_info": subscribe_info
            })
            
            # 统计订阅
            SubscribeHelper().sub_done_async({
                "tmdbid": subscribe.tmdbid,
                "doubanid": subscribe.doubanid
            })
            
            return f"成功删除订阅：{subscribe.name} ({subscribe.year})"
        except Exception as e:
            logger.error(f"删除订阅失败: {e}", exc_info=True)
            return f"删除订阅时发生错误: {str(e)}"

