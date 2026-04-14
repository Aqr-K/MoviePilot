"""测试站点连通性工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.site import SiteChain
from app.db.site_oper import SiteOper
from app.log import logger


class TestSiteInput(BaseModel):
    """测试站点连通性工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    site_identifier: int = Field(..., description="Site ID to test (can be obtained from query_sites tool)")


class TestSiteTool(MoviePilotTool):
    name: str = "test_site"
    description: str = "Test site connectivity and availability. This will check if a site is accessible and can be logged in. Accepts site ID only."
    args_schema: Type[BaseModel] = TestSiteInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据测试参数生成友好的提示消息"""
        site_identifier = kwargs.get("site_identifier")
        return f"正在测试站点连通性: {site_identifier}"

    async def run(self, site_identifier: int, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: site_identifier={site_identifier}")

        try:
            site_oper = SiteOper()
            site_chain = SiteChain()
            site = await site_oper.async_get(site_identifier)
            
            if not site:
                return f"未找到站点：{site_identifier}，请使用 query_sites 工具查询可用的站点"
            
            # 测试站点连通性
            status, message = site_chain.test(site.domain)
            
            if status:
                return f"站点连通性测试成功：{site.name} ({site.domain})\n{message}"
            else:
                return f"站点连通性测试失败：{site.name} ({site.domain})\n{message}"
        except Exception as e:
            logger.error(f"测试站点连通性失败: {e}", exc_info=True)
            return f"测试站点连通性时发生错误: {str(e)}"
