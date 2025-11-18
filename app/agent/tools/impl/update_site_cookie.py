"""更新站点Cookie和UA工具"""

from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.chain.site import SiteChain
from app.db.site_oper import SiteOper
from app.log import logger
from app.utils.string import StringUtils


class UpdateSiteCookieInput(BaseModel):
    """更新站点Cookie和UA工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    site_identifier: str = Field(..., description="Site identifier: can be site ID (integer as string), site name, or site domain/URL")
    username: str = Field(..., description="Site login username")
    password: str = Field(..., description="Site login password")
    two_step_code: Optional[str] = Field(None, description="Two-step verification code or secret key (optional, required for sites with 2FA enabled)")


class UpdateSiteCookieTool(MoviePilotTool):
    name: str = "update_site_cookie"
    description: str = "Update site Cookie and User-Agent by logging in with username and password. This tool can automatically obtain and update the site's authentication credentials. Supports two-step verification for sites that require it. Accepts site ID, site name, or site domain/URL as identifier."
    args_schema: Type[BaseModel] = UpdateSiteCookieInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据更新参数生成友好的提示消息"""
        site_identifier = kwargs.get("site_identifier", "")
        username = kwargs.get("username", "")
        two_step_code = kwargs.get("two_step_code")
        
        message = f"正在更新站点Cookie: {site_identifier} (用户: {username})"
        if two_step_code:
            message += " [需要两步验证]"
        
        return message

    async def run(self, site_identifier: str, username: str, password: str, 
                  two_step_code: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: site_identifier={site_identifier}, username={username}")

        try:
            site_oper = SiteOper()
            site_chain = SiteChain()
            
            # 尝试解析为站点ID
            site = None
            if site_identifier.isdigit():
                # 如果是数字，尝试作为站点ID查询
                site = await site_oper.async_get(int(site_identifier))
            
            # 如果不是ID或ID查询失败，尝试按名称或域名查询
            if not site:
                # 尝试按名称查询
                sites = await site_oper.async_list()
                for s in sites:
                    if (site_identifier.lower() in (s.name or "").lower()) or \
                       (site_identifier.lower() in (s.domain or "").lower()):
                        site = s
                        break
                
                # 如果还是没找到，尝试从URL提取域名
                if not site:
                    domain = StringUtils.get_url_domain(site_identifier)
                    if domain:
                        site = await site_oper.async_get_by_domain(domain)
            
            if not site:
                return f"未找到站点：{site_identifier}，请使用 query_sites 工具查询可用的站点"
            
            # 更新站点Cookie和UA
            status, message = site_chain.update_cookie(
                site_info=site,
                username=username,
                password=password,
                two_step_code=two_step_code
            )
            
            if status:
                return f"站点【{site.name}】Cookie和UA更新成功\n{message}"
            else:
                return f"站点【{site.name}】Cookie和UA更新失败\n错误原因：{message}"
        except Exception as e:
            logger.error(f"更新站点Cookie和UA失败: {e}", exc_info=True)
            return f"更新站点Cookie和UA时发生错误: {str(e)}"

