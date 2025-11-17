"""查询站点工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.db.site_oper import SiteOper
from app.log import logger


class QuerySitesInput(BaseModel):
    """查询站点工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")
    status: Optional[str] = Field("all",
                                  description="Filter sites by status: 'active' for enabled sites, 'inactive' for disabled sites, 'all' for all sites")
    name: Optional[str] = Field(None,
                                description="Filter sites by name (partial match, optional)")


class QuerySitesTool(MoviePilotTool):
    name: str = "query_sites"
    description: str = "Query site status and list all configured sites. Shows site name, domain, status, priority, and basic configuration."
    args_schema: Type[BaseModel] = QuerySitesInput

    async def run(self, status: Optional[str] = "all", name: Optional[str] = None, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}, 参数: status={status}, name={name}")
        try:
            site_oper = SiteOper()
            # 获取所有站点（按优先级排序）
            sites = await site_oper.async_list()
            filtered_sites = []
            for site in sites:
                # 按状态过滤
                if status == "active" and not site.is_active:
                    continue
                if status == "inactive" and site.is_active:
                    continue
                # 按名称过滤（部分匹配）
                if name and name.lower() not in (site.name or "").lower():
                    continue
                filtered_sites.append(site)
            if filtered_sites:
                # 精简字段，只保留关键信息
                simplified_sites = []
                for s in filtered_sites:
                    simplified = {
                        "id": s.id,
                        "name": s.name,
                        "domain": s.domain,
                        "url": s.url,
                        "pri": s.pri,
                        "is_active": s.is_active,
                        "downloader": s.downloader,
                        "proxy": s.proxy,
                        "timeout": s.timeout
                    }
                    simplified_sites.append(simplified)
                result_json = json.dumps(simplified_sites, ensure_ascii=False, indent=2)
                return result_json
            return "未找到相关站点"
        except Exception as e:
            logger.error(f"查询站点失败: {e}", exc_info=True)
            return f"查询站点时发生错误: {str(e)}"

