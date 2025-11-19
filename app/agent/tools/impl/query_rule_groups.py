"""查询规则组工具"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.tools.base import MoviePilotTool
from app.helper.rule import RuleHelper
from app.log import logger


class QueryRuleGroupsInput(BaseModel):
    """查询规则组工具的输入参数模型"""
    explanation: str = Field(..., description="Clear explanation of why this tool is being used in the current context")


class QueryRuleGroupsTool(MoviePilotTool):
    name: str = "query_rule_groups"
    description: str = "Query all filter rule groups available in the system. Rule groups are used to filter torrents when searching or subscribing. Returns rule group names, media types, and categories, but excludes rule_string to keep results concise."
    args_schema: Type[BaseModel] = QueryRuleGroupsInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息"""
        return "正在查询所有规则组"

    async def run(self, **kwargs) -> str:
        logger.info(f"执行工具: {self.name}")
        
        try:
            rule_helper = RuleHelper()
            rule_groups = rule_helper.get_rule_groups()
            
            if not rule_groups:
                return json.dumps({
                    "message": "未找到任何规则组",
                    "rule_groups": []
                }, ensure_ascii=False, indent=2)
            
            # 精简字段，过滤掉 rule_string 避免结果过大
            simplified_groups = []
            for group in rule_groups:
                simplified = {
                    "name": group.name,
                    "media_type": group.media_type,
                    "category": group.category
                }
                simplified_groups.append(simplified)
            
            result = {
                "message": f"找到 {len(simplified_groups)} 个规则组",
                "rule_groups": simplified_groups
            }
            
            return json.dumps(result, ensure_ascii=False, indent=2)
            
        except Exception as e:
            error_message = f"查询规则组失败: {str(e)}"
            logger.error(f"查询规则组失败: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "message": error_message,
                "rule_groups": []
            }, ensure_ascii=False)

