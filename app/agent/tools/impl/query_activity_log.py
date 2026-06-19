"""查询 Agent 活动日志工具。"""

import json
from typing import Optional, Type

from pydantic import BaseModel, Field

from app.agent.middleware.activity_log import (
    DEFAULT_QUERY_DAYS,
    DEFAULT_QUERY_LIMIT,
    query_activity_logs,
)
from app.agent.runtime import agent_runtime_manager
from app.agent.tools.base import MoviePilotTool
from app.agent.tools.tags import ToolTag
from app.log import logger


class QueryActivityLogInput(BaseModel):
    """查询活动日志工具的输入参数模型。"""

    explanation: Optional[str] = Field(
        None,
        description="Clear explanation of why this tool is being used in the current context",
    )
    keyword: Optional[str] = Field(
        None,
        description=(
            "Optional plain-text keyword to filter activity summaries. Use short title, path, site, task, "
            "or status fragments; omit it to inspect latest entries."
        ),
    )
    use_regex: Optional[bool] = Field(
        False,
        description=(
            "Whether to treat keyword as a regular expression. Defaults to false; enable only for "
            "alternative or pattern matching."
        ),
    )
    date: Optional[str] = Field(
        None,
        description="Optional exact date in YYYY-MM-DD format. If omitted, recent days are searched.",
    )
    days: Optional[int] = Field(
        DEFAULT_QUERY_DAYS,
        description="Number of recent days to search when date is not specified.",
    )
    limit: Optional[int] = Field(
        DEFAULT_QUERY_LIMIT,
        description="Maximum number of activity entries to return.",
    )


class QueryActivityLogTool(MoviePilotTool):
    """
    Agent 活动日志只读查询工具。
    """

    name: str = "query_activity_log"
    tags: list[str] = [
        ToolTag.Read,
        ToolTag.System,
    ]
    description: str = (
        "Query recent MoviePilot Agent activity logs on demand. Use this when the user asks what was done before, "
        "asks to continue a previous task, or explicitly references recent agent activity. Supports keyword, date, "
        "recent-day window, limit, and optional regex filters. If a keyword search returns no results, retry with "
        "a shorter keyword, a larger days window, or no keyword to inspect recent entries."
    )
    args_schema: Type[BaseModel] = QueryActivityLogInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据查询参数生成友好的提示消息。"""
        keyword = kwargs.get("keyword")
        date = kwargs.get("date")
        if date and keyword:
            return f"查询活动日志: {date} / {keyword}"
        if date:
            return f"查询活动日志: {date}"
        if keyword:
            return f"搜索活动日志: {keyword}"
        return "查询近期活动日志"

    async def run(
        self,
        keyword: Optional[str] = None,
        use_regex: Optional[bool] = False,
        date: Optional[str] = None,
        days: Optional[int] = DEFAULT_QUERY_DAYS,
        limit: Optional[int] = DEFAULT_QUERY_LIMIT,
        **kwargs,
    ) -> str:
        """
        查询活动日志并返回 JSON 字符串。
        """
        logger.info(
            f"执行工具: {self.name}, keyword={keyword}, use_regex={use_regex}, date={date}, "
            f"days={days}, limit={limit}"
        )
        try:
            payload = await self.run_blocking(
                "default",
                query_activity_logs,
                str(agent_runtime_manager.activity_dir),
                keyword=keyword,
                use_regex=bool(use_regex),
                date=date,
                days=days or DEFAULT_QUERY_DAYS,
                limit=limit,
            )
            return json.dumps(payload, ensure_ascii=False, indent=2)
        except Exception as err:
            logger.error(f"查询活动日志失败: {err}", exc_info=True)
            return json.dumps(
                {
                    "success": False,
                    "message": f"查询活动日志时发生错误: {str(err)}",
                },
                ensure_ascii=False,
            )
