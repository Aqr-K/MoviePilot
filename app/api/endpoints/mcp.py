"""工具API端点
通过HTTP API暴露MoviePilot的智能体工具功能
"""

from typing import List, Any, Dict, Annotated

from fastapi import APIRouter, Depends, HTTPException

from app import schemas
from app.agent.tools.manager import MoviePilotToolsManager
from app.core.security import verify_apikey
from app.log import logger

router = APIRouter()

# 全局工具管理器实例（单例模式，按用户ID缓存）
_tools_managers: Dict[str, MoviePilotToolsManager] = {}


def get_tools_manager(user_id: str = "mcp_user", session_id: str = "mcp_session") -> MoviePilotToolsManager:
    """
    获取工具管理器实例（按用户ID缓存）
    
    Args:
        user_id: 用户ID
        session_id: 会话ID
        
    Returns:
        MoviePilotToolsManager实例
    """
    global _tools_managers
    # 使用用户ID作为缓存键
    cache_key = f"{user_id}_{session_id}"
    if cache_key not in _tools_managers:
        _tools_managers[cache_key] = MoviePilotToolsManager(
            user_id=user_id,
            session_id=session_id
        )
    return _tools_managers[cache_key]


@router.get("/tools", summary="列出所有可用工具", response_model=List[Dict[str, Any]])
async def list_tools(
        _: Annotated[str, Depends(verify_apikey)]
) -> Any:
    """
    获取所有可用的工具列表
    
    返回每个工具的名称、描述和参数定义
    """
    try:
        manager = get_tools_manager()
        # 获取所有工具定义
        tools = manager.list_tools()

        # 转换为字典格式
        tools_list = []
        for tool in tools:
            tool_dict = {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema
            }
            tools_list.append(tool_dict)

        return tools_list
    except Exception as e:
        logger.error(f"获取工具列表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取工具列表失败: {str(e)}")


@router.post("/tools/call", summary="调用工具", response_model=schemas.ToolCallResponse)
async def call_tool(
        request: schemas.ToolCallRequest,

) -> Any:
    """
    调用指定的工具
        
    Returns:
        工具执行结果
    """
    try:
        # 使用当前用户ID创建管理器实例
        manager = get_tools_manager()

        # 调用工具
        result_text = await manager.call_tool(request.tool_name, request.arguments)

        return schemas.ToolCallResponse(
            success=True,
            result=result_text
        )
    except Exception as e:
        logger.error(f"调用工具 {request.tool_name} 失败: {e}", exc_info=True)
        return schemas.ToolCallResponse(
            success=False,
            error=f"调用工具失败: {str(e)}"
        )


@router.get("/tools/{tool_name}", summary="获取工具详情", response_model=Dict[str, Any])
async def get_tool_info(
        tool_name: str,
        _: Annotated[str, Depends(verify_apikey)]
) -> Any:
    """
    获取指定工具的详细信息
        
    Returns:
        工具的详细信息，包括名称、描述和参数定义
    """
    try:
        manager = get_tools_manager()
        # 获取所有工具
        tools = manager.list_tools()

        # 查找指定工具
        for tool in tools:
            if tool.name == tool_name:
                return {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema
                }

        raise HTTPException(status_code=404, detail=f"工具 '{tool_name}' 未找到")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取工具信息失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取工具信息失败: {str(e)}")


@router.get("/tools/{tool_name}/schema", summary="获取工具参数Schema", response_model=Dict[str, Any])
async def get_tool_schema(
        tool_name: str,
        _: Annotated[str, Depends(verify_apikey)]
) -> Any:
    """
    获取指定工具的参数Schema（JSON Schema格式）
        
    Returns:
        工具的JSON Schema定义
    """
    try:
        manager = get_tools_manager()
        # 获取所有工具
        tools = manager.list_tools()

        # 查找指定工具
        for tool in tools:
            if tool.name == tool_name:
                return tool.input_schema

        raise HTTPException(status_code=404, detail=f"工具 '{tool_name}' 未找到")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取工具Schema失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"获取工具Schema失败: {str(e)}")
