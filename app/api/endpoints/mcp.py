"""工具API端点
通过HTTP API暴露MoviePilot的智能体工具功能
"""

import uuid
from typing import List, Any, Dict, Annotated, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from fastapi.responses import JSONResponse, Response

from app import schemas
from app.agent.tools.manager import MoviePilotToolsManager
from app.core.security import verify_apikey
from app.log import logger

# 导入版本号
try:
    from version import APP_VERSION
except ImportError:
    APP_VERSION = "unknown"

router = APIRouter()

# MCP 协议版本
MCP_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2024-11-05"]
MCP_PROTOCOL_VERSION = MCP_PROTOCOL_VERSIONS[0]  # 默认使用最新版本

# 全局会话管理器
_sessions: Dict[str, Dict[str, Any]] = {}

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


def get_session(session_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """获取会话"""
    if not session_id:
        return None
    return _sessions.get(session_id)


def create_session(user_id: str) -> Dict[str, Any]:
    """创建新会话"""
    session_id = str(uuid.uuid4())
    session = {
        "id": session_id,
        "user_id": user_id,
        "initialized": False,
        "protocol_version": None,
        "capabilities": {}
    }
    _sessions[session_id] = session
    return session


def delete_session(session_id: str):
    """删除会话"""
    if session_id in _sessions:
        del _sessions[session_id]
    # 同时清理工具管理器缓存
    cache_key = f"{_sessions.get(session_id, {}).get('user_id', 'mcp_user')}_{session_id}"
    if cache_key in _tools_managers:
        del _tools_managers[cache_key]


def create_jsonrpc_response(request_id: Union[str, int, None], result: Any) -> Dict[str, Any]:
    """创建 JSON-RPC 成功响应"""
    response = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result
    }
    return response


def create_jsonrpc_error(request_id: Union[str, int, None], code: int, message: str, data: Any = None) -> Dict[str, Any]:
    """创建 JSON-RPC 错误响应"""
    error = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message
        }
    }
    if data is not None:
        error["error"]["data"] = data
    return error


# ==================== MCP JSON-RPC 端点 ====================

@router.post("", summary="MCP JSON-RPC 端点")
async def mcp_jsonrpc(
        request: Request,
        mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
        mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
        _: Annotated[str, Depends(verify_apikey)] = None
) -> JSONResponse:
    """
    MCP 标准 JSON-RPC 2.0 端点
    
    处理所有 MCP 协议消息（初始化、工具列表、工具调用等）
    """
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"解析请求体失败: {e}")
        return JSONResponse(
            status_code=400,
            content=create_jsonrpc_error(None, -32700, "Parse error", str(e))
        )

    # 验证 JSON-RPC 格式
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        return JSONResponse(
            status_code=400,
            content=create_jsonrpc_error(body.get("id"), -32600, "Invalid Request")
        )

    method = body.get("method")
    params = body.get("params", {})
    request_id = body.get("id")

    # 如果有 id，则为请求；没有 id 则为通知
    is_notification = request_id is None

    try:
        # 处理初始化请求
        if method == "initialize":
            result = await handle_initialize(params, mcp_session_id)
            response = create_jsonrpc_response(request_id, result["result"])
            # 如果创建了新会话，在响应头中返回
            if "session_id" in result:
                headers = {"MCP-Session-Id": result["session_id"]}
                return JSONResponse(content=response, headers=headers)
            return JSONResponse(content=response)

        # 处理已初始化通知
        elif method == "notifications/initialized":
            if is_notification:
                session = get_session(mcp_session_id)
                if session:
                    session["initialized"] = True
                # 通知不需要响应
                return Response(status_code=202)
            else:
                return JSONResponse(
                    content=create_jsonrpc_error(request_id, -32600, "initialized must be a notification")
                )

        # 验证会话（除了 initialize 和 ping）
        if method not in ["initialize", "ping"]:
            session = get_session(mcp_session_id)
            if not session:
                return JSONResponse(
                    status_code=404,
                    content=create_jsonrpc_error(request_id, -32002, "Session not found")
                )
            if not session.get("initialized") and method != "notifications/initialized":
                return JSONResponse(
                    content=create_jsonrpc_error(request_id, -32003, "Not initialized")
                )

        # 处理工具列表请求
        if method == "tools/list":
            result = await handle_tools_list(mcp_session_id)
            return JSONResponse(content=create_jsonrpc_response(request_id, result))

        # 处理工具调用请求
        elif method == "tools/call":
            result = await handle_tools_call(params, mcp_session_id)
            return JSONResponse(content=create_jsonrpc_response(request_id, result))

        # 处理 ping 请求
        elif method == "ping":
            return JSONResponse(content=create_jsonrpc_response(request_id, {}))

        # 未知方法
        else:
            return JSONResponse(
                content=create_jsonrpc_error(request_id, -32601, f"Method not found: {method}")
            )

    except Exception as e:
        logger.error(f"处理 MCP 请求失败: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=create_jsonrpc_error(request_id, -32603, "Internal error", str(e))
        )


async def handle_initialize(params: Dict[str, Any], session_id: Optional[str]) -> Dict[str, Any]:
    """处理初始化请求"""
    protocol_version = params.get("protocolVersion")
    client_info = params.get("clientInfo", {})
    client_capabilities = params.get("capabilities", {})

    logger.info(f"MCP 初始化请求: 客户端={client_info.get('name')}, 协议版本={protocol_version}")

    # 如果没有提供会话ID，创建新会话
    new_session = None
    if not session_id:
        new_session = create_session(user_id="mcp_user")
        session_id = new_session["id"]
    
    session = get_session(session_id) or new_session
    if not session:
        raise ValueError("Failed to create session")

    # 版本协商：选择客户端和服务器都支持的版本
    negotiated_version = MCP_PROTOCOL_VERSION
    if protocol_version in MCP_PROTOCOL_VERSIONS:
        # 客户端版本在支持列表中，使用客户端版本
        negotiated_version = protocol_version
        logger.info(f"使用客户端协议版本: {negotiated_version}")
    else:
        # 客户端版本不支持，使用服务器默认版本
        logger.warning(f"协议版本不匹配: 客户端={protocol_version}, 使用服务器版本={negotiated_version}")
    
    session["protocol_version"] = negotiated_version
    session["capabilities"] = client_capabilities

    result = {
        "result": {
            "protocolVersion": negotiated_version,
            "capabilities": {
                "tools": {
                    "listChanged": False  # 暂不支持工具列表变更通知
                },
                "logging": {}
            },
            "serverInfo": {
                "name": "MoviePilot",
                "version": APP_VERSION,
                "description": "MoviePilot MCP Server - 电影自动化管理工具",
            },
            "instructions": "MoviePilot MCP 服务器，提供媒体管理、订阅、下载等工具。使用 tools/list 查看所有可用工具。"
        }
    }

    # 如果是新创建的会话，返回会话ID
    if new_session:
        result["session_id"] = session_id

    return result


async def handle_tools_list(session_id: Optional[str]) -> Dict[str, Any]:
    """处理工具列表请求"""
    session = get_session(session_id)
    user_id = session.get("user_id", "mcp_user") if session else "mcp_user"
    
    manager = get_tools_manager(user_id=user_id, session_id=session_id or "default")
    tools = manager.list_tools()

    # 转换为 MCP 工具格式
    mcp_tools = []
    for tool in tools:
        mcp_tool = {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema
        }
        mcp_tools.append(mcp_tool)

    return {
        "tools": mcp_tools
    }


async def handle_tools_call(params: Dict[str, Any], session_id: Optional[str]) -> Dict[str, Any]:
    """处理工具调用请求"""
    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    if not tool_name:
        raise ValueError("Missing tool name")

    session = get_session(session_id)
    user_id = session.get("user_id", "mcp_user") if session else "mcp_user"
    
    manager = get_tools_manager(user_id=user_id, session_id=session_id or "default")
    
    try:
        result_text = await manager.call_tool(tool_name, arguments)
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": result_text
                }
            ]
        }
    except Exception as e:
        logger.error(f"工具调用失败: {tool_name}, 错误: {e}", exc_info=True)
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"错误: {str(e)}"
                }
            ],
            "isError": True
        }


@router.delete("", summary="终止 MCP 会话")
async def delete_mcp_session(
        mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
        _: Annotated[str, Depends(verify_apikey)] = None
) -> JSONResponse:
    """
    终止 MCP 会话（可选实现）
    
    客户端可以主动调用此接口终止会话
    """
    if not mcp_session_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "Missing MCP-Session-Id header"}
        )

    delete_session(mcp_session_id)
    return Response(status_code=204)


# ==================== 兼容的 RESTful API 端点 ====================

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
        _: Annotated[str, Depends(verify_apikey)] = None
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
