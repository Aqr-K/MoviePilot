"""
MCP（Model Context Protocol）JSON-RPC 2.0 协议塑形逻辑。

均为无副作用的纯 dict/string 变换：信封构造、版本协商、工具格式转换、
隐藏工具过滤、请求校验。不依赖 Chain / DB / agent / logger，可独立单测。
端点 app/api/endpoints/mcp.py 负责鉴权、请求解析、日志与真正的工具调用副作用。
"""
from typing import Any, Dict, List, Union

# MCP 协议版本
MCP_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2024-11-05"]
MCP_PROTOCOL_VERSION = MCP_PROTOCOL_VERSIONS[0]  # 默认使用最新版本
MCP_HIDDEN_TOOLS = {
    "execute_command",
    "search_web",
    "edit_file",
    "write_file",
    "read_file",
}


def create_jsonrpc_response(
    request_id: Union[str, int, None], result: Any
) -> Dict[str, Any]:
    """
    创建 JSON-RPC 成功响应
    """
    response = {"jsonrpc": "2.0", "id": request_id, "result": result}
    return response


def create_jsonrpc_error(
    request_id: Union[str, int, None], code: int, message: str, data: Any = None
) -> Dict[str, Any]:
    """
    创建 JSON-RPC 错误响应
    """
    error = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    if data is not None:
        error["error"]["data"] = data
    return error


def is_valid_jsonrpc_request(body: Any) -> bool:
    """
    校验 JSON-RPC 2.0 请求格式：必须是 dict 且 jsonrpc == "2.0"
    """
    return isinstance(body, dict) and body.get("jsonrpc") == "2.0"


def negotiate_protocol_version(client_version: Any) -> str:
    """
    协议版本协商：客户端版本在支持列表中则采用，否则回退服务器默认版本
    """
    if client_version in MCP_PROTOCOL_VERSIONS:
        return client_version
    return MCP_PROTOCOL_VERSION


def build_initialize_result(negotiated_version: str, app_version: str) -> Dict[str, Any]:
    """
    构建 MCP 初始化响应负载
    """
    return {
        "protocolVersion": negotiated_version,
        "capabilities": {
            "tools": {
                "listChanged": False  # 暂不支持工具列表变更通知
            },
            "logging": {},
        },
        "serverInfo": {
            "name": "MoviePilot",
            "version": app_version,
            "description": "MoviePilot MCP Server - 电影自动化管理工具",
        },
        "instructions": "MoviePilot MCP 服务器，提供媒体管理、订阅、下载等工具。",
    }


def filter_exposed_tools(tools: List[Any]) -> List[Any]:
    """
    过滤掉 MCP 隐藏工具
    """
    return [tool for tool in tools if tool.name not in MCP_HIDDEN_TOOLS]


def tool_to_mcp_dict(tool: Any) -> Dict[str, Any]:
    """
    将单个工具转换为 MCP 工具格式
    """
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }


def tools_to_mcp_format(tools: List[Any]) -> List[Dict[str, Any]]:
    """
    将工具列表转换为 MCP 工具格式
    """
    return [tool_to_mcp_dict(tool) for tool in tools]
