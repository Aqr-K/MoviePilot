"""
S7a 抽取验证：app.service.mcp 纯协议逻辑单测。

该模块不依赖 Chain/DB/agent，可在本地 venv 直接导入（而端点 app.api.endpoints.mcp
因 moviepilot_tool_manager 间接引入 jieba_next 在本环境无法导入）——把一个原本
完全不可测的协议层变成可单测覆盖。
"""
from types import SimpleNamespace

from app.service import mcp


def _tool(name, description="d", input_schema=None):
    return SimpleNamespace(
        name=name, description=description, input_schema=input_schema or {}
    )


def test_jsonrpc_response_shape():
    # Arrange / Act
    r = mcp.create_jsonrpc_response("abc", {"ok": 1})
    # Assert
    assert r == {"jsonrpc": "2.0", "id": "abc", "result": {"ok": 1}}


def test_jsonrpc_response_id_passthrough():
    assert mcp.create_jsonrpc_response(7, None)["id"] == 7
    assert mcp.create_jsonrpc_response(None, None)["id"] is None


def test_jsonrpc_error_omits_data_when_none():
    e = mcp.create_jsonrpc_error("id1", -32600, "Invalid Request")
    assert e == {
        "jsonrpc": "2.0",
        "id": "id1",
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    assert "data" not in e["error"]


def test_jsonrpc_error_includes_data_when_provided():
    e = mcp.create_jsonrpc_error(None, -32700, "Parse error", "boom")
    assert e["error"]["data"] == "boom"


def test_is_valid_jsonrpc_request():
    assert mcp.is_valid_jsonrpc_request({"jsonrpc": "2.0", "method": "x"}) is True
    assert mcp.is_valid_jsonrpc_request({"jsonrpc": "1.0"}) is False
    assert mcp.is_valid_jsonrpc_request({}) is False
    assert mcp.is_valid_jsonrpc_request([1, 2]) is False
    assert mcp.is_valid_jsonrpc_request("nope") is False
    assert mcp.is_valid_jsonrpc_request(None) is False


def test_negotiate_protocol_version_supported():
    supported = mcp.MCP_PROTOCOL_VERSIONS[1]
    assert mcp.negotiate_protocol_version(supported) == supported


def test_negotiate_protocol_version_fallback():
    assert mcp.negotiate_protocol_version("1999-01-01") == mcp.MCP_PROTOCOL_VERSION
    assert mcp.negotiate_protocol_version(None) == mcp.MCP_PROTOCOL_VERSION


def test_build_initialize_result_shape():
    res = mcp.build_initialize_result("2024-11-05", "9.9.9")
    assert res["protocolVersion"] == "2024-11-05"
    assert res["serverInfo"]["version"] == "9.9.9"
    assert res["serverInfo"]["name"] == "MoviePilot"
    assert res["capabilities"]["tools"]["listChanged"] is False
    assert "logging" in res["capabilities"]
    assert "instructions" in res


def test_filter_exposed_tools_removes_every_hidden():
    tools = [
        _tool("read_file"),
        _tool("search_media"),
        _tool("write_file"),
        _tool("subscribe"),
    ]
    names = {t.name for t in mcp.filter_exposed_tools(tools)}
    assert names == {"search_media", "subscribe"}
    assert not (names & mcp.MCP_HIDDEN_TOOLS)


def test_tool_to_mcp_dict_maps_input_schema_key():
    out = mcp.tool_to_mcp_dict(_tool("x", "y", {"k": 1}))
    assert out == {"name": "x", "description": "y", "inputSchema": {"k": 1}}


def test_tools_to_mcp_format():
    tools = [_tool("a", "desc-a", {"type": "object"}), _tool("b", "desc-b", {})]
    out = mcp.tools_to_mcp_format(tools)
    assert out == [
        {"name": "a", "description": "desc-a", "inputSchema": {"type": "object"}},
        {"name": "b", "description": "desc-b", "inputSchema": {}},
    ]
