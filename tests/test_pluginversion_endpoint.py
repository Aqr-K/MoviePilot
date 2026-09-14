"""插件版本查询与实例版本绑定切换接口测试。"""

from __future__ import annotations

import inspect

from app.api.dependencies.auth import get_current_active_superuser
from app.api.endpoints import pluginversion as pluginversion_endpoint
from app.api.endpoints.pluginversion import (
    plugin_version_overview,
    set_plugin_instance_version,
)
from app.schemas.plugin import PluginInstanceVersionUpdateRequest


def _depends_default(func, parameter_name: str):
    """取出端点函数指定参数的 FastAPI Depends 默认值。"""
    return inspect.signature(func).parameters[parameter_name].default


def _manager(**methods):
    """构造只实现指定方法的 Manager 替身。"""
    return type("Manager", (), methods)()


def _overview(instance_ids: tuple[str, ...] = (), current: str | None = "1.0.0") -> dict:
    """构造一份最小版本总览。"""
    return {
        "plugin_id": "DemoPlugin",
        "current_version": current,
        "installed_versions": [],
        "instances": [
            {"instance_id": instance_id, "pinned_version": None, "running": False}
            for instance_id in instance_ids
        ],
    }


def _raise_missing(_plugin_id: str):
    """模拟插件不存在。"""
    raise LookupError("插件 Missing 不存在")


def test_both_endpoints_require_superuser_dependency():
    """两个端点都要求超级管理员，不能被低权限用户直接调用。"""
    for func in (plugin_version_overview, set_plugin_instance_version):
        depends = _depends_default(func, "_")
        assert depends.dependency is get_current_active_superuser


def test_plugin_version_overview_returns_manager_result(monkeypatch):
    """接口把 Manager 组装好的总览原样透传给调用方。"""
    overview = _overview(("DemoPlugin",), current="2.0.0")
    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(get_plugin_version_overview=lambda self, _plugin_id: overview),
    )

    result = plugin_version_overview("DemoPlugin", None)

    assert result.success is True
    assert result.data == overview


def test_plugin_version_overview_reports_missing_plugin(monkeypatch):
    """插件不存在时返回失败响应，而不是让异常穿透接口。"""
    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(
            get_plugin_version_overview=lambda self, plugin_id: _raise_missing(plugin_id)
        ),
    )

    result = plugin_version_overview("Missing", None)

    assert result.success is False
    assert "不存在" in result.message


def test_set_plugin_instance_version_rejects_instance_outside_plugin(monkeypatch):
    """目标实例不在该插件的实例列表里时拒绝，不下发到 Manager 的切换逻辑。"""
    calls: list = []
    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(
            get_plugin_version_overview=lambda self, _plugin_id: _overview(("OtherWork",)),
            set_plugin_instance_version=lambda self, *args, **kwargs: calls.append(
                (args, kwargs)
            ),
        ),
    )

    result = set_plugin_instance_version(
        "DemoPlugin",
        "DemoPluginWork",
        PluginInstanceVersionUpdateRequest(),
        None,
    )

    assert result.success is False
    assert "不存在" in result.message
    assert calls == []


def test_set_plugin_instance_version_delegates_and_reports_success(monkeypatch):
    """已知实例的切换请求原样转交给 Manager，并按其结果返回成功响应。"""
    calls: list = []

    def _set_version(_self, instance_id, *, pinned_version=None):
        """记录一次切换请求。"""
        calls.append((instance_id, pinned_version))
        return True, instance_id

    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(
            get_plugin_version_overview=lambda self, _plugin_id: _overview(
                ("DemoPluginWork",)
            ),
            set_plugin_instance_version=_set_version,
        ),
    )

    result = set_plugin_instance_version(
        "DemoPlugin",
        "DemoPluginWork",
        PluginInstanceVersionUpdateRequest(pinned_version="2.0.0"),
        None,
    )

    assert result.success is True
    assert result.message == "版本切换成功"
    assert calls == [("DemoPluginWork", "2.0.0")]


def test_set_plugin_instance_version_passes_none_to_unpin(monkeypatch):
    """不带版本号的请求表示改为跟随当前版本，原样以空值下发。"""
    calls: list = []

    def _set_version(_self, instance_id, *, pinned_version=None):
        """记录一次切换请求。"""
        calls.append((instance_id, pinned_version))
        return True, instance_id

    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(
            get_plugin_version_overview=lambda self, _plugin_id: _overview(
                ("DemoPluginWork",)
            ),
            set_plugin_instance_version=_set_version,
        ),
    )

    set_plugin_instance_version(
        "DemoPlugin",
        "DemoPluginWork",
        PluginInstanceVersionUpdateRequest(),
        None,
    )

    assert calls == [("DemoPluginWork", None)]


def test_set_plugin_instance_version_propagates_manager_failure_message(monkeypatch):
    """Manager 拒绝切换时把可读原因原样返回给调用方。"""
    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(
            get_plugin_version_overview=lambda self, _plugin_id: _overview(
                ("DemoPluginWork",)
            ),
            set_plugin_instance_version=lambda self, *args, **kwargs: (
                False,
                "插件 DemoPlugin 未安装版本 9.9.9",
            ),
        ),
    )

    result = set_plugin_instance_version(
        "DemoPlugin",
        "DemoPluginWork",
        PluginInstanceVersionUpdateRequest(pinned_version="9.9.9"),
        None,
    )

    assert result.success is False
    assert result.message == "插件 DemoPlugin 未安装版本 9.9.9"


def test_set_plugin_instance_version_reports_missing_plugin(monkeypatch):
    """插件本身不存在时同样返回失败响应，不下发到实例切换逻辑。"""
    monkeypatch.setattr(
        pluginversion_endpoint,
        "get_plugin_manager",
        lambda: _manager(
            get_plugin_version_overview=lambda self, plugin_id: _raise_missing(plugin_id)
        ),
    )

    result = set_plugin_instance_version(
        "Missing",
        "MissingWork",
        PluginInstanceVersionUpdateRequest(),
        None,
    )

    assert result.success is False
    assert "不存在" in result.message


def test_router_registers_the_version_paths():
    """路由器暴露版本总览与实例切换两条路径。"""
    paths = {route.path for route in pluginversion_endpoint.router.routes}

    assert paths == {"/versions/{plugin_id}", "/versions/{plugin_id}/{instance_id}"}


def test_version_router_is_mounted_under_the_plugin_prefix():
    """版本路由挂在 /plugin 前缀下，与其它插件管理接口同一命名空间。"""
    from app.api.routers import API_V1_ROUTER_SPECS

    spec = next(
        item for item in API_V1_ROUTER_SPECS if item.router is pluginversion_endpoint.router
    )

    assert spec.prefix == "/plugin"
    assert spec.tags == ("plugin",)
