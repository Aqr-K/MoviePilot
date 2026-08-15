"""插件多实例的外围设施：定时服务、菜单命令、接口路由、定向事件与实例增删。

外围设施只要仍按插件类名寻址，分身实例就会被静默吞掉：job id 相同则后注册的顶掉先注册的、
路由前缀对不上则卸载时删不掉、命令重名则互相覆盖，全程没有任何日志。反过来，默认实例的
job id、路由、命令与 Agent 工具行为必须逐字节保持原样，否则全部存量单实例插件一次性改名。
"""
import threading
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, Mock, patch

import pytest
from fastapi import HTTPException

from app import schemas
from app.api.endpoints import plugin as plugin_endpoint
from app.command import Command
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, PluginConfig
from app.db.models.plugindata import PluginData
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.plugins import _PluginBase
from app.runtime.events import Event, eventmanager
from app.runtime.extensions.plugin_instance import instance_key
from app.runtime.extensions.plugin_manager import PluginManager
from app.scheduler import Scheduler
from app.schemas.types import EventType

PLUGIN_ID = "InstanceSurfacePlugin"
ALPHA_KEY = f"{PLUGIN_ID}@alpha"

# 事件投递的落点，记录实例标识
RECEIVED: list = []


class InstanceSurfacePlugin(_PluginBase):
    """同时声明定时服务、命令、接口和前端入口的最小插件实现。"""

    plugin_name = "实例外围示例插件"
    plugin_version = "1.0"

    def init_plugin(self, config: dict = None):
        self.inited_with = config

    def get_state(self) -> bool:
        return True

    def get_service(self) -> List[Dict[str, Any]]:
        return [{
            "id": "sync",
            "name": "同步任务",
            "trigger": "interval",
            "func": self.handle,
            "kwargs": {"seconds": 60},
        }]

    def get_command(self) -> List[Dict[str, Any]]:
        return [{
            "cmd": "/surface",
            "event": EventType.PluginAction,
            "desc": "示例命令",
            "category": "示例",
            "data": {},
        }]

    def get_api(self) -> List[Dict[str, Any]]:
        return [{
            "path": "/state",
            "endpoint": self.get_state,
            "methods": ["GET"],
            "summary": "状态",
        }]

    @staticmethod
    def get_render_mode() -> Tuple[str, Optional[str]]:
        return "vue", "dist/assets"

    def get_dashboard_meta(self) -> List[Dict[str, str]]:
        return [{"key": "board", "name": "示例面板"}]

    def get_dashboard(self, key: str = "", **kwargs):
        return {}, {}, []

    def get_sidebar_nav(self) -> List[Dict[str, Any]]:
        return [{"nav_key": "main", "title": "示例入口"}]

    def get_auth_providers(self) -> List[Dict[str, Any]]:
        return [{"id": "surface"}]

    def get_form(self):
        return [], {"token": ""}

    def get_page(self):
        return []

    def stop_service(self):
        pass

    def handle(self, event: Optional[Event] = None) -> None:
        """把本实例的身份记入投递落点。"""
        RECEIVED.append(self.instance_id)


@pytest.fixture(autouse=True)
def _track(db):
    """把本文件涉及的表纳入用例级回收。"""
    db.watermark(PluginConfig, PluginData)


@pytest.fixture(autouse=True)
def _reset_received():
    """每个用例独享事件落点。"""
    RECEIVED.clear()
    yield
    RECEIVED.clear()


@pytest.fixture
def manager():
    """构造与全局单例隔离、容器为空的插件管理器。"""
    instance = object.__new__(PluginManager)
    instance._plugins = {}
    instance._running_plugins = {}
    instance._plugin_agent_tools_cache = {}
    instance._plugin_agent_tools_cache_lock = threading.Lock()
    instance._plugin_agent_tools_revision = 0
    return instance


def running(manager: PluginManager, *instance_ids: str) -> dict:
    """在管理器中登记若干实例，返回 {实例标识: 插件实例}。"""
    instances = {}
    for instance_id in instance_ids:
        key = instance_key(PLUGIN_ID, instance_id)
        plugin = PluginManager._instantiate_plugin(InstanceSurfacePlugin, PLUGIN_ID, instance_id)
        manager._plugins[key] = InstanceSurfacePlugin
        manager._running_plugins[key] = plugin
        instances[instance_id] = plugin
    return instances


def build_scheduler() -> Scheduler:
    """构造不启动 APScheduler 的定时服务测试对象。"""
    scheduler = object.__new__(Scheduler)
    scheduler._lock = threading.RLock()
    scheduler._jobs = {}
    scheduler._scheduler = MagicMock()
    return scheduler


def patched_plugin_manager(manager: PluginManager):
    """让定时服务取到指定的插件管理器实例。"""
    return patch("app.scheduler.PluginManager", Mock(return_value=manager))


def fake_app(*paths: str) -> SimpleNamespace:
    """构造只含路由路径的应用替身。"""
    return SimpleNamespace(routes=[SimpleNamespace(path=path) for path in paths],
                           openapi_schema=None)


# --------------------------------------------------------------------------- #
# 定时服务
# --------------------------------------------------------------------------- #

def test_single_instance_job_id_and_registry_are_unchanged(manager):
    """单实例插件的 job id、归属与展示名称保持原样。"""
    running(manager, DEFAULT_INSTANCE_ID)
    scheduler = build_scheduler()

    with patched_plugin_manager(manager):
        scheduler.update_plugin_job(PLUGIN_ID)

    assert list(scheduler._jobs) == [f"{PLUGIN_ID}_sync"]
    job = scheduler._jobs[f"{PLUGIN_ID}_sync"]
    assert job["pid"] == PLUGIN_ID
    assert job["provider_name"] == InstanceSurfacePlugin.plugin_name
    assert scheduler._scheduler.add_job.call_args.kwargs["id"] == f"{PLUGIN_ID}_sync"


def test_every_instance_gets_its_own_job(manager):
    """同插件双实例声明同名服务时各自成 job，后注册的不得顶掉先注册的。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    scheduler = build_scheduler()

    with patched_plugin_manager(manager):
        scheduler.update_plugin_job(PLUGIN_ID)

    assert sorted(scheduler._jobs) == [f"{ALPHA_KEY}_sync", f"{PLUGIN_ID}_sync"]
    assert scheduler._jobs[f"{ALPHA_KEY}_sync"]["pid"] == ALPHA_KEY
    assert scheduler._jobs[f"{ALPHA_KEY}_sync"]["provider_name"] == "实例外围示例插件(alpha)"
    registered_ids = {
        call.kwargs["id"] for call in scheduler._scheduler.add_job.call_args_list
    }
    assert registered_ids == {f"{PLUGIN_ID}_sync", f"{ALPHA_KEY}_sync"}


def test_init_plugin_jobs_covers_every_instance(manager):
    """初始化按插件登记一次，插件的每个实例都要拿到自己的定时任务。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    scheduler = build_scheduler()

    with patched_plugin_manager(manager):
        scheduler.init_plugin_jobs()

    assert sorted(scheduler._jobs) == [f"{ALPHA_KEY}_sync", f"{PLUGIN_ID}_sync"]


def test_removing_by_plugin_id_takes_down_every_instance_job(manager):
    """按插件ID移除时该插件全部实例的定时任务一并下线。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    scheduler = build_scheduler()

    with patched_plugin_manager(manager):
        scheduler.update_plugin_job(PLUGIN_ID)
        scheduler.remove_plugin_job(PLUGIN_ID)

    assert scheduler._jobs == {}


def test_removing_by_instance_key_keeps_sibling_jobs(manager):
    """按实例键移除只影响该实例，同插件其余实例的定时任务照常运行。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    scheduler = build_scheduler()

    with patched_plugin_manager(manager):
        scheduler.update_plugin_job(PLUGIN_ID)
        scheduler.remove_plugin_job(ALPHA_KEY)

    assert list(scheduler._jobs) == [f"{PLUGIN_ID}_sync"]


def test_plugin_services_carry_their_owner_instance_key(manager):
    """服务声明带上归属实例键，调用方才可能区分同插件的多个实例。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")

    owners = sorted(service["pid"] for service in manager.get_plugin_services())

    assert owners == [PLUGIN_ID, ALPHA_KEY]


# --------------------------------------------------------------------------- #
# 菜单命令
# --------------------------------------------------------------------------- #

def build_command(commands: List[Dict[str, Any]]) -> Command:
    """构造只保留插件命令构建能力的命令管理器。"""
    command = object.__new__(Command)
    command.pluginmanager = SimpleNamespace(
        get_plugin_commands=lambda pid=None: commands
    )
    return command


def plugin_command(pid: str) -> Dict[str, Any]:
    """构造一条归属指定实例的插件命令声明。"""
    return {
        "cmd": "/surface",
        "event": EventType.PluginAction,
        "desc": "示例命令",
        "category": "示例",
        "data": {},
        "pid": pid,
    }


def test_single_instance_command_registration_is_unchanged():
    """单实例插件的命令内容保持原样。"""
    command = build_command([plugin_command(PLUGIN_ID)])

    built = command._Command__build_plugin_commands()

    assert built == {
        "/surface": {
            "pid": PLUGIN_ID,
            "func": command.send_plugin_event,
            "description": "示例命令",
            "category": "示例",
            "show": True,
            "data": {"etype": EventType.PluginAction, "data": {}},
        }
    }


def test_conflicting_command_keeps_the_first_owner_and_warns():
    """两个实例声明同一条命令时先到者胜，冲突必须留下告警而不是静默覆盖。"""
    command = build_command([plugin_command(PLUGIN_ID), plugin_command(ALPHA_KEY)])

    with patch("app.command.logger") as logger:
        built = command._Command__build_plugin_commands()

    assert built["/surface"]["pid"] == PLUGIN_ID
    warning = logger.warning.call_args.args[0]
    assert PLUGIN_ID in warning and ALPHA_KEY in warning


def test_same_owner_redeclaring_a_command_updates_it():
    """同一来源重复声明按最后一次声明更新，不当作冲突。"""
    latest = {**plugin_command(PLUGIN_ID), "desc": "最新描述"}
    command = build_command([plugin_command(PLUGIN_ID), latest])

    with patch("app.command.logger") as logger:
        built = command._Command__build_plugin_commands()

    assert built["/surface"]["description"] == "最新描述"
    logger.warning.assert_not_called()


# --------------------------------------------------------------------------- #
# 接口路由
# --------------------------------------------------------------------------- #

def test_single_instance_route_removal_is_unchanged():
    """单实例插件的路由回收范围保持原样，同前缀的其他插件不受牵连。"""
    routes = fake_app(
        f"{plugin_endpoint.PLUGIN_PREFIX}/{PLUGIN_ID}/state",
        f"{plugin_endpoint.PLUGIN_PREFIX}/{PLUGIN_ID}Other/state",
        f"{plugin_endpoint.PLUGIN_PREFIX}/{{plugin_id}}",
    )

    with patch.object(plugin_endpoint, "app", routes):
        assert plugin_endpoint._remove_routes(PLUGIN_ID) is True

    assert [route.path for route in routes.routes] == [
        f"{plugin_endpoint.PLUGIN_PREFIX}/{PLUGIN_ID}Other/state",
        f"{plugin_endpoint.PLUGIN_PREFIX}/{{plugin_id}}",
    ]


def test_instance_routes_are_removed_together_with_the_plugin():
    """按插件ID卸载时分身实例的路由也要删掉，否则旧路由长期指向已停实例。"""
    routes = fake_app(
        f"{plugin_endpoint.PLUGIN_PREFIX}/{PLUGIN_ID}/state",
        f"{plugin_endpoint.PLUGIN_PREFIX}/{ALPHA_KEY}/state",
        f"{plugin_endpoint.PLUGIN_PREFIX}/file/{PLUGIN_ID}/dist/remoteEntry.js",
    )

    with patch.object(plugin_endpoint, "app", routes):
        plugin_endpoint._remove_routes(PLUGIN_ID)

    assert [route.path for route in routes.routes] == [
        f"{plugin_endpoint.PLUGIN_PREFIX}/file/{PLUGIN_ID}/dist/remoteEntry.js"
    ]


def test_removing_one_instance_keeps_sibling_routes():
    """按实例键卸载只回收该实例的路由。"""
    routes = fake_app(
        f"{plugin_endpoint.PLUGIN_PREFIX}/{PLUGIN_ID}/state",
        f"{plugin_endpoint.PLUGIN_PREFIX}/{ALPHA_KEY}/state",
    )

    with patch.object(plugin_endpoint, "app", routes):
        plugin_endpoint._remove_routes(ALPHA_KEY)

    assert [route.path for route in routes.routes] == [
        f"{plugin_endpoint.PLUGIN_PREFIX}/{PLUGIN_ID}/state"
    ]


def test_frontend_entry_ids_match_the_registered_routes(manager):
    """前端据以拼接接口路径的标识必须与实际注册的路由前缀一致。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    registered = {
        f"{plugin_endpoint.PLUGIN_PREFIX}{api['path']}" for api in manager.get_plugin_apis()
    }

    entry_ids = (
        {item["id"] for item in manager.get_plugin_dashboard_meta()}
        | {item["plugin_id"] for item in manager.get_plugin_sidebar_nav()}
        | {item["plugin_id"] for item in manager.get_plugin_auth_providers()}
    )

    assert entry_ids == {PLUGIN_ID, ALPHA_KEY}
    assert registered == {
        f"{plugin_endpoint.PLUGIN_PREFIX}/{entry_id}/state" for entry_id in entry_ids
    }


def test_static_resources_are_addressed_by_the_plugin_source_directory(manager):
    """联邦入口指向插件源码目录，分身实例不得拼出不存在的目录。"""
    running(manager, "alpha")

    providers = manager.get_plugin_auth_providers()
    remotes = manager.get_plugin_remotes()

    assert manager.get_plugin_remote_entry(ALPHA_KEY, "dist/assets") == (
        f"/plugin/file/{PLUGIN_ID.lower()}/dist/assets/remoteEntry.js"
    )
    assert [provider["remote"]["id"] for provider in providers] == [PLUGIN_ID]
    assert [remote["id"] for remote in remotes] == [PLUGIN_ID]
    assert remotes[0]["url"] == f"/plugin/file/{PLUGIN_ID.lower()}/dist/assets/remoteEntry.js"


def test_auth_remote_of_an_instance_stays_anonymously_readable(manager):
    """登录页要在无登录态时加载分身实例声明的认证组件。"""
    running(manager, "alpha")

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=manager)):
        readable = plugin_endpoint._is_plugin_auth_remote_file(
            PLUGIN_ID, "dist/assets/remoteEntry.js"
        )

    assert readable is True


# --------------------------------------------------------------------------- #
# 定向事件
# --------------------------------------------------------------------------- #

def dispatch_to(target: Optional[str]) -> None:
    """按事件总线的内部调用路径做一次定向投递。"""
    eventmanager._EventManager__invoke_handler_by_type_sync(
        InstanceSurfacePlugin.handle,
        Event(EventType.MessageAction, {"text": "自由文本"}),
        True,
        target,
    )


def two_running_instances(monkeypatch) -> None:
    """让全局插件管理器持有该插件的默认实例和分身实例。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {
        PLUGIN_ID: InstanceSurfacePlugin,
        ALPHA_KEY: InstanceSurfacePlugin,
    })
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            InstanceSurfacePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
        ALPHA_KEY: PluginManager._instantiate_plugin(
            InstanceSurfacePlugin, PLUGIN_ID, "alpha"
        ),
    })


def test_targeted_input_reaches_only_the_named_instance(monkeypatch):
    """定向到某个实例的自由文本不得被同插件的其他实例看到。"""
    two_running_instances(monkeypatch)

    dispatch_to(ALPHA_KEY)

    assert RECEIVED == ["alpha"]


def test_target_without_instance_still_reaches_every_instance(monkeypatch):
    """目标只给到插件标识时，该插件的全部实例仍按原行为收取。"""
    two_running_instances(monkeypatch)

    dispatch_to(PLUGIN_ID)

    assert sorted(RECEIVED) == ["alpha", DEFAULT_INSTANCE_ID]


def test_single_instance_targeted_delivery_is_unchanged(monkeypatch):
    """单实例插件的定向投递行为保持原样。"""
    plugin_manager = PluginManager()
    monkeypatch.setattr(plugin_manager, "_plugins", {PLUGIN_ID: InstanceSurfacePlugin})
    monkeypatch.setattr(plugin_manager, "_running_plugins", {
        PLUGIN_ID: PluginManager._instantiate_plugin(
            InstanceSurfacePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
        ),
    })

    dispatch_to(PLUGIN_ID)

    assert RECEIVED == [DEFAULT_INSTANCE_ID]


@pytest.mark.parametrize("target", [PLUGIN_ID, ALPHA_KEY])
def test_instance_key_target_still_selects_the_plugin_class(target):
    """实例键同样要能命中插件类，否则定向事件会被整类丢弃。"""
    handler = InstanceSurfacePlugin.handle
    identifier = eventmanager._EventManager__get_handler_identifier(handler)

    assert eventmanager._EventManager__should_dispatch_to_target_plugin(
        handler, identifier, target
    ) is True


def test_target_of_another_plugin_is_rejected():
    """目标插件不是本类时整类拒绝投递。"""
    handler = InstanceSurfacePlugin.handle
    identifier = eventmanager._EventManager__get_handler_identifier(handler)

    assert eventmanager._EventManager__should_dispatch_to_target_plugin(
        handler, identifier, "OtherPlugin@alpha"
    ) is False


def test_plugin_exposes_its_own_instance_key():
    """插件要能拿到自己的实例键，才可能把输入会话定向回本实例。"""
    default_instance = PluginManager._instantiate_plugin(
        InstanceSurfacePlugin, PLUGIN_ID, DEFAULT_INSTANCE_ID
    )
    alpha = PluginManager._instantiate_plugin(InstanceSurfacePlugin, PLUGIN_ID, "alpha")

    assert default_instance.instance_key == PLUGIN_ID
    assert alpha.instance_key == ALPHA_KEY


# --------------------------------------------------------------------------- #
# 运行实例解析
# --------------------------------------------------------------------------- #

def test_form_and_page_reach_a_plugin_that_only_has_a_clone_instance(manager):
    """插件只有分身实例时，表单和数据页面按插件ID仍要取到实例。"""
    running(manager, "alpha")
    PluginConfigOper().set(PLUGIN_ID, {"token": "alpha-token"}, "alpha")

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=manager)):
        form = plugin_endpoint.plugin_form(ALPHA_KEY)
        page = plugin_endpoint.plugin_page(PLUGIN_ID)

    assert form["model"]["token"] == "alpha-token"
    assert page["render_mode"] == "vue"


def test_form_of_the_default_instance_reads_the_default_config(manager):
    """默认实例的表单仍读默认实例那一行配置。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    PluginConfigOper().set(PLUGIN_ID, {"token": "default-token"}, DEFAULT_INSTANCE_ID)
    PluginConfigOper().set(PLUGIN_ID, {"token": "alpha-token"}, "alpha")

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=manager)):
        form = plugin_endpoint.plugin_form(PLUGIN_ID)

    assert form["model"]["token"] == "default-token"


# --------------------------------------------------------------------------- #
# 实例增删
# --------------------------------------------------------------------------- #

def test_creating_the_first_clone_keeps_the_default_instance(manager):
    """创建首个分身时固化默认实例，默认实例不能因为没有配置行而在下次启动时缺席。"""
    running(manager, DEFAULT_INSTANCE_ID)

    created = manager.create_plugin_instance(PLUGIN_ID, "alpha", {"token": "alpha-token"})

    assert created == ALPHA_KEY
    assert sorted(PluginManager._list_instance_ids(PLUGIN_ID)) == ["alpha", DEFAULT_INSTANCE_ID]
    assert manager.get_plugin_config(PLUGIN_ID, "alpha") == {"token": "alpha-token"}
    assert manager.get_plugin_config(PLUGIN_ID) == {}


def test_creating_an_existing_or_default_instance_is_rejected(manager):
    """默认实例随插件自动创建，重复创建和重名创建都要当场拒绝。"""
    running(manager, DEFAULT_INSTANCE_ID)
    manager.create_plugin_instance(PLUGIN_ID, "alpha")

    with pytest.raises(ValueError):
        manager.create_plugin_instance(PLUGIN_ID, DEFAULT_INSTANCE_ID)
    with pytest.raises(ValueError):
        manager.create_plugin_instance(PLUGIN_ID, "alpha")


def test_creating_an_instance_with_an_illegal_id_is_rejected(manager):
    """实例标识会拼进数据目录，非法字符必须在落库前拒绝。"""
    running(manager, DEFAULT_INSTANCE_ID)

    with pytest.raises(ValueError):
        manager.create_plugin_instance(PLUGIN_ID, "../etc")


def test_deleting_an_instance_clears_its_config_and_data(manager):
    """删除实例要停掉运行态并清掉它自己的配置与数据，同插件其余实例不受影响。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha")
    PluginConfigOper().set(PLUGIN_ID, {"token": "alpha-token"}, "alpha")
    data_oper = PluginDataOper()
    data_oper.save(PLUGIN_ID, "state", {"v": "default"}, DEFAULT_INSTANCE_ID)
    data_oper.save(PLUGIN_ID, "state", {"v": "alpha"}, "alpha")

    with patch("app.runtime.extensions.plugin_manager.ModuleManager") as module_manager:
        module_manager.get_existing_instance.return_value = None
        removed = manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert removed == ALPHA_KEY
    assert manager.get_instance_keys(PLUGIN_ID) == [PLUGIN_ID]
    assert PluginConfigOper().get_instance(PLUGIN_ID, "alpha") is None
    assert data_oper.get_data(PLUGIN_ID, "state", "alpha") is None
    assert data_oper.get_data(PLUGIN_ID, "state", DEFAULT_INSTANCE_ID) == {"v": "default"}


def test_deleting_the_default_instance_is_rejected(manager):
    """默认实例不允许删除。"""
    running(manager, DEFAULT_INSTANCE_ID)

    with pytest.raises(ValueError):
        manager.delete_plugin_instance(PLUGIN_ID, DEFAULT_INSTANCE_ID)


def test_instance_list_falls_back_to_the_default_instance(manager):
    """没有配置任何实例时按默认实例呈现，与拉起逻辑一致。"""
    running(manager, DEFAULT_INSTANCE_ID)

    instances = manager.get_plugin_instances(PLUGIN_ID)

    assert instances == [{
        "plugin_id": PLUGIN_ID,
        "instance_id": DEFAULT_INSTANCE_ID,
        "instance_key": PLUGIN_ID,
        "is_default": True,
        "running": True,
        "enabled": True,
    }]


def test_instance_list_covers_configured_and_running_instances(manager):
    """已配置但未拉起的实例同样要出现在列表里。"""
    running(manager, DEFAULT_INSTANCE_ID)
    PluginConfigOper().set(PLUGIN_ID, {"enable": True}, "alpha")

    instances = {item["instance_id"]: item for item in manager.get_plugin_instances(PLUGIN_ID)}

    assert sorted(instances) == ["alpha", DEFAULT_INSTANCE_ID]
    assert instances["alpha"]["running"] is False
    assert instances["alpha"]["enabled"] is True
    assert instances["alpha"]["instance_key"] == ALPHA_KEY


# --------------------------------------------------------------------------- #
# 实例接口
# --------------------------------------------------------------------------- #

def instance_record(instance_id: str) -> Dict[str, Any]:
    """构造一条实例列表记录。"""
    return {
        "plugin_id": PLUGIN_ID,
        "instance_id": instance_id,
        "instance_key": instance_key(PLUGIN_ID, instance_id),
        "is_default": instance_id == DEFAULT_INSTANCE_ID,
        "running": True,
        "enabled": True,
    }


def test_instance_list_endpoint_returns_the_declared_response_model():
    """实例列表接口的返回值必须能被声明的响应模型接住。"""
    plugin_manager = MagicMock()
    plugin_manager.has_plugin.return_value = True
    plugin_manager.get_plugin_instances.return_value = [
        instance_record(DEFAULT_INSTANCE_ID), instance_record("alpha")
    ]

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)):
        instances = plugin_endpoint.plugin_instances(PLUGIN_ID)

    parsed = [schemas.PluginInstanceInfo.model_validate(item) for item in instances]
    assert [item.instance_key for item in parsed] == [PLUGIN_ID, ALPHA_KEY]


def test_instance_list_endpoint_rejects_an_unknown_plugin():
    """插件未加载时列表接口直接 404。"""
    plugin_manager = MagicMock()
    plugin_manager.has_plugin.return_value = False

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)):
        with pytest.raises(HTTPException) as error:
            plugin_endpoint.plugin_instances(PLUGIN_ID)

    assert error.value.status_code == 404


def test_create_instance_endpoint_starts_and_registers_the_instance():
    """创建实例后要拉起运行态并同步注册定时服务、命令与接口。"""
    plugin_manager = MagicMock()
    plugin_manager.has_plugin.return_value = True
    plugin_manager.create_plugin_instance.return_value = ALPHA_KEY
    plugin_manager.get_plugin_instances.return_value = [instance_record("alpha")]
    payload = schemas.PluginInstanceCreate(instance_id="alpha", config={"enable": True})

    with (
        patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)),
        patch.object(plugin_endpoint, "register_plugin") as register_plugin,
    ):
        response = plugin_endpoint.create_plugin_instance(PLUGIN_ID, payload)

    plugin_manager.create_plugin_instance.assert_called_once_with(
        PLUGIN_ID, "alpha", {"enable": True}
    )
    plugin_manager.reload_plugin.assert_called_once_with(PLUGIN_ID)
    register_plugin.assert_called_once_with(PLUGIN_ID)
    assert response.success is True
    assert schemas.Response[schemas.PluginInstanceInfo].model_validate(
        response.model_dump()
    ).data.instance_key == ALPHA_KEY


def test_create_instance_endpoint_rejects_an_illegal_instance_id():
    """非法实例标识在进入插件管理器之前就被拒绝。"""
    plugin_manager = MagicMock()
    plugin_manager.has_plugin.return_value = True
    payload = schemas.PluginInstanceCreate(instance_id="../etc")

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)):
        with pytest.raises(HTTPException) as error:
            plugin_endpoint.create_plugin_instance(PLUGIN_ID, payload)

    assert error.value.status_code == 400
    plugin_manager.create_plugin_instance.assert_not_called()


def test_delete_instance_endpoint_unregisters_the_instance():
    """删除实例后要回收该实例的接口与定时服务，并重建菜单命令。"""
    plugin_manager = MagicMock()
    plugin_manager.get_plugin_instances.return_value = [
        instance_record(DEFAULT_INSTANCE_ID), instance_record("alpha")
    ]
    plugin_manager.delete_plugin_instance.return_value = ALPHA_KEY

    with (
        patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)),
        patch.object(plugin_endpoint, "remove_plugin_api") as remove_plugin_api,
        patch.object(plugin_endpoint, "Scheduler") as scheduler,
        patch.object(plugin_endpoint, "Command") as command,
    ):
        response = plugin_endpoint.delete_plugin_instance(PLUGIN_ID, "alpha")

    plugin_manager.delete_plugin_instance.assert_called_once_with(PLUGIN_ID, "alpha")
    remove_plugin_api.assert_called_once_with(ALPHA_KEY)
    scheduler.return_value.remove_plugin_job.assert_called_once_with(ALPHA_KEY)
    command.return_value.init_commands.assert_called_once_with(PLUGIN_ID)
    assert response.success is True


def test_delete_instance_endpoint_refuses_the_default_instance():
    """默认实例不允许删除，接口要给出明确错误而不是静默成功。"""
    plugin_manager = MagicMock()
    plugin_manager.get_plugin_instances.return_value = [instance_record(DEFAULT_INSTANCE_ID)]
    plugin_manager.delete_plugin_instance.side_effect = ValueError("默认实例不允许删除")

    with (
        patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)),
        patch.object(plugin_endpoint, "remove_plugin_api") as remove_plugin_api,
    ):
        with pytest.raises(HTTPException) as error:
            plugin_endpoint.delete_plugin_instance(PLUGIN_ID, DEFAULT_INSTANCE_ID)

    assert error.value.status_code == 400
    assert "默认实例" in error.value.detail
    remove_plugin_api.assert_not_called()


def test_delete_instance_endpoint_rejects_an_unknown_instance():
    """删除不存在的实例返回 404。"""
    plugin_manager = MagicMock()
    plugin_manager.get_plugin_instances.return_value = [instance_record(DEFAULT_INSTANCE_ID)]

    with patch.object(plugin_endpoint, "PluginManager", Mock(return_value=plugin_manager)):
        with pytest.raises(HTTPException) as error:
            plugin_endpoint.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert error.value.status_code == 404
    plugin_manager.delete_plugin_instance.assert_not_called()
