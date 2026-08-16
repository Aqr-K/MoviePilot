"""卸载插件与删除实例这两条下线路径对分身实例的覆盖。

两条路径只要还在插件类名这一层做清理，分身的注册面就会静默留在进程里：路由继续指向
已停实例、定时任务照常触发、模块与存储还挂在注册中心，全程没有任何报错。反过来，配置
与数据是用户资产，卸载只回收注册面，重新安装必须原样复用。
"""
import threading
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Tuple
from unittest.mock import MagicMock, Mock, patch

import pytest

from app.modules.storages.base import StorageBase
from app.adapters.storage.registry import (
    get_registered_storages,
    register_storage,
    unregister_storages,
)
from app.api.endpoints import plugin as plugin_endpoint
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, PluginConfig
from app.db.models.plugindata import PluginData
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.modules import _ModuleBase
from app.plugins import _PluginBase
from app.runtime.config import settings
from app.runtime.extensions import contract
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_instance import instance_key
from app.runtime.extensions.plugin_manager import PluginManager
from app.scheduler import Scheduler
from app.schemas.message import ChannelCapabilities, ChannelCapability, ChannelCapabilityManager
from app.schemas.types import MessageChannel, ModuleType, SystemConfigKey

PLUGIN_ID = "UninstallDemoPlugin"
ALPHA_KEY = f"{PLUGIN_ID}@alpha"
BETA_KEY = f"{PLUGIN_ID}@beta"
OWNER_KEYS = (PLUGIN_ID, ALPHA_KEY, BETA_KEY)

# 各实例注册的渠道能力所占用的渠道
OWNER_CHANNELS = {
    PLUGIN_ID: MessageChannel.VoceChat,
    ALPHA_KEY: MessageChannel.SynologyChat,
    BETA_KEY: MessageChannel.Discord,
}

# 插件实例停止时留下的痕迹，元素为实例标识
STOPPED: list = []


class UninstallDemoPlugin(_PluginBase):
    """用于验证下线路径的最小插件实现。"""

    plugin_name = "卸载示例插件"
    plugin_version = "1.0"

    def init_plugin(self, config: dict = None):
        pass

    def get_state(self) -> bool:
        return True

    def get_api(self):
        return []

    def get_form(self):
        return [], {}

    def get_page(self):
        return None

    def stop_service(self):
        STOPPED.append(self.instance_id)


class StubModule(_ModuleBase):
    """满足模块契约的最小实现"""

    def init_module(self) -> None:
        pass

    def init_setting(self) -> Optional[Tuple[str, bool]]:
        return None

    def stop(self) -> None:
        pass

    def test(self) -> Optional[Tuple[bool, str]]:
        return True, ""

    @staticmethod
    def get_name() -> str:
        return "UninstallStub"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.Other

    @staticmethod
    def get_subtype():
        return None

    @staticmethod
    def get_priority() -> int:
        return 0


def make_storage(name: str) -> type:
    """
    构造一个通过存储契约校验的存储类

    :param name: 存储的 schema 标识
    :return: 存储类
    """
    body = {method: (lambda self, *args, **kwargs: None)
            for method in StorageBase.__abstractmethods__}
    body.update({"schema": name, "transtype": {}})
    return type(f"Stub{name}", (StorageBase,), body)


# 每个实例各自注册一个存储，schema 不同才能同时在册
OWNER_STORAGES = {key: make_storage(f"stub_{index}") for index, key in enumerate(OWNER_KEYS)}


@pytest.fixture(autouse=True)
def _track(db):
    """把本文件涉及的表纳入用例级回收。"""
    db.watermark(PluginConfig, PluginData)


@pytest.fixture(autouse=True)
def _reset_stopped():
    """每个用例独享插件停止痕迹。"""
    STOPPED.clear()
    yield
    STOPPED.clear()


@pytest.fixture(autouse=True)
def _clean_registries():
    """用例前后清空本文件涉及的外部注册，避免污染同进程内的其它用例。"""
    def purge():
        """回收本用例可能留下的存储与渠道能力注册"""
        for owner in OWNER_KEYS:
            unregister_storages(owner)
            ChannelCapabilityManager.unregister_capabilities(owner)

    purge()
    yield
    purge()


@pytest.fixture(autouse=True)
def _module_base_configured():
    """按启动组合根的方式装配模块基类，用例结束后还原。"""
    previous = contract._module_base
    contract.configure_module_base(_ModuleBase)
    yield
    contract._module_base = previous


@pytest.fixture
def module_manager() -> ModuleManager:
    """构造与全局单例隔离、内建模块为空的模块管理器。"""
    instance = object.__new__(ModuleManager)
    with patch("app.runtime.extensions.module_manager.ModuleHelper.load", return_value=[]), \
            patch("app.runtime.extensions.module_manager.eventmanager"):
        instance.__init__()
    return instance


@pytest.fixture
def manager() -> PluginManager:
    """构造与全局单例隔离、容器为空的插件管理器。"""
    instance = object.__new__(PluginManager)
    instance._plugins = {}
    instance._running_plugins = {}
    return instance


@pytest.fixture
def loaded_manager(manager) -> PluginManager:
    """把插件登记为已加载，使配置与数据的删除无需 force。"""
    manager._plugins[PLUGIN_ID] = UninstallDemoPlugin
    return manager


@pytest.fixture
def plugin_data_root(tmp_path, monkeypatch) -> Path:
    """把插件数据根目录指向用例私有的临时目录。"""
    root = tmp_path / "plugins"
    root.mkdir()
    monkeypatch.setattr(type(settings), "PLUGIN_DATA_PATH", property(lambda _self: root))
    return root


def patched_module_manager(module_manager: ModuleManager):
    """让插件管理器取到指定的模块管理器实例，构造与查询两条取法都覆盖。"""
    stub = Mock(return_value=module_manager)
    stub.get_existing_instance.return_value = module_manager
    return patch("app.runtime.extensions.plugin_manager.ModuleManager", stub)


def running(manager: PluginManager, *instance_ids: str) -> None:
    """在管理器中登记若干运行态实例。"""
    for instance_id in instance_ids:
        key = instance_key(PLUGIN_ID, instance_id)
        plugin = PluginManager._instantiate_plugin(  # noqa: SLF001
            UninstallDemoPlugin, PLUGIN_ID, instance_id
        )
        manager.plugins[key] = UninstallDemoPlugin
        manager.running_plugins[key] = plugin


def register_extensions(manager: PluginManager, module_manager: ModuleManager) -> None:
    """为管理器中已登记的每个实例注册模块、存储与渠道能力。"""
    for key in manager.plugins:
        module_manager.register_module(StubModule, owner=key)
        register_storage(OWNER_STORAGES[key], owner=key)
        ChannelCapabilityManager.register_capabilities(
            ChannelCapabilities(
                channel=OWNER_CHANNELS[key],
                capabilities={ChannelCapability.INLINE_BUTTONS},
                max_buttons_per_row=1,
            ),
            owner=key,
        )


def seed_configs() -> None:
    """为默认实例与两个分身写入配置。"""
    config_oper = PluginConfigOper()
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "default"}, DEFAULT_INSTANCE_ID)
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "alpha"}, "alpha")
    config_oper.set(PLUGIN_ID, {"enable": True, "token": "beta"}, "beta")


def seed_data() -> None:
    """为默认实例与两个分身写入业务数据。"""
    data_oper = PluginDataOper()
    data_oper.save(PLUGIN_ID, "state", {"v": "default"}, DEFAULT_INSTANCE_ID)
    data_oper.save(PLUGIN_ID, "state", {"v": "alpha"}, "alpha")
    data_oper.save(PLUGIN_ID, "state", {"v": "beta"}, "beta")


def instance_ids() -> list:
    """读出插件当前落库的实例标识，按标识排序便于断言。"""
    return sorted(record.instance_id for record in PluginConfigOper().list_instances(PLUGIN_ID))


def stored_data(instance_id: str):
    """读出某个实例的业务数据。"""
    return PluginDataOper().get_data(PLUGIN_ID, "state", instance_id)


def fake_app(*paths: str) -> SimpleNamespace:
    """构造只含路由路径的应用替身。"""
    return SimpleNamespace(
        routes=[SimpleNamespace(path=path) for path in paths],
        openapi_schema=None,
        setup=lambda: None,
    )


def system_config_stub() -> MagicMock:
    """构造把插件登记为已安装、文件夹配置为空的系统配置替身。"""
    oper = MagicMock()
    oper.get.side_effect = lambda key: (
        [PLUGIN_ID] if key == SystemConfigKey.UserInstalledPlugins else {}
    )
    return oper


def run_uninstall(manager: PluginManager, app_stub=None, scheduler=None):
    """
    以指定的插件管理器执行卸载接口

    :param manager: 插件管理器
    :param app_stub: 应用替身，为空时不真正改动路由
    :param scheduler: 定时服务对象，为空时用替身接住调用
    :return: 接口响应
    """
    scheduler = scheduler if scheduler is not None else MagicMock()
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            plugin_endpoint, "SystemConfigOper", Mock(return_value=system_config_stub())))
        stack.enter_context(patch.object(
            plugin_endpoint, "PluginManager", Mock(return_value=manager)))
        stack.enter_context(patch.object(
            plugin_endpoint, "Scheduler", Mock(return_value=scheduler)))
        stack.enter_context(patch("app.scheduler.PluginManager", Mock(return_value=manager)))
        # 菜单重建走线程池，真调会把后台线程漏进随后的用例
        stack.enter_context(patch.object(plugin_endpoint, "Command", Mock()))
        if app_stub is not None:
            stack.enter_context(patch.object(plugin_endpoint, "app", app_stub))
        else:
            stack.enter_context(patch.object(plugin_endpoint, "remove_plugin_api"))
        return plugin_endpoint.uninstall_plugin(PLUGIN_ID, None)


# --------------------------------------------------------------------------- #
# 按实例删除配置与数据
# --------------------------------------------------------------------------- #

def test_deleting_config_without_an_instance_clears_every_instance(loaded_manager):
    """不指定实例时按插件删除，全部实例的配置一并清空。"""
    seed_configs()

    assert loaded_manager.delete_plugin_config(PLUGIN_ID) is True

    assert instance_ids() == []


def test_deleting_config_of_one_instance_keeps_the_others(loaded_manager):
    """指定实例时只删该实例的配置，兄弟实例的配置原样保留。"""
    seed_configs()

    assert loaded_manager.delete_plugin_config(PLUGIN_ID, instance_id="alpha") is True

    assert instance_ids() == ["beta", DEFAULT_INSTANCE_ID]
    assert loaded_manager.get_plugin_config(PLUGIN_ID, "beta") == {
        "enable": True, "token": "beta",
    }


def test_deleting_config_of_one_instance_of_an_unloaded_plugin_needs_force(manager):
    """插件未加载时按实例删除配置同样受 force 约束。"""
    seed_configs()

    assert manager.delete_plugin_config(PLUGIN_ID, instance_id="alpha") is False
    assert manager.delete_plugin_config(PLUGIN_ID, force=True, instance_id="alpha") is True

    assert instance_ids() == ["beta", DEFAULT_INSTANCE_ID]


def test_deleting_config_rejects_an_illegal_instance_id(loaded_manager):
    """实例标识非法时直接拒绝，不能落到按插件删除。"""
    seed_configs()

    with pytest.raises(ValueError):
        loaded_manager.delete_plugin_config(PLUGIN_ID, instance_id="../etc")

    assert instance_ids() == ["alpha", "beta", DEFAULT_INSTANCE_ID]


def test_deleting_data_without_an_instance_clears_every_instance(loaded_manager):
    """不指定实例时按插件删除，全部实例的数据一并清空。"""
    seed_data()

    assert loaded_manager.delete_plugin_data(PLUGIN_ID) is True

    assert stored_data(DEFAULT_INSTANCE_ID) is None
    assert stored_data("alpha") is None
    assert stored_data("beta") is None


def test_deleting_data_of_one_instance_keeps_the_others(loaded_manager):
    """指定实例时只删该实例的数据，兄弟实例的数据原样保留。"""
    seed_data()

    assert loaded_manager.delete_plugin_data(PLUGIN_ID, instance_id="alpha") is True

    assert stored_data("alpha") is None
    assert stored_data(DEFAULT_INSTANCE_ID) == {"v": "default"}
    assert stored_data("beta") == {"v": "beta"}


def test_deleting_data_of_one_instance_keeps_the_shared_database(loaded_manager):
    """自管理库由同插件全部实例共享，按实例删数据不得把它拆掉。"""
    with patch("app.db.plugin.teardown_plugin_database") as teardown:
        loaded_manager.delete_plugin_data(PLUGIN_ID, instance_id="alpha")

    teardown.assert_not_called()


def test_deleting_data_of_the_whole_plugin_drops_the_shared_database(loaded_manager):
    """整插件删数据才拆除自管理库。"""
    with patch("app.db.plugin.teardown_plugin_database") as teardown:
        loaded_manager.delete_plugin_data(PLUGIN_ID)

    teardown.assert_called_once_with(PLUGIN_ID)


def test_deleting_data_of_one_instance_of_an_unloaded_plugin_needs_force(manager):
    """插件未加载时按实例删除数据同样受 force 约束。"""
    seed_data()

    assert manager.delete_plugin_data(PLUGIN_ID, instance_id="alpha") is False
    assert manager.delete_plugin_data(PLUGIN_ID, force=True, instance_id="alpha") is True

    assert stored_data("alpha") is None
    assert stored_data("beta") == {"v": "beta"}


def test_deleting_data_rejects_an_illegal_instance_id(loaded_manager):
    """实例标识非法时直接拒绝，不能落到按插件删除。"""
    seed_data()

    with pytest.raises(ValueError):
        loaded_manager.delete_plugin_data(PLUGIN_ID, instance_id="../etc")

    assert stored_data(DEFAULT_INSTANCE_ID) == {"v": "default"}


# --------------------------------------------------------------------------- #
# 删除实例回收该实例的注册面
# --------------------------------------------------------------------------- #

def test_deleting_an_instance_stops_only_that_instance(manager, plugin_data_root):
    """删实例只停这一个实例，同插件其余实例继续运行。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")

    manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert STOPPED == ["alpha"]
    assert sorted(manager.running_plugins) == [PLUGIN_ID, BETA_KEY]


def test_deleting_an_instance_reclaims_only_its_extension_registrations(
        manager, module_manager, plugin_data_root
):
    """删实例回收该实例注册的模块、存储与渠道能力，兄弟实例的注册不受影响。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")

    with patched_module_manager(module_manager):
        register_extensions(manager, module_manager)
        assert module_manager.get_external_module_ids(ALPHA_KEY) != []
        assert OWNER_STORAGES[ALPHA_KEY] in get_registered_storages()
        manager.delete_plugin_instance(PLUGIN_ID, "alpha")

    assert module_manager.get_external_module_ids(ALPHA_KEY) == []
    assert module_manager.get_external_module_ids(BETA_KEY) != []
    assert OWNER_STORAGES[ALPHA_KEY] not in get_registered_storages()
    assert OWNER_STORAGES[BETA_KEY] in get_registered_storages()
    assert set(ChannelCapabilityManager.get_registered_owners().values()) == {
        PLUGIN_ID, BETA_KEY,
    }


# --------------------------------------------------------------------------- #
# 卸载插件覆盖全部实例
# --------------------------------------------------------------------------- #

def test_uninstalling_stops_every_instance(manager):
    """卸载插件后默认实例与全部分身都退出运行态。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")

    assert run_uninstall(manager).success is True

    assert sorted(STOPPED) == ["alpha", "beta", DEFAULT_INSTANCE_ID]
    assert manager.running_plugins == {}
    assert manager.plugins == {}


def test_uninstalling_reclaims_every_instance_extension_registration(manager, module_manager):
    """卸载插件后各实例注册的模块、存储与渠道能力全部回收。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")

    with patched_module_manager(module_manager):
        register_extensions(manager, module_manager)
        assert len(module_manager.get_external_module_ids()) == len(OWNER_KEYS)
        assert len(get_registered_storages()) == len(OWNER_KEYS)
        assert len(ChannelCapabilityManager.get_registered_owners()) == len(OWNER_KEYS)
        run_uninstall(manager)

    assert module_manager.get_external_module_ids() == []
    assert get_registered_storages() == []
    assert ChannelCapabilityManager.get_registered_owners() == {}


def test_uninstalling_removes_the_routes_of_every_instance(manager):
    """卸载插件后各实例的接口路由全部摘除，其它插件的路由保持原样。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")
    prefix = plugin_endpoint.PLUGIN_PREFIX
    other = f"{prefix}/OtherPlugin/state"
    app_stub = fake_app(
        f"{prefix}/{PLUGIN_ID}/state",
        f"{prefix}/{ALPHA_KEY}/state",
        f"{prefix}/{BETA_KEY}/state",
        other,
    )

    run_uninstall(manager, app_stub=app_stub)

    assert [route.path for route in app_stub.routes] == [other]


def test_uninstalling_takes_down_the_jobs_of_every_instance(manager):
    """卸载插件后各实例注册的定时任务全部摘除，其它插件的任务保持原样。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")
    scheduler = object.__new__(Scheduler)
    scheduler._lock = threading.RLock()
    scheduler._scheduler = MagicMock()
    scheduler._scheduler.get_jobs.return_value = []
    scheduler._jobs = {
        f"{key}_sync": {"pid": key, "name": "同步任务"} for key in OWNER_KEYS
    }
    scheduler._jobs["OtherPlugin_sync"] = {"pid": "OtherPlugin", "name": "别家任务"}

    run_uninstall(manager, scheduler=scheduler)

    assert list(scheduler._jobs) == ["OtherPlugin_sync"]


def test_uninstalling_keeps_the_config_and_data_of_every_instance(manager):
    """卸载插件保留全部实例的配置与数据，含分身的实例定义行。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")
    seed_configs()
    seed_data()

    run_uninstall(manager)

    assert instance_ids() == ["alpha", "beta", DEFAULT_INSTANCE_ID]
    assert stored_data("alpha") == {"v": "alpha"}
    assert stored_data("beta") == {"v": "beta"}
    assert stored_data(DEFAULT_INSTANCE_ID) == {"v": "default"}


def test_reinstalling_restores_every_instance(manager):
    """卸载后重新加载，各实例带着原有配置回到运行态。"""
    running(manager, DEFAULT_INSTANCE_ID, "alpha", "beta")
    seed_configs()

    run_uninstall(manager)
    running(manager, *[record.instance_id for record in PluginConfigOper().list_instances(PLUGIN_ID)])

    assert sorted(manager.running_plugins) == [PLUGIN_ID, ALPHA_KEY, BETA_KEY]
    assert manager.get_plugin_config(PLUGIN_ID, "alpha") == {"enable": True, "token": "alpha"}
