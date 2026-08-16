"""外部来源注册系统模块的行为门禁。

宿主模块由 manifest 静态声明，插件模块在运行期交出类对象。两者经同一个 Runtime 调度，
因此注册、上线、按来源卸载与各项拒绝理由都要在这里锁死。
"""
from types import SimpleNamespace
from typing import Iterator, Optional, Tuple, Union

import pytest

from app.foundation.singleton import Singleton
from app.runtime.capabilities.registry import CapabilityRegistry
from app.runtime.events import eventmanager
from app.runtime.extensions import module_manager as module_manager_extension
from app.runtime.extensions.host_module_adapter import (
    HOST_MODULE_KIND,
    HOST_MODULE_SELECTOR_SCHEMAS,
)
from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.plugin_module_adapter import ProvidedModule
from app.schemas.types import MediaServerType, ModuleType


class _BaseFixtureModule:
    """满足模块契约的最小实现，供注册路径使用。"""

    started = 0
    stopped = 0

    def init_module(self) -> None:
        type(self).started += 1

    def init_setting(self) -> Optional[Tuple[str, Union[str, bool]]]:
        return None

    def stop(self) -> None:
        type(self).stopped += 1

    def test(self) -> Tuple[bool, str]:
        return True, ""

    @staticmethod
    def get_name() -> str:
        return "Fixture"

    @staticmethod
    def get_type() -> ModuleType:
        return ModuleType.MediaServer

    @staticmethod
    def get_subtype() -> MediaServerType:
        return MediaServerType.Emby

    @staticmethod
    def get_priority() -> int:
        return 0


class FixtureModule(_BaseFixtureModule):
    """默认注册使用的模块。"""


class OtherFixtureModule(_BaseFixtureModule):
    """与 FixtureModule 同子类型，用于验证子类型占用。"""

    @staticmethod
    def get_name() -> str:
        return "OtherFixture"


class ThirdFixtureModule(_BaseFixtureModule):
    """子类型与 FixtureModule 不同，用于验证同插件多实例的标识限定。"""

    @staticmethod
    def get_name() -> str:
        return "ThirdFixture"

    @staticmethod
    def get_subtype() -> MediaServerType:
        return MediaServerType.Jellyfin


class IndexerLikeModule(_BaseFixtureModule):
    """声明了内建独占能力的模块。"""

    @staticmethod
    def get_subtype() -> MediaServerType:
        return MediaServerType.Plex

    def search_torrents(self, *args, **kwargs) -> list:
        return []


class BrokenModule:
    """缺少契约方法的类。"""

    def init_module(self) -> None:
        pass


@pytest.fixture
def manager() -> Iterator[ModuleManager]:
    """用空宿主清单隔离 ModuleManager 单例，只保留运行期注册路径。"""
    empty_registry = CapabilityRegistry(
        {},
        kinds={HOST_MODULE_KIND},
        selector_schemas=HOST_MODULE_SELECTOR_SCHEMAS,
    )
    original_builder = module_manager_extension.build_host_module_registry
    module_manager_extension.build_host_module_registry = lambda: empty_registry

    singleton_key = (ModuleManager, (), frozenset())
    previous = Singleton._instances.pop(singleton_key, None)
    resolver_attr = "_EventManager__handler_instance_resolvers"
    previous_resolvers = dict(getattr(eventmanager, resolver_attr))

    for module_cls in (FixtureModule, OtherFixtureModule, ThirdFixtureModule, IndexerLikeModule):
        module_cls.started = 0
        module_cls.stopped = 0

    instance = ModuleManager()
    try:
        yield instance
    finally:
        try:
            instance.shutdown()
        except Exception:
            pass
        module_manager_extension.build_host_module_registry = original_builder
        setattr(eventmanager, resolver_attr, previous_resolvers)
        Singleton._instances.pop(singleton_key, None)
        if previous is not None:
            Singleton._instances[singleton_key] = previous


def test_registered_module_comes_online(manager: ModuleManager) -> None:
    # Arrange / Act
    accepted = manager.register_module(FixtureModule, owner="pluginA")

    # Assert
    assert accepted is True
    assert manager.get_running_module("FixtureModule") is not None
    assert FixtureModule.started == 1
    assert "FixtureModule" in manager.get_module_ids()
    assert manager.get_external_module_ids("pluginA") == ["FixtureModule"]


def test_registered_module_participates_in_dispatch(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    by_method = [module.__class__.__name__ for module in manager.get_running_modules("test")]
    by_type = [module.__class__.__name__
               for module in manager.get_running_type_modules(ModuleType.MediaServer)]

    # Assert
    assert "FixtureModule" in by_method
    assert "FixtureModule" in by_type


def test_unregister_stops_and_removes_by_owner(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    removed = manager.unregister_modules("pluginA")

    # Assert
    assert removed == ["FixtureModule"]
    assert FixtureModule.stopped == 1
    assert manager.get_running_module("FixtureModule") is None
    assert "FixtureModule" not in manager.get_module_ids()
    assert manager.get_external_module_ids("pluginA") == []


def test_contract_violation_is_rejected(manager: ModuleManager) -> None:
    # Arrange / Act
    accepted = manager.register_module(BrokenModule, owner="pluginA")

    # Assert
    assert accepted is False
    assert manager.get_running_module("BrokenModule") is None


def test_builtin_only_capability_is_rejected(manager: ModuleManager) -> None:
    # Arrange / Act
    accepted = manager.register_module(IndexerLikeModule, owner="pluginA")

    # Assert
    assert accepted is False
    assert manager.get_running_module("IndexerLikeModule") is None


def test_type_mismatch_is_rejected(manager: ModuleManager) -> None:
    # Arrange
    declaration = ProvidedModule(FixtureModule, expected_type=ModuleType.Downloader)

    # Act
    accepted = manager.register_module(declaration, owner="pluginA")

    # Assert
    assert accepted is False
    assert manager.get_running_module("FixtureModule") is None


def test_subtype_taken_by_another_module_is_rejected(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    accepted = manager.register_module(OtherFixtureModule, owner="pluginB")

    # Assert
    assert accepted is False
    assert manager.get_running_module("OtherFixtureModule") is None


def test_same_module_id_from_another_owner_is_rejected(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    accepted = manager.register_module(FixtureModule, owner="pluginB")

    # Assert
    assert accepted is False
    assert manager.get_external_module_ids("pluginB") == []


def test_instances_of_one_plugin_qualify_module_ids(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    accepted = manager.register_module(ThirdFixtureModule, owner="pluginA@second")

    # Assert
    assert accepted is True
    assert manager.get_external_module_ids("pluginA") == ["FixtureModule"]
    assert manager.get_external_module_ids("pluginA@second") == ["ThirdFixtureModule@pluginA@second"]
    assert manager.get_running_module("ThirdFixtureModule@pluginA@second") is not None


def test_same_subtype_from_another_instance_is_rejected(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    accepted = manager.register_module(FixtureModule, owner="pluginA@second")

    # Assert
    assert accepted is False
    assert manager.get_external_module_ids("pluginA@second") == []


def test_reload_brings_registered_modules_back(manager: ModuleManager) -> None:
    # Arrange
    manager.register_module(FixtureModule, owner="pluginA")

    # Act
    manager.stop()
    manager.load_modules()

    # Assert
    assert manager.get_running_module("FixtureModule") is not None
    assert manager.get_external_module_ids("pluginA") == ["FixtureModule"]
