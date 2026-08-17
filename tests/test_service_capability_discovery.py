"""ServiceBaseHelper 按能力发现服务的行为测试。

分发层已经不看 get_type() 返回的单一身份，服务发现改按族标志能力查表；这里锁定
三条边界：单方法族命中 providers_for、OR 组族按方法去重合并、未声明标志能力的族
回退到原按身份路径。最后一条用真实 ModuleManager 验证判据没有偏离——不管当前哪些
模块在跑，标志能力选出的模块集合必须与按 get_type() 圈出的族完全一致。
"""

from typing import Dict, Tuple
from unittest.mock import Mock

from app.runtime.extensions.module_manager import ModuleManager
from app.runtime.extensions.service_registry import ServiceBaseHelper, _FAMILY_CAPABILITIES
from app.schemas.types import ModuleType, SystemConfigKey


class _FakeModuleManager:
    """替身：记录调用轨迹，验证 _discover_modules 走了哪条路径。"""

    def __init__(self, providers: Dict[str, Tuple] = None, by_type: Dict[ModuleType, Tuple] = None):
        self._providers = providers or {}
        self._by_type = by_type or {}
        self.providers_for_calls = []
        self.get_running_type_modules_calls = []

    def providers_for(self, method):
        self.providers_for_calls.append(method)
        return self._providers.get(method, ())

    def get_running_type_modules(self, module_type):
        self.get_running_type_modules_calls.append(module_type)
        return iter(self._by_type.get(module_type, ()))


def _helper(module_type: ModuleType, manager) -> ServiceBaseHelper:
    """绕过 __init__（避免构造真实 ModuleManager 单例），直接装配待测实例。"""
    helper = ServiceBaseHelper.__new__(ServiceBaseHelper)
    helper.modulemanager = manager
    helper.config_key = SystemConfigKey.Downloaders
    helper.conf_type = object
    helper.module_type = module_type
    return helper


def test_single_capability_family_uses_providers_for():
    module = Mock(name="qbittorrent")
    manager = _FakeModuleManager(providers={"list_torrents": (module,)})
    helper = _helper(ModuleType.Downloader, manager)

    discovered = list(helper._discover_modules())

    assert discovered == [module]
    assert manager.providers_for_calls == ["list_torrents"]
    assert manager.get_running_type_modules_calls == []


def test_media_recognize_or_group_dedupes_shared_provider():
    # shared 同时提供 recognize_media 与 media_detail，只应出现一次；
    # only_detail 只提供 media_detail，仍必须被发现到。
    shared = Mock(name="TheMovieDb")
    only_detail = Mock(name="TheTVDb")
    manager = _FakeModuleManager(providers={
        "recognize_media": (shared,),
        "media_detail": (shared, only_detail),
    })
    helper = _helper(ModuleType.MediaRecognize, manager)

    discovered = list(helper._discover_modules())

    assert discovered == [shared, only_detail]
    assert manager.providers_for_calls == ["recognize_media", "media_detail"]


def test_unmapped_family_falls_back_to_running_type_modules():
    module = Mock(name="filemanager")
    manager = _FakeModuleManager(by_type={ModuleType.Other: (module,)})
    helper = _helper(ModuleType.Other, manager)

    discovered = list(helper._discover_modules())

    assert discovered == [module]
    assert manager.get_running_type_modules_calls == [ModuleType.Other]
    assert manager.providers_for_calls == []


def test_family_capability_table_matches_real_module_membership():
    """回归判据：标志能力选出的模块集合必须等于按 get_type() 圈出的族，不论当前运行态如何。"""
    manager = ModuleManager()
    for module_type, methods in _FAMILY_CAPABILITIES.items():
        by_identity = set(manager.get_running_type_modules(module_type))
        by_capability = set()
        for method in methods:
            by_capability.update(manager.providers_for(method))
        assert by_capability == by_identity, f"{module_type} 的标志能力判据与身份圈定的模块集合不一致"
