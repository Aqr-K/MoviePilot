"""分发注册表：按能力查表。

三级分发里，广播与多播/单播的复杂度代价来源不同：

- 广播是「通知，不求答案」，语义上必须触达全体，O(n) 是它的固有代价，不做优化
- 多播是「圈定一类，收集所有答案」，单播是「最终只要一个答案」，两者都是**查询**，
  本该只付出 O(k)——k 为真正提供该能力的模块数

索引的键是**能力**而不是模块身份。get_type() 只有一个取值，它回答「你是什么」；而
能力回答「你能做什么」。一个模块只有一个身份，却可以提供多种能力：媒体服务器同时
兼任认证登录，而 ModuleType 里根本没有认证这一族。用身份当键，跨族能力就无处安放。

能力也不能由标签声明，只能从运行期实例推导——方法可以继承自基类（user_authenticate
就定义在媒体服务器基类上），只看类体会把它看成什么都没实现。
"""
import threading
import unittest

from app.runtime.extensions.module_manager import ModuleManager
from app.schemas.types import ModuleType


class _ModuleStub:
    """模块替身基座，能力声明在类上——与生产模块一致，也是能力推导的前提"""

    def __init__(self, name: str, module_type=None, priority: int = 1):
        """
        :param name: 模块名
        :param module_type: 模块身份
        :param priority: 模块优先级
        """
        self._name = name
        self._type = module_type
        self._priority = priority

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_type(self):
        """模块身份"""
        return self._type

    def get_priority(self) -> int:
        """模块优先级"""
        return self._priority


def FakeModule(name: str, module_type, capabilities, priority: int = 1):
    """
    构造在类上声明指定能力的模块替身

    :param name: 模块名
    :param module_type: 模块身份
    :param capabilities: 该模块提供的能力方法名
    :param priority: 模块优先级
    :return: 模块替身实例
    """
    namespace = {}
    for capability in capabilities:
        def implementation(self, *args, _capability=capability, **kwargs):
            """能力实现"""
            return f"{self._name}:{_capability}"
        namespace[capability] = implementation
    stub_cls = type(f"Stub_{name}", (_ModuleStub,), namespace)
    return stub_cls(name, module_type, priority)


class AuthCapableModule(_ModuleStub):
    """兼任认证的模块替身，认证能力定义在本类上"""

    def __init__(self, name: str, module_type, capabilities=(), priority: int = 1):
        """
        :param name: 模块名
        :param module_type: 模块身份
        :param capabilities: 兼容位，认证能力已在类上声明
        :param priority: 模块优先级
        """
        super().__init__(name, module_type, priority)

    def user_authenticate(self, **kwargs):
        """认证能力"""
        return f"{self._name}:user_authenticate"


class DerivedModule(AuthCapableModule):
    """自身类体不含认证能力，仅从基类继承"""


def build_manager(*modules):
    """
    构造只认给定模块、并记录扫描次数的 ModuleManager

    :param modules: 运行态模块替身
    :return: (管理器, 扫描计数器)
    """
    manager = object.__new__(ModuleManager)
    manager._lock = threading.RLock()
    manager._running_modules = {m.get_name(): m for m in modules}
    manager._dispatch_index = {}
    scans = {"count": 0}

    def counting_snapshot():
        """替换真实快照，统计扫描次数"""
        scans["count"] += 1
        return tuple(modules)

    manager._running_snapshot = counting_snapshot
    return manager, scans


class DispatchIndexTest(unittest.TestCase):
    """按能力查表的注册表契约"""

    def test_a_lookup_returns_every_provider_of_that_capability(self):
        """返回所有提供该能力的模块，不论它们的身份是什么。"""
        emby = FakeModule("emby", ModuleType.MediaServer, ["media_statistic"])
        plex = FakeModule("plex", ModuleType.MediaServer, ["media_statistic"])
        no_capability = FakeModule("legacy", ModuleType.MediaServer, [])
        manager, _ = build_manager(emby, plex, no_capability)

        providers = manager.providers_for("media_statistic")

        self.assertEqual((emby, plex), providers)

    def test_a_capability_crossing_families_is_still_found(self):
        """跨族能力照样被找到：认证由媒体服务器兼任，而认证不是一个 ModuleType。"""
        plex = AuthCapableModule("plex", ModuleType.MediaServer, [])
        ldap_plugin = AuthCapableModule("ldap", ModuleType.Other, [])
        unrelated = FakeModule("qb", ModuleType.Downloader, ["download"])
        manager, _ = build_manager(plex, ldap_plugin, unrelated)

        providers = manager.providers_for("user_authenticate")

        self.assertEqual((plex, ldap_plugin), providers)

    def test_a_capability_inherited_from_a_base_class_counts(self):
        """能力继承自基类时同样算提供者，不能只看类体。"""
        derived = DerivedModule("navidrome", ModuleType.MediaServer, [])
        manager, _ = build_manager(derived)

        self.assertEqual((derived,), manager.providers_for("user_authenticate"))

    def test_a_repeated_lookup_does_not_rescan_running_modules(self):
        """重复查询直接命中注册表，不再扫描运行态模块。"""
        manager, scans = build_manager(
            FakeModule("emby", ModuleType.MediaServer, ["media_statistic"]),
        )
        manager.providers_for("media_statistic")
        scans_after_first = scans["count"]

        for _ in range(5):
            manager.providers_for("media_statistic")

        self.assertEqual(scans_after_first, scans["count"])

    def test_providers_are_ordered_by_priority_for_arbitration(self):
        """提供者按优先级排序，供单播直接取第一个仲裁。"""
        low = FakeModule("low", ModuleType.MediaServer, ["media_statistic"], priority=9)
        high = FakeModule("high", ModuleType.MediaServer, ["media_statistic"], priority=1)
        manager, _ = build_manager(low, high)

        providers = manager.providers_for("media_statistic")

        self.assertEqual((high, low), providers)

    def test_distinct_capabilities_are_indexed_separately(self):
        """不同能力各自成表，互不串味。"""
        emby = FakeModule("emby", ModuleType.MediaServer, ["media_statistic", "playing"])
        plex = FakeModule("plex", ModuleType.MediaServer, ["media_statistic"])
        manager, _ = build_manager(emby, plex)

        self.assertEqual((emby, plex), manager.providers_for("media_statistic"))
        self.assertEqual((emby,), manager.providers_for("playing"))

    def test_an_unprovided_capability_yields_no_providers(self):
        """无人提供该能力时返回空元组，且该结论同样进表。"""
        manager, scans = build_manager(
            FakeModule("qb", ModuleType.Downloader, ["download"]),
        )

        self.assertEqual((), manager.providers_for("media_statistic"))
        scans_after_first = scans["count"]
        self.assertEqual((), manager.providers_for("media_statistic"))
        self.assertEqual(scans_after_first, scans["count"])

    def test_the_index_is_dropped_when_the_running_set_changes(self):
        """运行态模块集合变化后注册表失效，下次查询重新求值。"""
        emby = FakeModule("emby", ModuleType.MediaServer, ["media_statistic"])
        manager, scans = build_manager(emby)
        manager.providers_for("media_statistic")
        scans_after_first = scans["count"]

        manager.invalidate_dispatch_index()
        manager.providers_for("media_statistic")

        self.assertEqual(scans_after_first + 1, scans["count"])


if __name__ == "__main__":
    unittest.main()
