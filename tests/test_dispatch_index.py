"""分发注册表：按族类与能力查表。

三级分发里，广播与多播/单播的复杂度代价来源不同：

- 广播是「通知，不求答案」，语义上必须触达全体，O(n) 是它的固有代价，不做优化
- 多播是「圈定一类，收集所有答案」，单播是「最终只要一个答案」，两者都是**查询**，
  本该只付出 O(k)——k 为该族类下真正提供该能力的模块数

过去业务能力查询借广播实现（方法名 + hasattr 扫全体），把 O(k) 的查询摊成了 O(n) 的
遍历。注册表把 (族类, 能力) 映射到已排序的提供者元组，查询命中后为 O(1)，只有运行态
模块集合变化时才重建。
"""
import threading
import unittest

from app.runtime.extensions.module_manager import ModuleManager
from app.schemas.types import ModuleType


class FakeModule:
    """声明族类与能力的模块替身"""

    def __init__(self, name: str, module_type, capabilities, priority: int = 1):
        """
        :param name: 模块名
        :param module_type: 所属族类
        :param capabilities: 该模块提供的能力方法名
        :param priority: 模块优先级
        """
        self._name = name
        self._type = module_type
        self._priority = priority
        for capability in capabilities:
            setattr(self, capability, self._make_capability(capability))

    def _make_capability(self, capability: str):
        """构造一个已实现的能力方法"""
        def implementation(*args, **kwargs):
            """能力实现"""
            return f"{self._name}:{capability}"
        return implementation

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_type(self):
        """模块族类"""
        return self._type

    def get_priority(self) -> int:
        """模块优先级"""
        return self._priority


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
    """按族类与能力查表的注册表契约"""

    def test_a_lookup_returns_only_providers_of_that_family_and_capability(self):
        """只返回该族类下真正提供该能力的模块。"""
        emby = FakeModule("emby", ModuleType.MediaServer, ["media_statistic"])
        plex = FakeModule("plex", ModuleType.MediaServer, ["media_statistic"])
        no_capability = FakeModule("legacy", ModuleType.MediaServer, [])
        other_family = FakeModule("qb", ModuleType.Downloader, ["media_statistic"])
        manager, _ = build_manager(emby, plex, no_capability, other_family)

        providers = manager.providers_for(ModuleType.MediaServer, "media_statistic")

        self.assertEqual((emby, plex), providers)

    def test_a_repeated_lookup_does_not_rescan_running_modules(self):
        """重复查询直接命中注册表，不再扫描运行态模块。"""
        manager, scans = build_manager(
            FakeModule("emby", ModuleType.MediaServer, ["media_statistic"]),
        )
        manager.providers_for(ModuleType.MediaServer, "media_statistic")
        scans_after_first = scans["count"]

        for _ in range(5):
            manager.providers_for(ModuleType.MediaServer, "media_statistic")

        self.assertEqual(scans_after_first, scans["count"])

    def test_providers_are_ordered_by_priority_for_arbitration(self):
        """提供者按优先级排序，供单播直接取第一个仲裁。"""
        low = FakeModule("low", ModuleType.MediaServer, ["media_statistic"], priority=9)
        high = FakeModule("high", ModuleType.MediaServer, ["media_statistic"], priority=1)
        manager, _ = build_manager(low, high)

        providers = manager.providers_for(ModuleType.MediaServer, "media_statistic")

        self.assertEqual((high, low), providers)

    def test_distinct_capabilities_are_indexed_separately(self):
        """同族类不同能力各自成表，互不串味。"""
        emby = FakeModule("emby", ModuleType.MediaServer, ["media_statistic", "playing"])
        plex = FakeModule("plex", ModuleType.MediaServer, ["media_statistic"])
        manager, _ = build_manager(emby, plex)

        self.assertEqual(
            (emby, plex),
            manager.providers_for(ModuleType.MediaServer, "media_statistic"),
        )
        self.assertEqual(
            (emby,),
            manager.providers_for(ModuleType.MediaServer, "playing"),
        )

    def test_an_empty_family_yields_no_providers(self):
        """族类下无提供者时返回空元组，且该结论同样进表。"""
        manager, scans = build_manager(
            FakeModule("qb", ModuleType.Downloader, ["media_statistic"]),
        )

        self.assertEqual(
            (),
            manager.providers_for(ModuleType.MediaServer, "media_statistic"),
        )
        scans_after_first = scans["count"]
        self.assertEqual(
            (),
            manager.providers_for(ModuleType.MediaServer, "media_statistic"),
        )
        self.assertEqual(scans_after_first, scans["count"])

    def test_the_index_is_dropped_when_the_running_set_changes(self):
        """运行态模块集合变化后注册表失效，下次查询重新求值。"""
        emby = FakeModule("emby", ModuleType.MediaServer, ["media_statistic"])
        manager, scans = build_manager(emby)
        manager.providers_for(ModuleType.MediaServer, "media_statistic")
        scans_after_first = scans["count"]

        manager.invalidate_dispatch_index()
        manager.providers_for(ModuleType.MediaServer, "media_statistic")

        self.assertEqual(scans_after_first + 1, scans["count"])


if __name__ == "__main__":
    unittest.main()
