"""能力注册表的只读诊断接口。

`ModuleManager.providers_for(method)` 只回答「谁能处理这个方法」，排查分发问题时
更常问的是反过来的两个问题：这个系统里有哪些能力、分别由谁提供？某个模块自己
提供了哪些能力？这两个问题目前没有对外接口，只能翻源码。

`get_module_capabilities` 与 `get_capability_index` 补上这两个只读查询，两者都
直接复用 `capability.provided_capabilities`——「什么算能力」全库只有一处定义，
这里不重新判定。
"""
import threading
import unittest
from unittest import mock

from app.runtime.extensions import module_manager as module_manager_mod
from app.runtime.extensions.module_manager import ModuleManager


class _Widget:
    """只提供一种能力的桩模块。"""

    def get_priority(self) -> int:
        return 0

    def widget_capability(self) -> str:
        return "widget"


class _Gadget:
    """提供两种能力的桩模块，其中一种与 `_Widget` 重名，用于验证倒排索引的合并。"""

    def get_priority(self) -> int:
        return 0

    def widget_capability(self) -> str:
        return "gadget-widget"

    def gadget_only_capability(self) -> str:
        return "gadget"


def _build_registry(running: dict) -> ModuleManager:
    """
    构造只持有给定运行态模块字典的管理器，不触发真实 Runtime 初始化

    :param running: {模块标识: 运行态模块实例}
    :return: 裸构造的模块管理器
    """
    manager = object.__new__(ModuleManager)
    manager._lock = threading.RLock()
    manager._running_modules = dict(running)
    return manager


class GetModuleCapabilitiesTest(unittest.TestCase):
    """单个模块的能力列表"""

    def test_returns_the_capabilities_of_a_running_module(self):
        """运行态模块的能力列表按能力方法名返回。"""
        manager = _build_registry({"widget-1": _Widget()})

        self.assertEqual(["widget_capability"], manager.get_module_capabilities("widget-1"))

    def test_result_is_sorted(self):
        """多个能力时按名称排序，不依赖推导顺序。"""
        manager = _build_registry({"gadget-1": _Gadget()})

        self.assertEqual(
            ["gadget_only_capability", "widget_capability"],
            manager.get_module_capabilities("gadget-1"),
        )

    def test_returns_empty_list_when_module_is_not_running(self):
        """模块标识未出现在运行态集合中时返回空列表，而非抛异常。"""
        manager = _build_registry({"widget-1": _Widget()})

        self.assertEqual([], manager.get_module_capabilities("not-running"))

    def test_returns_empty_list_when_nothing_is_running(self):
        """运行态集合为空时同样返回空列表。"""
        manager = _build_registry({})

        self.assertEqual([], manager.get_module_capabilities("anything"))


class GetCapabilityIndexTest(unittest.TestCase):
    """能力到提供者的倒排索引"""

    def test_maps_each_capability_to_its_providers(self):
        """同一能力的多个提供者都出现在同一个键下。"""
        manager = _build_registry({
            "widget-1": _Widget(),
            "widget-2": _Widget(),
            "gadget-1": _Gadget(),
        })

        index = manager.get_capability_index()

        self.assertEqual(
            ["gadget-1", "widget-1", "widget-2"],
            index["widget_capability"],
        )
        self.assertEqual(["gadget-1"], index["gadget_only_capability"])

    def test_keys_and_values_are_sorted(self):
        """键与值都排序稳定，不依赖字典的插入或推导顺序。"""
        manager = _build_registry({
            "widget-2": _Widget(),
            "widget-1": _Widget(),
            "gadget-1": _Gadget(),
        })

        index = manager.get_capability_index()

        self.assertEqual(sorted(index.keys()), list(index.keys()))
        for owners in index.values():
            self.assertEqual(sorted(owners), owners)

    def test_empty_when_nothing_is_running(self):
        """没有运行态模块时返回空字典。"""
        manager = _build_registry({})

        self.assertEqual({}, manager.get_capability_index())

    def test_a_single_module_derivation_error_does_not_abort_the_whole_index(self):
        """一个模块推导能力出错时记 debug 日志并跳过，其它模块的能力照常收录。"""
        healthy = _Widget()
        broken = _Gadget()
        manager = _build_registry({"healthy-1": healthy, "broken-1": broken})
        real_provided_capabilities = module_manager_mod.provided_capabilities

        def _flaky(module):
            if module is broken:
                raise RuntimeError("boom")
            return real_provided_capabilities(module)

        with mock.patch.object(
            module_manager_mod, "provided_capabilities", side_effect=_flaky,
        ):
            index = manager.get_capability_index()

        self.assertEqual(["healthy-1"], index["widget_capability"])
        self.assertNotIn("gadget_only_capability", index)


if __name__ == "__main__":
    unittest.main()
