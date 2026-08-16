"""chain 按子类型精确分发。

``run_module`` 按方法名广播，对「依次试」「全都要」的模块家族是正确语义；但存储、下载器
这类家族必须精确选中一个后端，一次删除不能打到所有后端上。精确分发是与广播并列的第二条
路径，不改变广播语义。

精确分发只面向注册到模块管理器的模块。``get_module()`` 注入式旁路按方法名抢跑、无子类型
可言，不参与该路径。
"""
import sys
import unittest
from types import ModuleType as _PyModuleType
from unittest.mock import Mock, patch

sys.modules.setdefault("qbittorrentapi", _PyModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", _PyModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)

from app.chain import ChainBase  # noqa: E402
from app.schemas import RateLimitExceededException  # noqa: E402
from app.schemas.types import StorageSchema  # noqa: E402


class StorageLikeModule:
    """声明存储子类型的模块替身"""

    def __init__(self, subtype, priority: int = 1):
        """
        :param subtype: 模块声明的子类型
        :param priority: 模块优先级
        """
        self._subtype = subtype
        self._priority = priority
        self.calls = []

    def get_name(self) -> str:
        """模块名称"""
        return f"存储模块 {self._subtype}"

    def get_subtype(self):
        """模块子类型"""
        return self._subtype

    def get_priority(self) -> int:
        """模块优先级"""
        return self._priority

    def delete_file(self, fileitem=None, **kwargs) -> str:
        """删除文件"""
        self.calls.append(fileitem)
        return f"deleted:{self._subtype}"


class FailingModule(StorageLikeModule):
    """执行时抛错的模块替身"""

    def delete_file(self, fileitem=None, **kwargs):
        """删除文件"""
        raise RuntimeError("后端不可用")


class RateLimitedModule(StorageLikeModule):
    """执行时命中本地限流的模块替身"""

    def delete_file(self, fileitem=None, **kwargs):
        """删除文件"""
        raise RateLimitExceededException("[delete_file] 限流期间，跳过调用")


class NoMethodModule(StorageLikeModule):
    """未实现目标方法的模块替身"""

    delete_file = None


class ChainSubtypeDispatchTest(unittest.TestCase):
    """精确分发的行为契约"""

    @staticmethod
    def build_chain(*modules) -> ChainBase:
        """
        构造与真实模块、插件运行态隔离的 ChainBase

        :param modules: 运行态模块替身
        :return: 链基类实例
        """
        chain = ChainBase()
        chain.pluginmanager = Mock()
        chain.pluginmanager.running_plugins = {}
        chain.modulemanager = Mock()
        chain.modulemanager.get_running_subtype_module.side_effect = \
            lambda subtype: iter([m for m in modules if m.get_subtype() == subtype])
        chain.messagehelper = Mock()
        chain.eventmanager = Mock()
        return chain

    def test_only_the_matching_module_runs(self):
        """精确命中目标子类型的模块并返回其结果。"""
        local = StorageLikeModule(StorageSchema.Local)
        chain = self.build_chain(local)

        result = chain.run_module_for(StorageSchema.Local, "delete_file", fileitem="a.mkv")

        self.assertEqual(f"deleted:{StorageSchema.Local}", result)
        self.assertEqual(["a.mkv"], local.calls)

    def test_sibling_backends_are_not_touched(self):
        """同方法名的其余后端一个都不被调用，避免一次删除打到所有存储。"""
        local = StorageLikeModule(StorageSchema.Local)
        alipan = StorageLikeModule(StorageSchema.Alipan)
        u115 = StorageLikeModule(StorageSchema.U115)
        chain = self.build_chain(local, alipan, u115)

        chain.run_module_for(StorageSchema.Alipan, "delete_file", fileitem="a.mkv")

        self.assertEqual([], local.calls)
        self.assertEqual([], u115.calls)
        self.assertEqual(["a.mkv"], alipan.calls)

    def test_no_match_returns_none_without_falling_back_to_broadcast(self):
        """无匹配模块时返回 None，不回落到广播。"""
        local = StorageLikeModule(StorageSchema.Local)
        chain = self.build_chain(local)

        result = chain.run_module_for(StorageSchema.Alipan, "delete_file", fileitem="a.mkv")

        self.assertIsNone(result)
        self.assertEqual([], local.calls)

    def test_a_module_without_the_method_returns_none(self):
        """命中的模块未实现该方法时返回 None。"""
        chain = self.build_chain(NoMethodModule(StorageSchema.Local))

        self.assertIsNone(chain.run_module_for(StorageSchema.Local, "delete_file"))

    def test_the_highest_priority_module_wins_when_several_match(self):
        """同一子类型有多个模块时按优先级取一个，不重复执行。"""
        low = StorageLikeModule(StorageSchema.Local, priority=9)
        high = StorageLikeModule(StorageSchema.Local, priority=1)
        chain = self.build_chain(low, high)

        chain.run_module_for(StorageSchema.Local, "delete_file", fileitem="a.mkv")

        self.assertEqual(["a.mkv"], high.calls)
        self.assertEqual([], low.calls)

    def test_a_failing_module_is_reported_and_returns_none(self):
        """模块抛错时按系统模块错误处理，返回 None。"""
        chain = self.build_chain(FailingModule(StorageSchema.Local))

        result = chain.run_module_for(StorageSchema.Local, "delete_file", fileitem="a.mkv")

        self.assertIsNone(result)
        chain.messagehelper.put.assert_called_once()

    def test_a_failing_module_raises_when_asked_to(self):
        """要求抛出异常时原样抛出。"""
        chain = self.build_chain(FailingModule(StorageSchema.Local))

        with self.assertRaises(RuntimeError):
            chain.run_module_for(StorageSchema.Local, "delete_file", raise_exception=True)

    def test_rate_limiting_is_skipped_without_an_error_report(self):
        """命中本地限流时跳过执行，不产生系统错误告警。"""
        chain = self.build_chain(RateLimitedModule(StorageSchema.Local))

        result = chain.run_module_for(StorageSchema.Local, "delete_file")

        self.assertIsNone(result)
        chain.messagehelper.put.assert_not_called()

    def test_injected_plugin_methods_do_not_participate(self):
        """get_module() 注入式旁路不参与精确分发。"""
        injected = Mock(return_value="hijacked")
        local = StorageLikeModule(StorageSchema.Local)
        chain = self.build_chain(local)

        with patch("app.chain.get_plugin_modules",
                   return_value={("Hijacker", "劫持插件"): {"delete_file": injected}}):
            result = chain.run_module_for(StorageSchema.Local, "delete_file", fileitem="a.mkv")

        injected.assert_not_called()
        self.assertEqual(["a.mkv"], local.calls)
        self.assertNotEqual("hijacked", result)

    def test_a_string_subtype_reaches_an_externally_registered_module(self):
        """以字符串声明子类型的外部模块可被字符串精确命中。"""
        external = StorageLikeModule("plugin_cloud")
        chain = self.build_chain(external)

        result = chain.run_module_for("plugin_cloud", "delete_file", fileitem="a.mkv")

        self.assertEqual("deleted:plugin_cloud", result)


if __name__ == "__main__":
    unittest.main()
