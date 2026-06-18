"""S6 DI #2：ChainBase 的 8 个公共依赖经 keyword-only 参数可注入，默认回退全局单例。

这是 S6（去服务定位器 / 依赖注入）从「单 consumer 试点」(#1 DownloadChain) 升级到
**所有 chain 的基类**——ChainBase.__init__ 构造的 modulemanager/eventmanager/messageoper/
messagehelper/messagequeue/pluginmanager/filecache/async_filecache 八个全局单例，现可整体注入。

价值：测试可注入 fake 依赖、且不构造任何真实全局单例（ModuleManager/EventManager/
PluginManager 等），无需 mock.patch 一长串导入点；现有 SomeChain() 无参调用点、子类
super().__init__()、市场插件（p115 的 PluginChian(ChainBase)）取全局单例、行为不变。
"""
import inspect
import unittest
from unittest.mock import Mock

from app.chain import ChainBase


# ChainBase 无 @abstractmethod，可裸子类化用于测试
class _StubChain(ChainBase):
    pass


_DEPS = (
    "modulemanager",
    "eventmanager",
    "messageoper",
    "messagehelper",
    "messagequeue",
    "pluginmanager",
    "filecache",
    "async_filecache",
)


class ChainBaseDependencyInjectionTest(unittest.TestCase):
    def test_all_deps_injectable_via_keyword(self):
        """注入全部 8 个 fake → 原样落到实例属性，且不构造任何真实全局单例。"""
        fakes = {name: Mock(name=name) for name in _DEPS}
        chain = _StubChain(**fakes)
        for name in _DEPS:
            self.assertIs(fakes[name], getattr(chain, name))

    def test_init_params_keyword_only_with_none_default(self):
        """8 个依赖参数均为 keyword-only 且默认 None（不传 = 回退全局单例）。"""
        sig = inspect.signature(ChainBase.__init__)
        for name in _DEPS:
            self.assertIn(name, sig.parameters)
            param = sig.parameters[name]
            self.assertIsNone(param.default, f"{name} 默认值应为 None")
            self.assertEqual(
                inspect.Parameter.KEYWORD_ONLY,
                param.kind,
                f"{name} 应为 keyword-only",
            )

    def test_partial_injection_keeps_other_deps_defaulting(self):
        """只注入部分依赖：被注入的用 fake，其余仍回退全局单例（不报错、属性就位）。"""
        em = Mock(name="eventmanager")
        # 仅注入 eventmanager；其余走默认（构造真实全局单例，验证编排不破）
        chain = _StubChain(eventmanager=em)
        self.assertIs(em, chain.eventmanager)
        # 其余依赖仍被赋值（非 None）
        for name in _DEPS:
            self.assertIsNotNone(getattr(chain, name))


if __name__ == "__main__":
    unittest.main()
