"""S6 DI 试点（首切片）：DownloadChain 经构造注入 ThreadHelper，默认回退全局共享单例。

这是 S6（去服务定位器 / 依赖注入）的模板示范——「构造注入 + 默认回退全局单例」：
  - 不传参（现有 463 处 Chain() 调用点与市场插件）= 取全局单例，行为与内存零变化；
  - 测试可注入同步 fake executor，**无需 mock.patch 全局 ThreadHelper** 即确定性驱动
    原本会起真实线程的后台提交（_submit_download_added_task）。

本测试锁定该注入缝（签名）+ 证明后台提交确实路由经 self._thread_helper（可注入），
作为 S6 推广到其余 Chain/Oper 的行为锁与范式样板。
"""
import inspect
import unittest
from pathlib import Path
from unittest.mock import Mock

from app.chain.download import DownloadChain


class DownloadChainThreadHelperInjectionTest(unittest.TestCase):
    def test_init_exposes_injectable_thread_helper_defaulting_none(self):
        """__init__ 暴露 thread_helper 形参且默认 None（不传 = 回退全局单例）。"""
        sig = inspect.signature(DownloadChain.__init__)
        self.assertIn("thread_helper", sig.parameters)
        self.assertIsNone(sig.parameters["thread_helper"].default)

    def test_background_submit_routes_through_injected_executor(self):
        """后台下载附加处理经 self._thread_helper.submit 提交，可被同步 fake 确定性驱动。"""
        # object.__new__ 绕过 ChainBase.__init__（避免构造 8 个全局单例），仅注入受测依赖
        chain = object.__new__(DownloadChain)
        fake_executor = Mock()
        chain._thread_helper = fake_executor
        added_calls = []
        chain.download_added = lambda **kw: added_calls.append(kw)

        chain._submit_download_added_task(
            context="CTX", download_dir=Path("/d"), torrent_content="T"
        )

        # 提交到注入的执行器（而非全局 ThreadHelper），且仅一次
        fake_executor.submit.assert_called_once()
        submitted = fake_executor.submit.call_args.args[0]
        self.assertTrue(callable(submitted))
        # 执行被提交的闭包 → 原样透传到 download_added
        submitted()
        self.assertEqual(
            [{"context": "CTX", "download_dir": Path("/d"), "torrent_content": "T"}],
            added_calls,
        )

    def test_submit_failure_is_swallowed_and_logged(self):
        """注入的 executor.submit 抛错时被 try/except 吞掉（不冒泡阻塞添加下载响应）。"""
        chain = object.__new__(DownloadChain)
        boom = Mock()
        boom.submit.side_effect = RuntimeError("pool down")
        chain._thread_helper = boom
        chain.download_added = lambda **kw: None

        # 不抛出即通过（原 try/except 行为保持）
        chain._submit_download_added_task(
            context="CTX", download_dir=Path("/d"), torrent_content="T"
        )
        boom.submit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
