# -*- coding: utf-8 -*-
"""
统一分发内核 app.core.dispatch 回归测试。

覆盖：
- is_valid_empty 空值判定；
- 合并规则（空→取值、list→extend、非空标量→短路、系统面 check_signature 管道精化、插件面不精化）；
- 错误隔离（单后端异常被隔离、其余续跑）与回调透传首个异常；
- 限流（RateLimitExceededException 走 on_rate_limit、不进 on_error）；
- kwargs 原样转发（内核对 kwargs 内容无主张）；
- sync 与 async 两版关键路径；
- **唯一真实差异：raise_exception 透传系统后端** —— ChainBase 路径系统后端 func 收到 raise_exception，
  ManagerBase._dispatch 路径系统后端 func 不收到（pop 掉，否则 TypeError）。
"""
import asyncio
import unittest
from unittest.mock import Mock

from app.core import dispatch
from app.chain import ChainBase
from app.managers import DownloaderManager
from app.schemas import RateLimitExceededException


def _noop(*_args, **_kwargs):
    """空回调。"""
    return None


def _reraise(err, *_args, **_kwargs):
    """重抛回调：模拟 raise_exception=True 时错误处理回调透传异常。"""
    raise err


class _RecordingModule:
    """记录每次调用所收 kwargs 的系统后端桩。"""

    def __init__(self, name="rec", priority=1, ret="ok"):
        self._name = name
        self._priority = priority
        self._ret = ret
        self.received = []

    def get_name(self):
        return self._name

    def get_priority(self):
        return self._priority

    def probe(self, *args, **kwargs):
        self.received.append(dict(kwargs))
        return self._ret


class _StrictModule:
    """形参严格（不接受 raise_exception）的系统后端桩，用于验证 pop 的必要性。"""

    def __init__(self, name="strict"):
        self._name = name
        self.calls = 0

    def get_name(self):
        return self._name

    def get_priority(self):
        return 1

    def probe(self):
        self.calls += 1
        return "ok"


# --------------------------------------------------------------------------- #
# is_valid_empty
# --------------------------------------------------------------------------- #
class TestIsValidEmpty(unittest.TestCase):

    def test_none_is_empty(self):
        self.assertTrue(dispatch.is_valid_empty(None))

    def test_all_none_tuple_is_empty(self):
        self.assertTrue(dispatch.is_valid_empty((None, None)))

    def test_partial_none_tuple_is_not_empty(self):
        self.assertFalse(dispatch.is_valid_empty(("got", None)))

    def test_falsy_scalars_are_not_empty(self):
        self.assertFalse(dispatch.is_valid_empty(0))
        self.assertFalse(dispatch.is_valid_empty(False))
        self.assertFalse(dispatch.is_valid_empty([]))
        self.assertFalse(dispatch.is_valid_empty(""))


# --------------------------------------------------------------------------- #
# 合并规则（同步）
# --------------------------------------------------------------------------- #
class TestSyncMergeRules(unittest.TestCase):

    def _run(self, entries, *, pipeline, **kwargs):
        return dispatch.execute_modules(
            entries, "probe", None, pipeline=pipeline,
            on_rate_limit=_noop, on_error=_noop, **kwargs,
        )

    def test_empty_takes_value(self):
        entries = [("a", "A", lambda *a, **k: None), ("b", "B", lambda *a, **k: "val")]
        self.assertEqual(self._run(entries, pipeline=False), "val")

    def test_list_extends_across_backends(self):
        entries = [("a", "A", lambda *a, **k: [1, 2]), ("b", "B", lambda *a, **k: [3])]
        self.assertEqual(self._run(entries, pipeline=False), [1, 2, 3])

    def test_non_empty_scalar_short_circuits(self):
        seen = []

        def second(*a, **k):
            seen.append(True)
            return [9]

        entries = [("a", "A", lambda *a, **k: True), ("b", "B", second)]
        self.assertIs(self._run(entries, pipeline=False), True)
        self.assertEqual(seen, [])  # 短路：第二个后端不被调用

    def test_system_pipeline_refines_result(self):
        def first(*a, **k):
            return "raw"

        def refine(x: str):
            return x + "-refined"

        entries = [("a", "A", first), ("b", "B", refine)]
        self.assertEqual(self._run(entries, pipeline=True), "raw-refined")

    def test_plugin_face_does_not_refine(self):
        def first(*a, **k):
            return "raw"

        def refine(x: str):
            return x + "-refined"

        # pipeline=False：非空标量直接短路，不走 check_signature 精化
        entries = [("a", "A", first), ("b", "B", refine)]
        self.assertEqual(self._run(entries, pipeline=False), "raw")

    def test_log_each_called_before_each_backend(self):
        logged = []
        entries = [("a", "A", lambda *a, **k: None), ("b", "B", lambda *a, **k: "v")]
        dispatch.execute_modules(
            entries, "probe", None, pipeline=False,
            on_rate_limit=_noop, on_error=_noop,
            log_each=lambda name, m: logged.append((name, m)),
        )
        self.assertEqual(logged, [("A", "probe"), ("B", "probe")])

    def test_kwargs_forwarded_verbatim(self):
        received = []

        def first(*a, **k):
            received.append(dict(k))
            return None

        def second(*a, **k):
            received.append(dict(k))
            return "v"

        entries = [("a", "A", first), ("b", "B", second)]
        dispatch.execute_modules(
            entries, "probe", None, pipeline=False,
            on_rate_limit=_noop, on_error=_noop,
            foo="bar", raise_exception=True,
        )
        self.assertEqual(received[0], {"foo": "bar", "raise_exception": True})


# --------------------------------------------------------------------------- #
# 错误隔离 / 限流（同步）
# --------------------------------------------------------------------------- #
class TestSyncErrorAndRateLimit(unittest.TestCase):

    def test_error_isolated_and_others_continue(self):
        errors = []

        def boom(*a, **k):
            raise RuntimeError("boom")

        def ok(*a, **k):
            return "value"

        entries = [("a", "A", boom), ("b", "B", ok)]
        out = dispatch.execute_modules(
            entries, "probe", None, pipeline=True,
            on_rate_limit=_noop,
            on_error=lambda e, i, n, m: errors.append((i, n, type(e))),
        )
        self.assertEqual(out, "value")
        self.assertEqual(errors, [("a", "A", RuntimeError)])

    def test_on_error_may_propagate_first_exception(self):
        def boom(*a, **k):
            raise RuntimeError("boom")

        entries = [("a", "A", boom), ("b", "B", lambda *a, **k: "value")]
        with self.assertRaises(RuntimeError):
            dispatch.execute_modules(
                entries, "probe", None, pipeline=True,
                on_rate_limit=_noop, on_error=_reraise,
            )

    def test_rate_limit_skipped_not_treated_as_error(self):
        rate_limited = []
        errors = []

        def limited(*a, **k):
            raise RateLimitExceededException("rl")

        def ok(*a, **k):
            return "value"

        entries = [("a", "A", limited), ("b", "B", ok)]
        out = dispatch.execute_modules(
            entries, "probe", None, pipeline=True,
            on_rate_limit=lambda e, i, n, m: rate_limited.append(i),
            on_error=lambda e, i, n, m: errors.append(i),
        )
        self.assertEqual(out, "value")
        self.assertEqual(rate_limited, ["a"])
        self.assertEqual(errors, [])


# --------------------------------------------------------------------------- #
# 异步关键路径
# --------------------------------------------------------------------------- #
class TestAsyncKernel(unittest.TestCase):

    def test_async_mixes_sync_threadpool_and_async_await(self):
        async def afunc(*a, **k):
            return "async-val"

        def sfunc(*a, **k):
            return None

        async def runner():
            entries = [("a", "A", sfunc), ("b", "B", afunc)]
            return await dispatch.async_execute_modules(
                entries, "probe", None, pipeline=False,
                on_rate_limit=_noop, on_error=_noop,
            )

        self.assertEqual(asyncio.run(runner()), "async-val")

    def test_async_list_extend(self):
        async def afirst(*a, **k):
            return [1]

        def ssecond(*a, **k):
            return [2, 3]

        async def runner():
            entries = [("a", "A", afirst), ("b", "B", ssecond)]
            return await dispatch.async_execute_modules(
                entries, "probe", None, pipeline=False,
                on_rate_limit=_noop, on_error=_noop,
            )

        self.assertEqual(asyncio.run(runner()), [1, 2, 3])

    def test_async_pipeline_refines(self):
        def first(*a, **k):
            return "raw"

        async def refine(x: str):
            return x + "-refined"

        async def runner():
            entries = [("a", "A", first), ("b", "B", refine)]
            return await dispatch.async_execute_modules(
                entries, "probe", None, pipeline=True,
                on_rate_limit=_noop, on_error=_noop,
            )

        self.assertEqual(asyncio.run(runner()), "raw-refined")

    def test_async_error_isolated(self):
        errors = []

        def boom(*a, **k):
            raise RuntimeError("boom")

        async def ok(*a, **k):
            return "value"

        async def runner():
            entries = [("a", "A", boom), ("b", "B", ok)]
            return await dispatch.async_execute_modules(
                entries, "probe", None, pipeline=True,
                on_rate_limit=_noop,
                on_error=lambda e, i, n, m: errors.append(i),
            )

        self.assertEqual(asyncio.run(runner()), "value")
        self.assertEqual(errors, ["a"])

    def test_async_rate_limit_skipped(self):
        rate_limited = []
        errors = []

        async def limited(*a, **k):
            raise RateLimitExceededException("rl")

        def ok(*a, **k):
            return "value"

        async def runner():
            entries = [("a", "A", limited), ("b", "B", ok)]
            return await dispatch.async_execute_modules(
                entries, "probe", None, pipeline=True,
                on_rate_limit=lambda e, i, n, m: rate_limited.append(i),
                on_error=lambda e, i, n, m: errors.append(i),
            )

        self.assertEqual(asyncio.run(runner()), "value")
        self.assertEqual(rate_limited, ["a"])
        self.assertEqual(errors, [])


# --------------------------------------------------------------------------- #
# raise_exception 透传系统后端：唯一真实差异（最关键）
# --------------------------------------------------------------------------- #
class TestRaiseExceptionPassthroughDifference(unittest.TestCase):
    """
    ChainBase.run_module 从不 pop raise_exception → 随 **kwargs 透传给系统后端 func（by-design，
    chain 领域方法经签名消费）。ManagerBase._dispatch pop 掉 raise_exception → 系统后端 func 不收到
    （门面后端无此形参，带上会 TypeError）。
    """

    def _make_chain(self, backend):
        chain = ChainBase()
        chain.pluginmanager = Mock()
        chain.pluginmanager.get_plugin_modules.return_value = {}
        chain.modulemanager = Mock()
        chain.modulemanager.get_running_modules.return_value = [backend]
        chain.messagehelper = Mock()
        chain.eventmanager = Mock()
        return chain

    def _make_downloader(self, backend):
        dm = DownloaderManager()
        orig = dm._modulemanager
        dm._modulemanager = Mock()
        dm._modulemanager.get_running_modules.return_value = [backend]
        return dm, orig

    def test_chain_system_backend_receives_raise_exception(self):
        backend = _RecordingModule("chain-sys")
        chain = self._make_chain(backend)

        chain.run_module("probe", raise_exception=True)

        self.assertEqual(len(backend.received), 1)
        self.assertIn("raise_exception", backend.received[0])
        self.assertTrue(backend.received[0]["raise_exception"])

    def test_manager_system_backend_does_not_receive_raise_exception(self):
        backend = _RecordingModule("mgr-sys")
        dm, orig = self._make_downloader(backend)
        try:
            dm._dispatch("probe", raise_exception=True)
        finally:
            dm._modulemanager = orig

        self.assertEqual(len(backend.received), 1)
        self.assertNotIn("raise_exception", backend.received[0])

    def test_async_chain_system_backend_receives_raise_exception(self):
        backend = _RecordingModule("chain-async-sys")
        chain = self._make_chain(backend)

        asyncio.run(chain.async_run_module("probe", raise_exception=True))

        self.assertEqual(len(backend.received), 1)
        self.assertTrue(backend.received[0]["raise_exception"])

    def test_strict_backend_ok_on_manager_but_typeerror_on_chain(self):
        # 门面 pop raise_exception → 严格形参后端可被调用
        backend_m = _StrictModule("mgr")
        dm, orig = self._make_downloader(backend_m)
        try:
            self.assertEqual(dm._dispatch("probe", raise_exception=True), "ok")
        finally:
            dm._modulemanager = orig
        self.assertEqual(backend_m.calls, 1)

        # chain 透传 raise_exception → 严格形参后端 TypeError，且 raise_exception=True 时上抛
        backend_c = _StrictModule("chain")
        chain = self._make_chain(backend_c)
        with self.assertRaises(TypeError):
            chain.run_module("probe", raise_exception=True)


if __name__ == "__main__":
    unittest.main()
