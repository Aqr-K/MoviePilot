# -*- coding: utf-8 -*-
"""
SystemConfigOper set()/async_set() 合法 falsy 值守卫回归（PR-I None/falsy 守卫族）。

复现缺陷（母报告 §765-769，systemconfig_oper.py:44/80）：set(key, <falsy>) 因 `if value:`
对 0/False/[]/{}/"" 求值为假，走 delete 分支删除 DB 记录，而内存缓存已写入该 falsy 值
→ 缓存与 DB 不一致；重启后从 DB 重建缓存该 key 消失，合法配置永久丢失。
修复：`if value is not None:`，合法 falsy 正常落库，仅 value is None 才删除记录。
"""
import asyncio
import unittest

from app.db.models.systemconfig import SystemConfig
from app.db.systemconfig_oper import SystemConfigOper


class _FalsyGuardBase(unittest.TestCase):
    KEY = "__pri_falsy_guard_test__"

    def setUp(self):
        self.op = SystemConfigOper()
        # 每个用例重置异步锁：asyncio.Lock 惰性绑定到首次 acquire 的事件循环，
        # 而每个用例各自 asyncio.run 一个新循环，复用旧锁会触发“绑定到不同事件循环”。
        self.op._alock = asyncio.Lock()
        # 干净起点：确保 key 不存在于缓存与 DB。
        self.op.delete(self.KEY)

    def tearDown(self):
        self.op.delete(self.KEY)

    def _db_record(self):
        """经同步会话直读 DB 记录（绕过内存缓存），用于验证 DB 侧真实状态。"""
        return SystemConfig.get_by_key(self.op._db, self.KEY)


class TestSyncSetFalsyGuard(_FalsyGuardBase):

    def test_update_to_empty_list_preserves_db_record(self):
        # Arrange：先存非空值建立 DB 记录
        self.assertTrue(self.op.set(self.KEY, ["a"]))
        self.assertIsNotNone(self._db_record())
        # Act：更新为合法 falsy 空列表
        self.assertTrue(self.op.set(self.KEY, []))
        # Assert：DB 记录仍在、值为 []，缓存与 DB 一致
        rec = self._db_record()
        self.assertIsNotNone(rec, "合法 falsy 值不应删除 DB 记录")
        self.assertEqual(rec.value, [])
        self.assertEqual(self.op.get(self.KEY), [])

    def test_update_to_various_falsy_values_persist(self):
        for falsy in ([], 0, False, ""):
            with self.subTest(falsy=falsy):
                self.op.set(self.KEY, "seed")
                self.assertTrue(self.op.set(self.KEY, falsy))
                rec = self._db_record()
                self.assertIsNotNone(rec, f"falsy={falsy!r} 不应删除 DB 记录")
                self.assertEqual(rec.value, falsy)
                self.op.delete(self.KEY)

    def test_none_still_deletes_record(self):
        self.op.set(self.KEY, "seed")
        self.assertIsNotNone(self._db_record())
        self.op.set(self.KEY, None)
        self.assertIsNone(self._db_record(), "value is None 仍应删除 DB 记录")


class TestAsyncSetFalsyGuard(_FalsyGuardBase):

    def test_async_update_to_empty_list_preserves_db_record(self):
        async def _run():
            # 全部异步操作收进单一事件循环，避免 _alock 跨循环绑定
            await self.op.async_set(self.KEY, ["a"])
            await self.op.async_set(self.KEY, [])
            return await SystemConfig.async_get_by_key(None, self.KEY)

        rec = asyncio.run(_run())
        self.assertIsNotNone(rec, "async: 合法 falsy 值不应删除 DB 记录")
        self.assertEqual(rec.value, [])

    def test_async_none_still_deletes_record(self):
        async def _run():
            await self.op.async_set(self.KEY, "seed")
            await self.op.async_set(self.KEY, None)
            return await SystemConfig.async_get_by_key(None, self.KEY)

        rec = asyncio.run(_run())
        self.assertIsNone(rec, "async: value is None 仍应删除 DB 记录")


if __name__ == "__main__":
    unittest.main()
