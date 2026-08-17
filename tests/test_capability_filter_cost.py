"""能力判定的开销契约。

能力过滤是分发流水线共用的一级：每次分发都要对每个候选者判定一次「该方法是否已实现」。
判定要解析方法源码，而结果只取决于方法本身、与绑定到哪个实例无关，重复解析是纯浪费。

缓存键必须是底层函数对象而非绑定方法：绑定方法持有实例，把它放进缓存会让模块在停止或
重载后仍被钉住，与模块运行时按代次回收资源的语义冲突。
"""
import ast
import gc
import unittest
import weakref
from unittest.mock import patch

from app.foundation.reflection import ObjectUtils


class Probe:
    """被判定的模块替身"""

    def implemented(self, payload=None):
        """已实现的方法"""
        result = []
        for item in range(3):
            result.append(item)
        return result or payload

    def empty(self):
        """空实现"""
        pass

    def not_implemented(self):
        """声明未实现"""
        raise NotImplementedError


class CapabilityFilterCostTest(unittest.TestCase):
    """判定结果可复用，且不把模块实例钉在缓存里"""

    def test_repeated_checks_parse_the_source_only_once(self):
        """同一个方法重复判定时不再解析源码。"""
        probe = Probe()
        ObjectUtils.check_method(probe.implemented)

        with patch("app.foundation.reflection.ast.parse", wraps=ast.parse) as parse_spy:
            for _ in range(5):
                ObjectUtils.check_method(probe.implemented)

        self.assertEqual(0, parse_spy.call_count)

    def test_a_second_instance_reuses_the_first_verdict(self):
        """判定与实例无关，另一个实例的同名方法直接命中缓存。"""
        ObjectUtils.check_method(Probe().implemented)

        with patch("app.foundation.reflection.ast.parse", wraps=ast.parse) as parse_spy:
            ObjectUtils.check_method(Probe().implemented)

        self.assertEqual(0, parse_spy.call_count)

    def test_empty_and_unimplemented_bodies_are_still_rejected(self):
        """缓存不改变判定结果：空实现与未实现仍判为未提供能力。"""
        probe = Probe()

        self.assertTrue(ObjectUtils.check_method(probe.implemented))
        self.assertFalse(ObjectUtils.check_method(probe.empty))
        self.assertFalse(ObjectUtils.check_method(probe.not_implemented))

    def test_the_cache_does_not_pin_module_instances(self):
        """判定缓存不持有模块实例，模块停止后可被回收。"""
        instance = Probe()
        reference = weakref.ref(instance)
        ObjectUtils.check_method(instance.implemented)

        del instance
        gc.collect()

        self.assertIsNone(reference())


if __name__ == "__main__":
    unittest.main()
