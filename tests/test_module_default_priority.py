# -*- coding: utf-8 -*-
"""
回归测试：_ModuleBase.get_priority() 默认返回 int（DEFAULT_MODULE_PRIORITY），不再返回 None。

背景（架构审计 #25）：get_priority() 旧实现为 ``pass`` → 返回 None，未显式声明优先级的模块在
按优先级排序/比较时会触发 ``TypeError: '<' not supported between 'int' and 'NoneType'``。
修复为回退到模块级常量 DEFAULT_MODULE_PRIORITY=100。

注意：修复刻意未采用 ``x.get_priority() or 0`` 写法——那会把 6 个合法 priority=0 的内建模块
误改为 0 之外的语义（0 为假值会被 ``or`` 吞掉）。本测试同时守护"合法 0 不被改写"这一不变式。
"""
from app.modules import DEFAULT_MODULE_PRIORITY, _ModuleBase
from app.schemas.types import ModuleType


def test_default_priority_constant_is_int_100():
    assert DEFAULT_MODULE_PRIORITY == 100
    assert isinstance(DEFAULT_MODULE_PRIORITY, int)


def test_base_get_priority_returns_int_not_none():
    priority = _ModuleBase.get_priority()
    assert priority is not None
    assert isinstance(priority, int)
    assert priority == DEFAULT_MODULE_PRIORITY


def test_subclass_without_override_inherits_default():
    """未重写 get_priority 的子类回退到默认优先级（实例与类调用一致）。"""

    class _NoPriorityModule(_ModuleBase):
        def init_module(self) -> None:
            pass

        def init_setting(self):
            return None

        def stop(self) -> None:
            pass

        def test(self):
            return True, ""

        @staticmethod
        def get_type() -> ModuleType:
            return ModuleType.Other

    assert _NoPriorityModule().get_priority() == DEFAULT_MODULE_PRIORITY


def test_legitimate_zero_priority_preserved():
    """显式声明 priority=0 的模块不被回退/吞掉——守护"勿用 or 0"的修复约束。"""

    class _ZeroPriorityModule(_ModuleBase):
        def init_module(self) -> None:
            pass

        def init_setting(self):
            return None

        def stop(self) -> None:
            pass

        def test(self):
            return True, ""

        @staticmethod
        def get_type() -> ModuleType:
            return ModuleType.Other

        @staticmethod
        def get_priority() -> int:
            return 0

    assert _ZeroPriorityModule().get_priority() == 0
