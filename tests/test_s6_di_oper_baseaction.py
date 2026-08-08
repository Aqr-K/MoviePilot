"""S6 DI #4：Oper 注入——BaseAction 经 keyword-only 参数注入 SystemConfigOper，默认回退全局单例。

S6「构造注入 + 默认回退全局」模板（#1 ThreadHelper / #2 ChainBase 8 依赖 / #3 settings）
扩到 **Oper 层**（服务定位器的另一半，248 调用点）。BaseAction 是**全部 15 个工作流动作**
的基类，其持有的 SystemConfigOper（单例 Oper）现可注入。

注：db Oper 经 DbOper.__init__(db=None) 已可注入 session；本切片解决的是「单例 Oper
（SystemConfigOper/UserConfigOper）被 consumer 持有」的注入缺口。

价值：任意工作流动作测试可注入 fake SystemConfigOper、不碰全局单例；现有 15 子类
super().__init__(action_id) 位置传参 = 取全局单例、行为不变。
"""
import inspect
import unittest
from unittest.mock import Mock

from app.db.systemconfig_oper import SystemConfigOper
from app.workflow.actions import BaseAction


class _StubAction(BaseAction):
    """覆盖 BaseAction 全部抽象成员（name/description/data/success/execute）以便实例化。"""

    name = "stub"
    description = "stub action"
    data = {}
    success = True

    def execute(self, workflow_id, params, context):
        return context


class BaseActionOperInjectionTest(unittest.TestCase):
    def test_init_exposes_keyword_only_systemconfigoper_default_none(self):
        """__init__ 暴露 keyword-only systemconfigoper 形参且默认 None。"""
        sig = inspect.signature(BaseAction.__init__)
        self.assertIn("systemconfigoper", sig.parameters)
        param = sig.parameters["systemconfigoper"]
        self.assertIsNone(param.default)
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, param.kind)

    def test_systemconfigoper_injectable(self):
        """注入 fake → 原样落到实例属性（不构造真实单例 Oper）。"""
        fake = Mock(name="systemconfigoper")
        action = _StubAction("a1", systemconfigoper=fake)
        self.assertIs(fake, action.systemconfigoper)

    def test_default_falls_back_to_global_singleton(self):
        """不传 → 回退全局单例 SystemConfigOper（零破坏：现有子类位置传参行为不变）。"""
        action = _StubAction("a1")
        self.assertIs(SystemConfigOper(), action.systemconfigoper)
        self.assertEqual("a1", action._action_id)


if __name__ == "__main__":
    unittest.main()
