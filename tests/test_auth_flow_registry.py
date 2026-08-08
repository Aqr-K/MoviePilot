# -*- coding: utf-8 -*-
"""PR12：命名流程注册表 + provides_auth_flows SPI —— 流程形状（组合策略）可由插件插拔。"""
from unittest import TestCase

from app.core.auth.flow import NOf, StepRef
from app.core.auth.flow_registry import (
    FlowSpecRegistry,
    get_auth_flow,
    register_auth_flow,
    unregister_auth_flows,
    verify_flow_spec_contract,
)
from app.helper import plugin_metadata
from app.plugins import _PluginBase


class _GoodFlow:
    flow_id = "high-assurance"

    def mfa_requirement(self, factor_steps):
        return NOf(2, [StepRef(s.step_id) for s in factor_steps])


# ----------------------------- 契约校验 -----------------------------
class VerifyFlowSpecTest(TestCase):

    def test_valid_passes(self):
        ok, reasons = verify_flow_spec_contract(_GoodFlow())
        self.assertTrue(ok, reasons)

    def test_invalid_flow_id_rejected(self):
        bad = _GoodFlow()
        bad.flow_id = "has_underscore"
        ok, reasons = verify_flow_spec_contract(bad)
        self.assertFalse(ok)
        self.assertTrue(any("flow_id" in r for r in reasons))

    def test_missing_method_rejected(self):
        class _NoMethod:
            flow_id = "x"
        ok, reasons = verify_flow_spec_contract(_NoMethod())
        self.assertFalse(ok)
        self.assertTrue(any("mfa_requirement" in r for r in reasons))


# ----------------------------- 注册表 -----------------------------
class FlowRegistryTest(TestCase):

    def setUp(self):
        self.reg = FlowSpecRegistry()

    def test_register_and_get(self):
        ok, reason = self.reg.register(_GoodFlow(), owner="pluginA")
        self.assertTrue(ok, reason)
        self.assertIsNotNone(self.reg.get("high-assurance"))

    def test_collision_across_owners_rejected(self):
        self.assertTrue(self.reg.register(_GoodFlow(), owner="pluginA")[0])
        ok, reason = self.reg.register(_GoodFlow(), owner="pluginB")
        self.assertFalse(ok)
        self.assertIn("冲突", reason)

    def test_unregister_by_owner(self):
        self.reg.register(_GoodFlow(), owner="pluginA")
        self.reg.unregister(owner="pluginA")
        self.assertIsNone(self.reg.get("high-assurance"))


class ModuleLevelHelpersTest(TestCase):

    def test_register_get_unregister_roundtrip(self):
        try:
            ok, reason = register_auth_flow(_GoodFlow(), owner="modtest")
            self.assertTrue(ok, reason)
            self.assertIsNotNone(get_auth_flow("high-assurance"))
        finally:
            unregister_auth_flows(owner="modtest")
        self.assertIsNone(get_auth_flow("high-assurance"))


# ----------------------------- 钩子 + 聚合 -----------------------------
class _FlowPlugin:
    def get_state(self):
        return True

    def provides_auth_flows(self):
        return [_GoodFlow()]


class ProvidesHookAndAggregatorTest(TestCase):

    def test_base_hook_defaults_empty(self):
        # _PluginBase 为抽象类不可实例化；方法体忽略 self，直接以哑 self 调用验证默认 []
        self.assertEqual(_PluginBase.provides_auth_flows(object()), [])

    def test_aggregator_collects(self):
        provided = plugin_metadata.get_plugin_provided_auth_flows({"fp": _FlowPlugin()})
        self.assertIn("fp", provided)
        self.assertEqual(provided["fp"][0].flow_id, "high-assurance")

    def test_aggregator_skips_disabled(self):
        class _Off(_FlowPlugin):
            def get_state(self):
                return False
        self.assertEqual(plugin_metadata.get_plugin_provided_auth_flows({"off": _Off()}), {})
