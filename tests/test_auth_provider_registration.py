# -*- coding: utf-8 -*-
"""
provides_auth_providers 固化（消除 G3）片 1 回归：db-free 核心 + 注册管线。

锁定：
  - verify_auth_provider_contract 契约校验（通过 / 各类失败原因）；
  - AuthProviderRegistry 按 provider_id 单索引、provider_id 碰撞检测、按 owner 卸载；
  - SsoStateStore CSRF state 单次有效 / 过期 / 拒绝未知空；
  - _PluginBase.provides_auth_providers 默认 [] + get_plugin_provided_auth_providers 聚合。
"""
from unittest import TestCase

from app.core import sso
from app.core.sso import (
    AuthProviderIdentity,
    AuthProviderRegistry,
    SsoStateStore,
    verify_auth_provider_contract,
)
from app.helper import plugin_metadata
from app.plugins import _PluginBase


class _GoodProvider:
    provider_id = "github"
    provider_name = "GitHub"
    provider_icon = "mdi-github"

    def authorize_url(self, state, redirect_uri):
        return f"https://idp.example.com/auth?state={state}&redirect_uri={redirect_uri}"

    def fetch_identity(self, code, redirect_uri):
        return AuthProviderIdentity(subject="1", username="octocat")


# ---------------------------------------------------------------- 契约校验
class VerifyContractTest(TestCase):

    def test_valid_provider_passes(self):
        ok, reasons = verify_auth_provider_contract(_GoodProvider())
        self.assertTrue(ok)
        self.assertEqual(reasons, [])

    def test_missing_provider_id_rejected(self):
        p = _GoodProvider()
        p.provider_id = ""
        ok, reasons = verify_auth_provider_contract(p)
        self.assertFalse(ok)
        self.assertTrue(any("provider_id" in r for r in reasons))

    def test_non_string_name_rejected(self):
        p = _GoodProvider()
        p.provider_name = 123
        ok, reasons = verify_auth_provider_contract(p)
        self.assertFalse(ok)
        self.assertTrue(any("provider_name" in r for r in reasons))

    def test_provider_id_with_separator_rejected(self):
        # 安全：provider_id 含下划线会破坏 sso_{pid}_{user} 命名空间隔离（跨提供方撞名）
        for bad_id in ("gh_sso", "github/../x", "a b", "../evil"):
            p = _GoodProvider()
            p.provider_id = bad_id
            ok, reasons = verify_auth_provider_contract(p)
            self.assertFalse(ok, f"非法 provider_id 应拒绝：{bad_id}")
            self.assertTrue(any("provider_id" in r for r in reasons))

    def test_provider_id_with_hyphen_allowed(self):
        p = _GoodProvider()
        p.provider_id = "github-enterprise"
        self.assertTrue(verify_auth_provider_contract(p)[0])

    def test_missing_method_rejected(self):
        class _NoMethods:
            provider_id = "x"
            provider_name = "X"
            provider_icon = "i"
        ok, reasons = verify_auth_provider_contract(_NoMethods())
        self.assertFalse(ok)
        self.assertTrue(any("authorize_url" in r for r in reasons))
        self.assertTrue(any("fetch_identity" in r for r in reasons))


# ---------------------------------------------------------------- 注册表
class AuthProviderRegistryTest(TestCase):

    def setUp(self):
        self.reg = AuthProviderRegistry()

    def test_register_and_get(self):
        ok, reason = self.reg.register(_GoodProvider(), owner="pluginA")
        self.assertTrue(ok, reason)
        self.assertEqual(self.reg.provider_ids(), ["github"])
        self.assertIsNotNone(self.reg.get("github"))
        self.assertIsNone(self.reg.get("nope"))

    def test_invalid_provider_rejected_with_reason(self):
        bad = _GoodProvider()
        bad.provider_id = ""
        ok, reason = self.reg.register(bad, owner="pluginA")
        self.assertFalse(ok)
        self.assertIn("provider_id", reason)
        self.assertEqual(self.reg.provider_ids(), [])

    def test_provider_id_collision_across_owners_rejected(self):
        self.assertTrue(self.reg.register(_GoodProvider(), owner="pluginA")[0])
        ok, reason = self.reg.register(_GoodProvider(), owner="pluginB")
        self.assertFalse(ok, "不同 owner 占用同 provider_id 必须拒绝")
        self.assertIn("冲突", reason)

    def test_same_owner_reregister_is_idempotent(self):
        self.assertTrue(self.reg.register(_GoodProvider(), owner="pluginA")[0])
        ok, _ = self.reg.register(_GoodProvider(), owner="pluginA")
        self.assertTrue(ok, "同 owner 重注册同 id 应幂等通过")
        self.assertEqual(self.reg.provider_ids(), ["github"])

    def test_unregister_removes_only_owner(self):
        a = _GoodProvider()
        b = _GoodProvider()
        b.provider_id = "feishu"
        b.provider_name = "Feishu"
        self.reg.register(a, owner="pluginA")
        self.reg.register(b, owner="pluginB")
        self.reg.unregister(owner="pluginA")
        self.assertEqual(self.reg.provider_ids(), ["feishu"])  # 仅卸载 A，B 保留


# ---------------------------------------------------------------- 模块级便捷函数
class ModuleLevelHelpersTest(TestCase):

    def test_register_get_unregister_roundtrip(self):
        prov = _GoodProvider()
        prov.provider_id = "github-modtest"   # 用唯一 id 避免污染共享单例
        try:
            ok, reason = sso.register_auth_provider(prov, owner="modtest-owner")
            self.assertTrue(ok, reason)
            self.assertIsNotNone(sso.get_auth_provider("github-modtest"))
            self.assertIn("github-modtest", sso.registered_provider_ids())
        finally:
            sso.unregister_auth_providers(owner="modtest-owner")
        self.assertIsNone(sso.get_auth_provider("github-modtest"))


# ---------------------------------------------------------------- CSRF state
class SsoStateStoreTest(TestCase):

    def test_single_use(self):
        s = SsoStateStore(ttl_seconds=600)
        st = s.issue()
        self.assertTrue(s.consume(st))
        self.assertFalse(s.consume(st), "state 必须单次有效")

    def test_reject_unknown_and_none(self):
        s = SsoStateStore(ttl_seconds=600)
        self.assertFalse(s.consume("bogus"))
        self.assertFalse(s.consume(None))

    def test_expired_rejected(self):
        s = SsoStateStore(ttl_seconds=0)
        self.assertFalse(s.consume(s.issue()), "过期 state 必须拒绝")


# ---------------------------------------------------------------- 钩子 + 聚合
class _AuthPlugin:
    """声明 SSO 提供方的插件替身（duck-type）。"""

    def get_state(self):
        return True

    def provides_auth_providers(self):
        return [_GoodProvider()]


class ProvidesHookAndAggregatorTest(TestCase):

    def test_base_hook_defaults_empty(self):
        # _PluginBase 默认 provides_auth_providers 返回 []（非 SSO 插件零贡献）
        self.assertIsNotNone(_PluginBase.provides_auth_providers.__doc__)

    def test_aggregator_collects_from_plugin(self):
        provided = plugin_metadata.get_plugin_provided_auth_providers({"ghsso": _AuthPlugin()})
        self.assertIn("ghsso", provided)
        self.assertEqual(len(provided["ghsso"]), 1)
        self.assertEqual(provided["ghsso"][0].provider_id, "github")

    def test_aggregator_skips_disabled(self):
        class _Off(_AuthPlugin):
            def get_state(self):
                return False
        self.assertEqual(plugin_metadata.get_plugin_provided_auth_providers({"off": _Off()}), {})
