# -*- coding: utf-8 -*-
"""Task 12：单 SPI ``provides_auth_steps`` + 装配桥（``_build_flow_service`` 读 ``all_auth_steps``）
+ ``verify_flow_spec_contract`` 非空真校验 —— S1 失败测试（先红后绿）。
"""
from app.core.auth.flow import AllOf, AnyOf, AuthStepResult, NOf, StepRef


class _SomeStep:
    """最小统一认证步骤（凭证类，directory 种）。"""

    step_id = "myauth-step"
    step_kind = "directory"
    priority = 40

    def applies_to(self, context):
        return context.resolved_user_id is None

    def advance(self, context, submission):
        return AuthStepResult(status="pending")


class _DemoFactor:
    """最小因子构件（供 FactorStep 包装，证明 factor 切分入第二因子步）。"""

    factor_id = "plugin-otp"
    factor_kind = "possession"
    display_name = "插件 OTP"
    priority = 30

    def is_enrolled(self, ref):
        return True

    def verify(self, ref, submission):
        from app.core.auth.outcome import MfaFactorResult
        return MfaFactorResult(status="allow")


# ----------------------------- S1.1 单 SPI 注册 -----------------------------
def test_plugin_step_single_spi(make_plugin_with_steps):
    """插件经唯一 ``provides_auth_steps()`` 声明的步骤，被框架以 owner=plugin_id 注册进全局步骤注册表。"""
    from app.core.auth.steps import auth_step_owner, get_auth_step

    make_plugin_with_steps(plugin_id="myauth", steps=[_SomeStep()]).activate("myauth")
    assert get_auth_step(_SomeStep.step_id) is not None
    assert auth_step_owner(_SomeStep.step_id) == "myauth"


def test_plugin_step_unregistered_on_unload(make_plugin_with_steps):
    """卸载插件后其步骤从注册表移除（无僵尸残留）。"""
    from app.core.auth.steps import get_auth_step

    harness = make_plugin_with_steps(plugin_id="myauth2", steps=[_SomeStep()])
    harness.activate("myauth2")
    assert get_auth_step("myauth-step") is not None
    # 经 harness.deactivate 卸载（会从 fixture.activated 移除，避免 teardown 重复卸载）。
    harness.deactivate("myauth2")
    assert get_auth_step("myauth-step") is None


# ----------------------------- S1.2 装配桥读注册表 -----------------------------
def test_build_flow_service_reads_registry(register_demo_step):
    """``_build_flow_service`` 实时从 ``all_auth_steps()`` 装配；注册了步骤时仍能成功构建服务。"""
    from app.api.endpoints.auth import _build_flow_service

    assert _build_flow_service() is not None


def test_build_flow_service_partitions_by_step_kind():
    """装配桥按 step_kind 切分：credential/directory/... → 凭证步；factor → 第二因子步（含内建，不重复计入）。"""
    from app.api.endpoints.auth import _build_flow_service
    from app.core.auth.steps import register_auth_step, unregister_auth_steps
    from app.service.auth.flow_steps import FactorStep
    import types

    register_auth_step(_SomeStep(), owner="cred-plg")
    register_auth_step(FactorStep(_DemoFactor()), owner="fac-plg")
    try:
        svc = _build_flow_service()
        cred_ids = [getattr(s, "step_id", None) for s in svc._credential_steps]
        # 凭证步含本地 password 与插件 directory 步
        assert "password" in cred_ids
        assert "myauth-step" in cred_ids
        assert "plugin-otp" not in cred_ids  # factor 不进凭证步

        user = types.SimpleNamespace(id=1, name="u", is_otp=False, otp_secret="S")
        fac_ids = [getattr(s, "step_id", None) for s in svc._factor_steps_for(user)]
        # 第二因子步含内建（otp/passkey）+ 插件 factor，且插件 factor 仅出现一次（无双计）
        assert "otp" in fac_ids and "passkey" in fac_ids
        assert fac_ids.count("plugin-otp") == 1
        assert "myauth-step" not in fac_ids  # 凭证步不进第二因子步
    finally:
        unregister_auth_steps("cred-plg")
        unregister_auth_steps("fac-plg")


# ----------------------------- S1.3 非空真拒绝 -----------------------------
def test_flow_spec_rejects_empty_true():
    """空真流程规格（``AllOf([])`` 对空集即满足 → vacuous bypass MFA）必须被契约校验拒绝。"""
    from app.core.auth.flow_registry import verify_flow_spec_contract

    assert verify_flow_spec_contract(
        type("F", (), {"flow_id": "x", "requirement": AllOf([])})()
    )[0] is False


def test_flow_spec_rejects_empty_true_via_mfa_requirement():
    """``mfa_requirement([])`` 求值为空真（NOf(0)）的规格亦被拒绝。"""
    from app.core.auth.flow_registry import verify_flow_spec_contract

    class _VacuousFlow:
        flow_id = "default"

        def mfa_requirement(self, factor_steps):
            return NOf(0, [StepRef(s.step_id) for s in factor_steps])

    assert verify_flow_spec_contract(_VacuousFlow())[0] is False


def test_flow_spec_accepts_non_empty_true():
    """合法规格（NOf(2) 对空集不满足）通过校验，确保非空真校验不误伤正常 N-of-M。"""
    from app.core.auth.flow_registry import verify_flow_spec_contract

    class _StrongFlow:
        flow_id = "high-assurance"

        def mfa_requirement(self, factor_steps):
            return NOf(2, [StepRef(s.step_id) for s in factor_steps])

    assert verify_flow_spec_contract(_StrongFlow())[0] is True


# ----------------------------- S1.4 impostor-exclusion == trusted 集 (Fix 1) ---------
def test_impostor_auxiliary_excluded_builtin_wins(capfd, monkeypatch):
    """安全护栏：插件凭证步声称 step_id='auxiliary' 时，被 trusted_step_ids 过滤器拦截并告警；
    装配桥最终纳入的 'auxiliary' 步必须是内建 AuxiliaryCredentialStep，而非该插件替代步。
    """
    from unittest.mock import MagicMock, patch
    from app.core.auth.steps import register_auth_step, unregister_auth_steps
    from app.service.auth.flow_steps import AuxiliaryCredentialStep
    from app.core.config import settings
    from app.api.endpoints.auth import _build_flow_service

    class _ImpostorAuxiliary:
        step_id = "auxiliary"
        step_kind = "credential"
        priority = 99

        def applies_to(self, ctx):
            return True

        def advance(self, ctx, sub):
            return AuthStepResult(status="pending")

    register_auth_step(_ImpostorAuxiliary(), owner="evil-plugin")
    monkeypatch.setattr(settings, "AUXILIARY_AUTH_ENABLE", True)
    mock_logger = MagicMock()
    try:
        with patch("app.api.endpoints.auth.logger", mock_logger):
            svc = _build_flow_service()

        aux_steps = [s for s in svc._credential_steps
                     if getattr(s, "step_id", None) == "auxiliary"]
        assert len(aux_steps) == 1, "exactly one 'auxiliary' step must exist"
        assert isinstance(aux_steps[0], AuxiliaryCredentialStep), (
            "the 'auxiliary' step must be the builtin AuxiliaryCredentialStep, not the plugin impostor"
        )
        # Assert logger.warning was called with "auxiliary" in the message
        warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
        assert any("auxiliary" in msg for msg in warning_calls), (
            "a warning must be emitted when a plugin step_id clashes with a trusted built-in id"
        )
    finally:
        unregister_auth_steps("evil-plugin")
