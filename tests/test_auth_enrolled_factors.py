# -*- coding: utf-8 -*-
"""PR6：``factors_for_user`` / ``enrolled_factor_ids`` 枚举测试（monkeypatch PassKey/OtpUtils，db-free）。"""
import types

from app.service.auth.orchestrator import enrolled_factor_ids


def _patch(monkeypatch, has_passkey):
    import app.db.models.passkey as pk
    import app.utils.otp as otp
    monkeypatch.setattr(pk.PassKey, "get_by_user_id",
                        staticmethod(lambda db=None, user_id=None: ([object()] if has_passkey else [])))
    monkeypatch.setattr(otp.OtpUtils, "check", staticmethod(lambda s, p: False))


def _user(is_otp):
    return types.SimpleNamespace(id=1, name="admin", is_otp=is_otp, otp_secret="SECRET")


def test_no_factors(monkeypatch):
    _patch(monkeypatch, has_passkey=False)
    assert enrolled_factor_ids(_user(is_otp=False)) == []


def test_otp_only(monkeypatch):
    _patch(monkeypatch, has_passkey=False)
    assert enrolled_factor_ids(_user(is_otp=True)) == ["otp"]


def test_passkey_only(monkeypatch):
    _patch(monkeypatch, has_passkey=True)
    assert enrolled_factor_ids(_user(is_otp=False)) == ["passkey"]


def test_otp_and_passkey_ordered(monkeypatch):
    _patch(monkeypatch, has_passkey=True)
    assert enrolled_factor_ids(_user(is_otp=True)) == ["otp", "passkey"]
