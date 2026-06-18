"""
S7e 抽取验证：app.service.mfa 纯映射逻辑单测（PassKey 凭证/列表字典映射）。

仅覆盖从 MFA 端点抽出的、无副作用的展示用映射；端点保留全部 OTP/PassKey 的
鉴权与验证安全关键逻辑（未抽出、未改动）。
"""
from datetime import datetime
from types import SimpleNamespace

from app.service import mfa


def _pk(**kw):
    base = dict(
        id=1,
        name="key",
        credential_id="cid",
        transports="usb,nfc",
        created_at=None,
        last_used_at=None,
        aaguid="ag",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_build_credential_list_empty_and_none():
    assert mfa.build_credential_list([]) == []
    assert mfa.build_credential_list(None) == []


def test_build_credential_list_maps_fields():
    out = mfa.build_credential_list([_pk(credential_id="abc", transports="usb")])
    assert out == [{"credential_id": "abc", "transports": "usb"}]


def test_build_passkey_list_empty_and_none():
    assert mfa.build_passkey_list([]) == []
    assert mfa.build_passkey_list(None) == []


def test_build_passkey_list_maps_fields_and_dates():
    pk = _pk(
        id=7,
        name="MyKey",
        aaguid="aaa",
        transports="usb",
        created_at=datetime(2026, 6, 17, 22, 0, 0),
        last_used_at=None,
    )
    out = mfa.build_passkey_list([pk])
    assert out == [
        {
            "id": 7,
            "name": "MyKey",
            "created_at": "2026-06-17T22:00:00",
            "last_used_at": None,
            "aaguid": "aaa",
            "transports": "usb",
        }
    ]
