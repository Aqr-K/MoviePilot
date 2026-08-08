"""
MFA 端点的纯逻辑（service layer）：PassKey 凭证 / 列表的字典映射。

均为无副作用的只读字段映射（对 PassKey 对象 duck-typed），不依赖 DB/helper，
可独立单测。端点 app/api/endpoints/mfa.py 保留全部 OTP/PassKey 的鉴权与验证等
安全关键逻辑，本模块仅承接展示用的纯映射。
"""
from typing import Any, List


def build_credential_list(passkeys: list) -> List[dict]:
    """
    构建凭证列表（用于 WebAuthn 选项中的 existing_credentials）
    """
    return (
        [
            {"credential_id": pk.credential_id, "transports": pk.transports}
            for pk in passkeys
        ]
        if passkeys
        else []
    )


def build_passkey_list(passkeys: list) -> List[dict[str, Any]]:
    """
    构建 PassKey 详情列表（用于前端列表展示）
    """
    return (
        [
            {
                "id": pk.id,
                "name": pk.name,
                "created_at": pk.created_at.isoformat() if pk.created_at else None,
                "last_used_at": pk.last_used_at.isoformat()
                if pk.last_used_at
                else None,
                "aaguid": pk.aaguid,
                "transports": pk.transports,
            }
            for pk in passkeys
        ]
        if passkeys
        else []
    )
