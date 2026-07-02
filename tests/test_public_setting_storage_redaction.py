"""
公开系统设置端点存储凭据泄露回归测试。

GET /system/setting/public/Storages 只需普通用户（is_active）即可访问，
必须对返回的存储配置脱敏：剥离 config（内含 alist 账密 / SMB 密码 /
u115·alipan OAuth token），仅保留 type/name，避免非超管越权读取凭据。
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from app.api.endpoints import system as system_endpoints
from app.schemas.types import SystemConfigKey


_STORAGES_WITH_SECRETS = [
    {"type": "alist", "name": "我的Alist",
     "config": {"url": "http://x", "username": "admin", "password": "s3cret", "token": "tok"}},
    {"type": "u115", "name": "115网盘",
     "config": {"refresh_token": "rt-xxx", "access_token": "at-yyy"}},
    {"type": "smb", "name": "群晖",
     "config": {"host": "1.2.3.4", "username": "u", "password": "p@ss"}},
]

_SECRET_TOKENS = {"s3cret", "tok", "rt-xxx", "at-yyy", "p@ss"}


def _call_public_setting(key: str):
    fake_user = SimpleNamespace(id=2, name="normal", is_superuser=False, is_active=True)
    with patch.object(system_endpoints, "SystemConfigOper") as mock_oper:
        mock_oper.return_value.get.return_value = _STORAGES_WITH_SECRETS
        return asyncio.run(system_endpoints.get_public_setting(key, _=fake_user))


def test_storages_public_setting_strips_credentials():
    resp = _call_public_setting(SystemConfigKey.Storages.value)
    value = resp.data.get("value") if isinstance(resp.data, dict) else resp.data
    # 序列化整段返回值，断言任何凭据 token 都不出现
    dumped = str(value)
    for secret in _SECRET_TOKENS:
        assert secret not in dumped, f"凭据 {secret} 不应出现在公开端点返回中"


def test_storages_public_setting_keeps_type_and_name():
    resp = _call_public_setting(SystemConfigKey.Storages.value)
    value = resp.data.get("value") if isinstance(resp.data, dict) else resp.data
    assert isinstance(value, list) and len(value) == 3
    names = {item.get("name") for item in value}
    types = {item.get("type") for item in value}
    assert names == {"我的Alist", "115网盘", "群晖"}
    assert types == {"alist", "u115", "smb"}
