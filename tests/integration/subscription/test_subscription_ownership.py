"""
媒体订阅旧归属的迁移、身份隔离与管理员复核。
"""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.adapters.web.security.access import oauth2_scheme_manual_error
from app.api.dependencies.auth import get_current_active_user_async
from app.api.dependencies.subscription import get_subscription_ownership_command
from app.api.endpoints.subscribe import router
from app.application.subscription.ownership import (
    ConfirmSubscriptionOwner,
    SubscriptionOwnerAccount,
)
from app.db.models.subscribe import Subscribe


def _new_item(**values):
    """
    创建拥有完整仲裁键的样例订阅。
    """
    return Subscribe(**{
        "name": "示例剧", "username": "old-name", "type": "电视剧", "media_source": "themoviedb",
        "media_id": "42", "season": 1, "state": "R", **values,
    })


def test_ownership_dependency_uses_current_session_and_transaction():
    """
    归属复核命令由当前请求的仓储和事务装配，缺少仓储时拒绝继续。
    """
    session = object()
    unit_of_work = object()
    repositories = []

    def new_repository(scoped_session):
        """
        记录本次请求的会话。
        """
        repositories.append(scoped_session)
        return object()

    runtime = SimpleNamespace(ownership_repository=new_repository)
    assert isinstance(get_subscription_ownership_command(session, runtime, unit_of_work), ConfirmSubscriptionOwner)
    assert repositories == [session]
    runtime.ownership_repository = None
    with pytest.raises(RuntimeError, match="归属确认仓储未注册"):
        get_subscription_ownership_command(session, runtime, unit_of_work)















def test_admin_endpoint_rejects_other_principals():
    """
    仅接受网页管理员，提交的账号版本和记录版本逐字段校验。
    """
    app = FastAPI()
    app.include_router(router)
    actor = SimpleNamespace(id=8, is_superuser=True, account_type="local", authorization_id=None)
    calls = []

    async def execute(*args):
        calls.append(args)
        return "confirmed"

    app.dependency_overrides[get_current_active_user_async] = lambda: actor
    app.dependency_overrides[oauth2_scheme_manual_error] = lambda: None
    async def list_accounts():
        """
        提供稳定顺序的三条复核选项。
        """
        return [SubscriptionOwnerAccount(account_id, f"account-{account_id}", "a" * 64)
                for account_id in range(1, 4)]

    app.dependency_overrides[get_subscription_ownership_command] = lambda: SimpleNamespace(
        execute=execute, list_accounts=list_accounts,
    )
    body = {"account_id": 7, "revision": "a" * 64, "account_revision": "b" * 64}
    with TestClient(app) as client:
        assert client.put("/ownership/active/123", json=body).status_code == 403
        app.dependency_overrides[oauth2_scheme_manual_error] = lambda: "validated-by-auth-dependency"
        actor.authorization_id = "linked-channel"
        assert client.put("/ownership/active/123", json=body).status_code == 403
        actor.authorization_id = None
        actor.is_superuser = False
        assert client.put("/ownership/active/123", json=body).status_code == 403
        actor.is_superuser = True
        assert client.put("/ownership/history/123", json={**body, "owner_identity": "forged"}).status_code == 422
        assert client.put("/ownership/history/123", json=body).json()["success"]
        result = client.get("/ownership/accounts?page=2&count=1")
        assert result.status_code == 200
        assert result.headers["X-Total-Count"] == "3"
        assert result.headers["X-Result-Count"] == "1"
        assert [item["id"] for item in result.json()["data"]] == [2]
    assert calls == [("history", 123, "a" * 64, 7, "b" * 64, 8)]
