"""
验证浏览器订阅的账号隔离、可信登记、重启恢复及失效清理竞争。
"""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies.auth import get_current_active_superuser, get_current_active_user
from app.api.endpoints import message as endpoint
from app.db.models.user import User
from app.modules.webpush import WebPushModule
from app.runtime.webpush import webpush_registry
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import NotificationChannel
from tests.support.messaging.webpush import subscription as _subscription
from tests.support.messaging.webpush import subscription_scope


@pytest.fixture
def browser_devices(tmp_path, monkeypatch):
    """
    为本文件创建并回收独立浏览器设备数据库。

    :param tmp_path: 本用例独立目录
    :param monkeypatch: 自动恢复服务装配
    :yields: 服务与账号身份快照
    """
    yield from subscription_scope(tmp_path, monkeypatch)



def test_http_registration_uses_server_account_and_rejects_client_owner(browser_devices):
    """
    HTTP owner 参数被拒绝，真实归属只从当前本地账号读取，取消仅限本人。

    :param browser_devices: 真实临时数据库及可恢复的服务登记
    """
    case = browser_devices
    alice, owner, bob, bob_owner = case.identities
    current = SimpleNamespace(id=alice, notification_identity=bob_owner)
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/message")
    app.dependency_overrides[get_current_active_user] = lambda: current
    payload = {**_subscription().model_dump(by_alias=True), "expirationTime": None}
    with TestClient(app) as client:
        assert client.post("/message/webpush/subscribe", json={**payload, "owner": bob_owner}).status_code == 422
        assert case.service.management_targets() == ()
        assert client.post("/message/webpush/subscribe", json=payload).json()["success"]
        assert len(case.service.for_owners((owner,))) == 1
        assert case.service.for_owners((bob_owner,)) == ()
        current.id = bob
        assert client.post("/message/webpush/unsubscribe", json=payload).json()["success"]
        assert len(case.service.for_owners((owner,))) == 1
        response = client.post("/message/webpush/subscribe", json=_subscription(auth="forged").model_dump(by_alias=True))
        assert response.status_code == 409
        assert client.post("/message/webpush/subscribe", json=payload).json()["success"]
        assert case.service.for_owners((owner,)) == ()
        assert len(case.service.for_owners((bob_owner,))) == 1
        with case.factory.begin() as session:
            session.get(User, bob).is_active = False
        assert client.post("/message/webpush/subscribe", json=payload).status_code == 403


def test_management_delivery_ignores_ownerless_registry_and_stale_gone_failure(browser_devices, monkeypatch):
    """
    管理全体计划只包含持久化账号设备，410 清理不能删除发送途中重新登记的设备。

    :param browser_devices: 已注入端点的真实持久化服务
    :param monkeypatch: 恢复离线发送器替换
    """
    from app.adapters.network.webpush import WebPushDeliveryError

    case = browser_devices
    alice, owner, _, _ = case.identities
    case.service.register(alice, _subscription())
    attempts = []

    def expired_after_reregistration(**kwargs):
        """
        模拟旧网络请求返回前浏览器完成重新登记。

        :param kwargs: 已剥离 owner 的推送协议参数
        :raises WebPushDeliveryError: 模拟推送服务的 410 响应
        """
        attempts.append(kwargs["subscription"])
        case.service.register(alice, _subscription())
        raise WebPushDeliveryError("gone", response=SimpleNamespace(status_code=410))

    monkeypatch.setattr("app.adapters.network.webpush.send_webpush", expired_after_reregistration)
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/message")
    app.dependency_overrides[get_current_active_superuser] = lambda: SimpleNamespace(id=alice)
    previous = webpush_registry.list()
    webpush_registry.upsert({"endpoint": "https://push.example/legacy", "keys": {}})
    try:
        with TestClient(app) as client:
            assert client.post("/message/webpush/send", json={"title": "管理通知"}).status_code == 200
        assert [item["endpoint"] for item in attempts] == ["https://push.example/one"]
        assert all(set(item) == {"endpoint", "keys"} for item in attempts)
        assert len(case.service.for_owners((owner,))) == 1
    finally:
        webpush_registry.clear()
        for subscription in previous:
            webpush_registry.upsert(subscription)




def test_private_message_never_delivers_to_ownerless_legacy_subscription(monkeypatch, browser_devices):
    """
    历史无归属订阅不能接收带明确私人目标的新通知。

    :param monkeypatch: 自动恢复发送器和模块配置的替换夹具
    :param browser_devices: 不包含任何新登记的独立持久化服务
    """
    previous = webpush_registry.list()
    webpush_registry.clear()
    webpush_registry.upsert({"endpoint": "https://push.example/legacy", "keys": {}})
    deliveries = []
    module = WebPushModule()
    config = NotificationConf(id="web", name="web", type="webpush", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {config.name: config})
    monkeypatch.setattr(module, "check_message", lambda *_: True)
    monkeypatch.setattr("app.modules.webpush.send_webpush", lambda **kwargs: deliveries.append(kwargs))
    message = Message(title="Alice 的私人通知", username="alice", targets={"webpush": "a" * 32})
    message.set_notification_route_scope("user")
    try:
        module.post_message(message)
        assert deliveries == []
    finally:
        webpush_registry.clear()
        for subscription in previous:
            webpush_registry.upsert(subscription)


@pytest.mark.parametrize("scope", ["user", "admin", "all", None])
def test_module_delivers_only_explicit_account_targets_with_real_scope_filter(browser_devices, monkeypatch, scope):
    """
    真实消息基类过滤与模块账号选择共同隔离个人、管理员和明确全体范围。

    :param browser_devices: 真实数据库服务和两个启用账号
    :param monkeypatch: 自动恢复模块配置与离线发送器
    :param scope: 通知链注入的投递范围；缺省不得广播
    """
    case = browser_devices
    alice, owner, bob, bob_owner = case.identities
    case.service.register(alice, _subscription("alice"))
    case.service.register(bob, _subscription("bob"))
    module = WebPushModule()
    config = NotificationConf(id="web", name="web", type="webpush", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {"web": config})
    monkeypatch.setattr(module, "get_config", lambda _name: config)
    deliveries = []
    monkeypatch.setattr("app.modules.webpush.send_webpush", lambda **kwargs: deliveries.append(kwargs))
    target = (owner, bob_owner) if scope == "all" else owner
    message = Message(title="通知", username="alice", targets={"webpush": target})
    message.set_notification_route_scope(scope)
    module.post_message(message)
    assert {item["subscription"]["endpoint"] for item in deliveries} == (
        {"https://push.example/alice", "https://push.example/bob"}
        if scope == "all" else {"https://push.example/alice"}
    )
    deliveries.clear()
    missing = Message(title="没有明确账号目标", username="alice")
    missing.set_notification_route_scope(scope)
    module.post_message(missing)
    assert deliveries == []


def test_module_rechecks_ordinary_delivery_after_endpoint_changes_owner(browser_devices, monkeypatch):
    """
    普通发送选择设备后若端点已经换号，原账号的正文不会提交给推送服务。
    """
    alice, owner, bob, bob_owner = browser_devices.identities
    service = browser_devices.service
    service.register(alice, _subscription())
    for_owners = service.for_owners

    def reassign_after_selection(owners):
        """
        返回旧选择快照前完成换号，模拟选中设备和实际提交之间的竞争。
        """
        selected = for_owners(owners)
        service.register(bob, _subscription())
        return selected

    monkeypatch.setattr(service, "for_owners", reassign_after_selection)
    module = WebPushModule()
    module._channel = NotificationChannel.WebPush
    config = NotificationConf(id="web", name="web", type="webpush", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {config.name: config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    deliveries = []
    monkeypatch.setattr("app.modules.webpush.send_webpush", lambda **kwargs: deliveries.append(kwargs))
    message = Message(title="仅 Alice 可见", channel=NotificationChannel.WebPush, targets={"webpush": owner})
    message.set_notification_route_scope("user")
    receipts = message.collect_delivery_results()
    module.post_message(message)

    assert deliveries == []
    assert [(item.status, item.code) for item in receipts] == [("skipped", "subscription_changed")]
    assert not for_owners((owner,)) and len(for_owners((bob_owner,))) == 1


@pytest.mark.parametrize("status", [404, 410])
def test_module_gone_cleanup_preserves_reassigned_endpoint(browser_devices, monkeypatch, status):
    """
    模块的失效清理也比较账号与版本，旧账号请求不能删除换绑后设备。

    :param browser_devices: 当前用例的真实持久化服务
    :param monkeypatch: 自动恢复模块配置和发送器
    :param status: 推送服务声明订阅失效的状态码
    """
    from app.adapters.network.webpush import WebPushDeliveryError

    case = browser_devices
    alice, owner, bob, bob_owner = case.identities
    case.service.register(alice, _subscription())

    def fail_after_reassignment(**_kwargs):
        """
        返回旧失效响应前把设备登记到当前另一个登录账号。

        :param _kwargs: 已被离线拦截的推送参数
        :raises WebPushDeliveryError: 模拟失效端点响应
        """
        case.service.register(bob, _subscription())
        raise WebPushDeliveryError("gone", response=SimpleNamespace(status_code=status))

    module = WebPushModule()
    config = NotificationConf(id="web", name="web", type="webpush", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {config.name: config})
    monkeypatch.setattr(module, "check_message", lambda *_: True)
    monkeypatch.setattr("app.modules.webpush.send_webpush", fail_after_reassignment)
    message = Message(title="私人通知", targets={"webpush": owner})
    message.set_notification_route_scope("user")
    module.post_message(message)
    assert case.service.for_owners((owner,)) == ()
    assert len(case.service.for_owners((bob_owner,))) == 1


def test_module_records_retry_after_without_removing_device(browser_devices, monkeypatch):
    """
    推送服务明确限流时保留设备，并给重试记录提供平台等待时间。
    """
    from app.adapters.network.webpush import WebPushDeliveryError

    alice, owner, _, _ = browser_devices.identities
    browser_devices.service.register(alice, _subscription())
    response = SimpleNamespace(status_code=429, headers={"Retry-After": "17"})

    def rate_limit(**_):
        """
        模拟浏览器推送服务的限流响应。
        """
        raise WebPushDeliveryError("rate limited", response)

    module = WebPushModule()
    config = NotificationConf(id="web", name="web", type="webpush", enabled=True)
    monkeypatch.setattr(module, "get_configs", lambda: {"web": config})
    monkeypatch.setattr(module, "check_message", lambda *_: True)
    monkeypatch.setattr("app.modules.webpush.send_webpush", rate_limit)
    message = Message(title="私人通知", targets={"webpush": owner}, channel=NotificationChannel.WebPush)
    message.set_notification_route_scope("user")
    results = message.collect_delivery_results()

    module.post_message(message)

    receipt, = results
    assert (receipt.status, receipt.retry_after, receipt.code) == ("retryable_failure", 17, "http_429")
    assert browser_devices.service.for_owners((owner,))


def test_startup_composes_and_resets_persistent_service(browser_devices, monkeypatch):
    """
    启动组合使用显式会话工厂，关停后访问拒绝并且下一启动恢复持久化登记。

    :param browser_devices: 测试独占数据库与服务装配
    :param monkeypatch: 自动恢复启动根会话工厂
    """
    from app.adapters.network import webpush as transport
    from app.application.webpush import get_webpush_service
    from app.startup.composition import webpush as composition

    case = browser_devices
    alice, owner, _, _ = case.identities
    monkeypatch.setattr(composition, "SessionFactory", case.factory)
    monkeypatch.setattr(transport, "_endpoint_validator", transport._endpoint_validator)
    composition.configure_webpush_services()
    get_webpush_service().register(alice, _subscription())
    composition.reset_webpush_services()
    with pytest.raises(RuntimeError, match="未初始化"):
        get_webpush_service()
    composition.configure_webpush_services()
    assert len(get_webpush_service().for_owners((owner,))) == 1
