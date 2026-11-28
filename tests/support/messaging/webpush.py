"""
浏览器推送真实短事务服务的隔离数据库与订阅构造。
"""

from functools import partial
from types import SimpleNamespace

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app.application.webpush import WebPushService
from app.db.adapters.webpush import webpush_scope
from app.db.models.user import User
from app.db.models.webpush import WebPushSubscription as SubscriptionRow
from app.schemas.webpush import WebPushSubscription


def subscription_scope(tmp_path, monkeypatch):
    """
    创建启用外键的真实临时数据库和独立服务，不接触运行配置目录数据库。

    :param tmp_path: 用例独占目录
    :param monkeypatch: 自动恢复进程服务装配的夹具
    :yields: 服务、会话工厂、两位用户及不可变 owner
    """
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'webpush.sqlite'}")

    @sa.event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        """
        启用 SQLite 外键，以真实验证用户删除时的级联清理。

        :param connection: 当前数据库连接
        :param _record: 未使用的连接池记录
        """
        connection.execute("PRAGMA foreign_keys=ON")

    User.__table__.create(engine)
    SubscriptionRow.__table__.create(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as session:
        alice = User(name="alice", is_active=True, account_type="local")
        bob = User(name="bob", is_active=True, account_type="local")
        session.add_all([alice, bob])
        session.flush()
        identities = (alice.id, alice.notification_identity, bob.id, bob.notification_identity)
    service = WebPushService(partial(webpush_scope, factory))
    monkeypatch.setattr("app.application.webpush._service", service)
    try:
        yield SimpleNamespace(service=service, factory=factory, identities=identities)
    finally:
        engine.dispose()



def subscription(endpoint="one", *, key="browser-key", auth="browser-secret"):
    """
    构造不包含客户端 owner 的完整浏览器订阅。

    :param endpoint: 测试端点尾部
    :param key: 浏览器公钥
    :param auth: 浏览器持有的认证密钥
    :return: 严格请求合同
    """
    return WebPushSubscription(endpoint=f"https://push.example/{endpoint}", keys={"p256dh": key, "auth": auth})
