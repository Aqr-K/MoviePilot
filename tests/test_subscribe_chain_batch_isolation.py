"""
覆盖 SubscribeChain 批量处理循环的异常隔离行为：单个订阅处理失败不应中断其余订阅。
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.application.orchestration import subscribe as subscribe_module
from app.application.orchestration.subscribe import SubscribeChain
from app.schemas.types import MediaType


class _FakeSubscribeOper:
    """最小订阅 Oper 替身，隔离批量循环异常隔离测试的数据库访问。"""

    subscribes = []
    updates = []

    def list(self, _state=None):
        """返回批量处理需要的测试订阅列表。"""
        return list(self.subscribes)

    def get(self, sid: int):
        """按 ID 返回测试订阅对象。"""
        return next((s for s in self.subscribes if s.id == sid), None)

    def update(self, sid: int, payload: dict) -> None:
        """记录订阅状态更新请求。"""
        self.updates.append((sid, payload))


def _subscribe(sub_id: int, name: str) -> SimpleNamespace:
    """构造一个最小可用的电影订阅快照。"""
    return SimpleNamespace(
        id=sub_id,
        name=name,
        year="2026",
        type=MediaType.MOVIE.value,
        media_source=None,
        media_id=None,
        season=None,
        custom_words=None,
        date=None,
        state="N",
        episode_group=None,
        best_version=False,
        sites=None,
    )


def test_search_continues_after_one_subscribe_raises(monkeypatch) -> None:
    """
    批量订阅搜索时，单个订阅在媒体识别阶段抛出异常不应中断其余订阅的搜索，
    且失败订阅应被记录到错误日志中，所有订阅仍应完成状态收敛。
    """
    subscribes = [_subscribe(1, "sub-a"), _subscribe(2, "sub-b"), _subscribe(3, "sub-c")]
    _FakeSubscribeOper.subscribes = subscribes
    _FakeSubscribeOper.updates = []
    monkeypatch.setattr(subscribe_module, "SubscribeOper", _FakeSubscribeOper)

    media_chain = Mock()
    # 依次对应 sub-a（未识别到，正常跳过）、sub-b（抛出非预期异常）、sub-c（未识别到，正常跳过）
    media_chain.recognize_media.side_effect = [None, RuntimeError("boom"), None]
    monkeypatch.setattr(subscribe_module, "MediaChain", Mock(return_value=media_chain))

    error_logs = []
    monkeypatch.setattr(subscribe_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    chain = object.__new__(SubscribeChain)
    chain.search(state="N", manual=False)

    # 三个订阅都应被尝试识别，sub-b 的异常不应阻断后续订阅
    assert media_chain.recognize_media.call_count == 3
    assert any("sub-b" in msg for msg in error_logs)
    # 全部订阅（包括失败的 sub-b）都应完成状态收敛
    assert {sid for sid, _ in _FakeSubscribeOper.updates} == {1, 2, 3}


def test_match_continues_after_one_subscribe_raises(monkeypatch) -> None:
    """
    批量订阅匹配时，单个订阅在媒体识别阶段抛出异常不应中断其余订阅的匹配，
    且失败订阅应被记录到错误日志中。
    """
    subscribes = [_subscribe(1, "sub-a"), _subscribe(2, "sub-b"), _subscribe(3, "sub-c")]
    _FakeSubscribeOper.subscribes = subscribes
    _FakeSubscribeOper.updates = []
    monkeypatch.setattr(subscribe_module, "SubscribeOper", _FakeSubscribeOper)

    media_chain = Mock()
    media_chain.recognize_media.side_effect = [None, RuntimeError("boom"), None]
    monkeypatch.setattr(subscribe_module, "MediaChain", Mock(return_value=media_chain))

    error_logs = []
    monkeypatch.setattr(subscribe_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    chain = object.__new__(SubscribeChain)
    # match() 需要预识别后的种子缓存，空字典即可跳过预识别阶段进入订阅匹配循环
    chain.match({"domain-a": []})

    assert media_chain.recognize_media.call_count == 3
    assert any("sub-b" in msg for msg in error_logs)


def test_check_continues_after_one_subscribe_raises(monkeypatch) -> None:
    """
    批量订阅元数据检查时，单个订阅在媒体识别阶段抛出异常不应中断其余订阅的检查，
    且失败订阅应被记录到错误日志中。
    """
    subscribes = [_subscribe(1, "sub-a"), _subscribe(2, "sub-b"), _subscribe(3, "sub-c")]
    _FakeSubscribeOper.subscribes = subscribes
    _FakeSubscribeOper.updates = []
    monkeypatch.setattr(subscribe_module, "SubscribeOper", _FakeSubscribeOper)

    media_chain = Mock()
    media_chain.recognize_media.side_effect = [None, RuntimeError("boom"), None]
    monkeypatch.setattr(subscribe_module, "MediaChain", Mock(return_value=media_chain))

    error_logs = []
    monkeypatch.setattr(subscribe_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    chain = object.__new__(SubscribeChain)
    chain.check()

    assert media_chain.recognize_media.call_count == 3
    assert any("sub-b" in msg for msg in error_logs)


def test_follow_continues_after_one_share_raises(monkeypatch) -> None:
    """
    批量刷新 Follow 分享订阅时，单个分享处理异常不应中断其余分享的处理，
    且失败分享应被记录到错误日志中。
    """
    shares = [
        {"share_uid": "user1", "name": "share-a", "media_source": "themoviedb", "media_id": "1"},
        {"share_uid": "user1", "name": "share-b", "media_source": "themoviedb", "media_id": "2"},
        {"share_uid": "user1", "name": "share-c", "media_source": "themoviedb", "media_id": "3"},
    ]

    system_config = Mock()
    system_config.get.return_value = ["user1"]
    monkeypatch.setattr(subscribe_module, "_system_config", lambda: system_config)
    monkeypatch.setattr(
        subscribe_module.MoviePilotServerHelper,
        "get_subscribe_shares",
        staticmethod(lambda: shares),
    )

    calls = []

    class _FakeSubscribeOper:
        """记录 exists 调用顺序并对第二个分享抛出异常的订阅 Oper 替身。"""

        def exists(self, **kwargs):
            media_id = kwargs.get("media_id")
            calls.append(media_id)
            if media_id == "2":
                raise RuntimeError("boom")
            # 视为已订阅，触发提前 continue，无需继续构造完整订阅模型
            return True

        def exist_history(self, **kwargs):
            return False

    monkeypatch.setattr(subscribe_module, "SubscribeOper", _FakeSubscribeOper)

    error_logs = []
    monkeypatch.setattr(subscribe_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    subscribe_module.SubscribeChain.follow()

    # 三个分享都应被尝试处理，share-b 的异常不应阻断后续分享
    assert calls == ["1", "2", "3"]
    assert any("share-b" in msg for msg in error_logs)


@pytest.mark.asyncio
async def test_cache_calendar_continues_after_one_subscribe_raises(monkeypatch) -> None:
    """
    批量预缓存订阅日历时，单个订阅在媒体识别阶段抛出异常不应中断其余订阅的预缓存，
    且失败订阅应被记录到错误日志中。
    """
    subscribes = [_subscribe(1, "sub-a"), _subscribe(2, "sub-b"), _subscribe(3, "sub-c")]

    subscribe_oper = Mock()
    subscribe_oper.async_list = AsyncMock(return_value=subscribes)
    monkeypatch.setattr(subscribe_module, "SubscribeOper", lambda: subscribe_oper)

    media_chain = Mock()
    media_chain.async_recognize_media = AsyncMock(side_effect=[None, RuntimeError("boom"), None])
    monkeypatch.setattr(subscribe_module, "MediaChain", Mock(return_value=media_chain))

    error_logs = []
    monkeypatch.setattr(subscribe_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    chain = object.__new__(SubscribeChain)
    await chain.cache_calendar()

    assert media_chain.async_recognize_media.call_count == 3
    assert any("sub-b" in msg for msg in error_logs)


def test_remove_site_wildcard_continues_after_one_subscribe_raises(monkeypatch) -> None:
    """
    站点被重置（site_id="*"）批量清空订阅站点设置时，单个订阅更新异常不应中断
    其余订阅的处理，且失败订阅应被记录到错误日志中。
    """
    subscribes = [
        SimpleNamespace(id=1, name="sub-a", sites=[10]),
        SimpleNamespace(id=2, name="sub-b", sites=[10]),
        SimpleNamespace(id=3, name="sub-c", sites=[10]),
    ]
    calls = []

    class _FakeSubscribeOper:
        """记录 update 调用顺序并对第二个订阅抛出异常的订阅 Oper 替身。"""

        def list(self):
            """返回测试构造的订阅列表。"""
            return subscribes

        def update(self, sid, payload):
            """记录更新调用，对指定订阅抛出异常。"""
            calls.append(sid)
            if sid == 2:
                raise RuntimeError("boom")

    monkeypatch.setattr(subscribe_module, "SubscribeOper", _FakeSubscribeOper)
    monkeypatch.setattr(subscribe_module, "_system_config", lambda: Mock())

    error_logs = []
    monkeypatch.setattr(subscribe_module.logger, "error",
                        lambda msg, *a, **k: error_logs.append(msg))

    chain = object.__new__(SubscribeChain)
    event = SimpleNamespace(event_data={"site_id": "*"})
    chain.remove_site(event)

    # 三个订阅都应被尝试更新，sub-b 的异常不应阻断后续订阅
    assert calls == [1, 2, 3]
    assert any("sub-b" in msg for msg in error_logs)
