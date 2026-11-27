"""
平台投递冻结计划、确认进度与断点恢复。
"""


import json
from unittest.mock import Mock

import pytest

from app.application.messaging.delivery import (
    claim_notification_part,
    collect_notification_preflight,
    freeze_notification_parts,
    merge_notification_progress,
    observe_notification_progress,
)
from app.chain.message import MessageChain
from app.modules.wechat import WechatModule
from app.modules.wechat.wechat import WeChat
from app.modules.wechat.wechatbot import WeChatBot
from app.schemas.message import Message
from app.schemas.system import NotificationConf
from app.schemas.types import MessageType, NotificationChannel


def _observe_recovery(state, *, initial):
    """
    让真实分段算法将内存字典作为独立通知意图的进度存储。
    """
    def record(results):
        """
        合并新回执，并保留已确认的记录。
        """
        state.update(merge_notification_progress(state, results))

    def reserve(part, should_submit):
        """
        按本次派发所处阶段保护网络提交。
        """
        recorded, updated = claim_notification_part(
            state, part, initial_attempt=initial, should_submit=should_submit,
        )
        state.update(updated)
        return recorded

    def plan(parts):
        """
        仅首次派发记录目标。
        """
        if initial:
            state.update(freeze_notification_parts(state, parts))

    return observe_notification_progress(record, reserve=reserve, plan=plan)



def test_wechat_partial_delivery_is_not_a_successful_strict_dispatch(monkeypatch):
    """
    同一轮内两个企业微信实例各发送一次，失败实例的结果不会掩盖成功实例。
    """
    wechat = WechatModule()
    wechat._channel = NotificationChannel.Wechat
    configs = {
        "office": NotificationConf(id="corp-app", name="office", type="wechat", enabled=True),
        "bot": NotificationConf(id="corp-bot", name="bot", type="wechat", enabled=True, config={"WECHAT_MODE": "bot"}),
    }
    clients = {"office": Mock(), "bot": Mock()}
    clients["office"].send_msg.return_value = True
    clients["bot"].send_msg.return_value = False
    monkeypatch.setattr(wechat, "get_configs", lambda: configs)
    monkeypatch.setattr(wechat, "get_config", configs.get)
    monkeypatch.setattr(wechat, "get_instance", clients.get)
    message = Message(channel=NotificationChannel.Wechat, userid="member", text="测试投递", save_history=False)
    chain = MessageChain()
    strict = Mock(side_effect=lambda _method, message: wechat.post_message(message))
    monkeypatch.setattr(chain, "run_module_strict", strict)

    with pytest.raises(RuntimeError, match="部分通知投递尚未确认"):
        chain._deliver_notification(message, strict_delivery=True, immediately=True, kwargs={})

    strict.assert_called_once()
    for client in clients.values():
        client.send_msg.assert_called_once()
    results = message.collect_delivery_results()
    assert [(item.connection_id, item.status) for item in results] == [
        ("corp-app", "confirmed"), ("corp-bot", "retryable_failure"),
    ]
    assert "delivery_results" not in message.model_dump()



def test_wechat_bot_reports_each_target_and_part(monkeypatch):
    """
    已确认的分段、结果未知和没有提交的后续分段均保留，其他目标继续发送。
    """
    monkeypatch.setattr(WeChatBot, "_start_gateway", lambda self: None)
    monkeypatch.setattr(WeChatBot, "_load_known_targets", lambda self: None)
    clients = {
        target: WeChatBot(WECHAT_BOT_ID=target, WECHAT_BOT_SECRET="fixture", WECHAT_BOT_CHAT_ID=target)
        for target in ("alice", "bob")
    }
    ack = Mock(side_effect=[
        ("confirmed", None), ("unknown", "ack_timeout"),
        ("confirmed", None), ("confirmed", None), ("confirmed", None),
    ])
    for client in clients.values():
        monkeypatch.setattr(client, "_split_content", lambda _: ["开始", "中间", "结束"])
        monkeypatch.setattr(client, "_send_with_ack", ack)
    module = WechatModule()
    module._channel = NotificationChannel.Wechat
    configs = {
        target: NotificationConf(id=target, name=target, type="wechat", enabled=True,
                                 config={"WECHAT_MODE": "bot"}, switchs=[MessageType.Subscribe.value])
        for target in clients
    }
    monkeypatch.setattr(module, "get_configs", lambda: configs)
    monkeypatch.setattr(module, "get_config", configs.get)
    monkeypatch.setattr(module, "get_instance", clients.get)
    message = Message(channel=NotificationChannel.Wechat, text="测试", mtype=MessageType.Subscribe,
                      delivery_kind="event_notification")
    results = message.collect_delivery_results()

    module.post_message(message)

    assert [(item.target_id, item.part, item.status, item.code) for item in results] == [
        ("user:alice", 0, "confirmed", None),
        ("user:alice", 1, "unknown", "ack_timeout"),
        ("user:alice", 2, "retryable_failure", "previous_part_unconfirmed"),
        ("user:bob", 0, "confirmed", None),
        ("user:bob", 1, "confirmed", None),
        ("user:bob", 2, "confirmed", None),
    ]
    assert ack.call_count == 5



def test_wechat_bot_host_notification_needs_explicit_or_configured_target(monkeypatch):
    """
    常规通知没有受众时，不向曾使用机器人的用户广播。
    """
    monkeypatch.setattr(WeChatBot, "_start_gateway", lambda self: None)
    monkeypatch.setattr(WeChatBot, "_load_known_targets", lambda self: None)
    client = WeChatBot(WECHAT_BOT_ID="bot", WECHAT_BOT_SECRET="fixture")
    client._known_targets.add("alice")
    send = Mock()
    receipt = Mock()
    monkeypatch.setattr(client, "_send_with_ack", send)

    assert client.send_msg(title="测试通知", receipt=receipt) is False
    send.assert_not_called()
    receipt.assert_called_once_with(None, 0, "skipped", "no_target")



@pytest.mark.parametrize("interrupted", ["retryable_failure", "unknown"])
def test_wechat_bot_recovery_sends_only_known_incomplete_parts(monkeypatch, interrupted):
    """
    恢复只提交同一连接身份和内容下可重试的分段。
    """
    monkeypatch.setattr(WeChatBot, "_start_gateway", lambda self: None)
    monkeypatch.setattr(WeChatBot, "_load_known_targets", lambda self: None)
    client = WeChatBot(WECHAT_BOT_ID="bot", WECHAT_BOT_SECRET="fixture", WECHAT_BOT_CHAT_ID="group:alice")
    monkeypatch.setattr(client, "_split_content", lambda _: ["第一段", "第二段"])
    send = Mock(side_effect=[("confirmed", None), (interrupted, "interrupted"), ("confirmed", None)])
    monkeypatch.setattr(client, "_send_with_ack", send)
    config = NotificationConf(id="bot", name="bot", type="wechat", enabled=True,
                              identity_namespace="binding", config={"WECHAT_MODE": "bot"})
    module = WechatModule()
    module._channel = NotificationChannel.Wechat
    progress = {}
    initial = True

    def observe(results):
        """
        以当前测试记录模拟 Outbox 提交。
        """
        nonlocal progress
        progress = merge_notification_progress(progress, results)

    def reserve(part, should_submit):
        """
        由真实规则决定在本轮可以提交哪些分段。
        """
        nonlocal progress
        result, progress = claim_notification_part(
            progress, part, initial_attempt=initial, should_submit=should_submit,
        )
        return result

    def deliver(current_config, target):
        """
        调用模块正常发送路径并汇总本次回执。
        """
        message = Message(text="内容")
        results = message.collect_delivery_results()
        with observe_notification_progress(observe, reserve=reserve):
            module._post_tracked_notification(client, current_config, message, target)
        return [item.status for item in results]

    assert deliver(config, "group:alice") == ["confirmed", interrupted]
    initial = False
    assert deliver(config, "group:alice") == [
        "confirmed", "confirmed" if interrupted == "retryable_failure" else "unknown",
    ]
    count_before = send.call_count
    assert [call.args[0]["body"]["markdown"]["content"] for call in send.call_args_list] == (
        ["第一段", "第二段", "第二段"] if interrupted == "retryable_failure" else ["第一段", "第二段"]
    )
    assert deliver(config, "group:bob") == ["permanent_failure", "permanent_failure"]
    assert deliver(config.model_copy(update={"identity_namespace": "new"}), "group:alice") == [
        "permanent_failure", "permanent_failure",
    ]
    assert send.call_count == count_before



@pytest.mark.parametrize(("interrupted", "status"), [(None, "unknown"), (45009, "retryable_failure")])
def test_wechat_app_recovers_per_target_and_text_part(monkeypatch, interrupted, status):
    """
    自建应用仅重试平台明确未接受的分段，其他目标仍可投递且恢复时不重发。
    """
    client = WeChat.__new__(WeChat)
    client._appid = "fixture-app"
    monkeypatch.setattr(client, "_WeChat__get_access_token", lambda: "fixture-token")
    responses = [0, interrupted, 0, 0, 0, 0]
    post = Mock(side_effect=[
        None if reply is None else Mock(status_code=200, **{"json.return_value": {"errcode": reply}})
        for reply in responses
    ])
    monkeypatch.setattr("app.modules.wechat.wechat.RequestUtils", Mock(**{"return_value.post": post}))
    config = NotificationConf(id="app", name="app", type="wechat", enabled=True, identity_namespace="binding")
    module = WechatModule()
    module._channel = NotificationChannel.Wechat
    monkeypatch.setattr(module, "get_configs", lambda: {"app": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    progress = {}
    initial = True

    def observe(results):
        """
        模拟由当前 Outbox 认领持久化分段结果。
        """
        nonlocal progress
        progress = merge_notification_progress(progress, results)

    def reserve(part, should_submit):
        """
        根据真实分段规则决定本次网络调用是否获准。
        """
        nonlocal progress
        result, progress = claim_notification_part(
            progress, part, initial_attempt=initial, should_submit=should_submit,
        )
        return result

    def deliver(recipient):
        """
        经通知模块实际入口发送超过单段字节限制的中文通知。
        """
        message = Message(channel=NotificationChannel.Wechat, userid=recipient, text="甲" * 800)
        results = message.collect_delivery_results()
        with observe_notification_progress(observe, reserve=reserve):
            module.post_message(message)
        return [(item.target_id, item.part, item.status) for item in results]

    assert deliver("alice|bob") == [
        ("alice", 0, "confirmed"), ("alice", 1, status),
        ("bob", 0, "confirmed"), ("bob", 1, "confirmed"),
    ]
    initial = False
    assert deliver("alice|bob") == [
        ("alice", 0, "confirmed"), ("alice", 1, "unknown" if interrupted is None else "confirmed"),
        ("bob", 0, "confirmed"), ("bob", 1, "confirmed"),
    ]
    assert deliver("carol") == [("carol", 0, "permanent_failure"), ("carol", 1, "permanent_failure")]
    posted = [json.loads(call.kwargs["data"]) for call in post.call_args_list]
    assert [payload["touser"] for payload in posted] == (
        ["alice", "alice", "bob", "bob"] if interrupted is None else ["alice", "alice", "bob", "bob", "alice"]
    )
    assert all(len(payload["text"]["content"].encode()) <= 2048 for payload in posted)
    if interrupted is not None:
        assert posted[-1] == posted[1]



@pytest.mark.parametrize("content_kind", ["file", "image"])
def test_wechat_app_retries_attachment_without_repeating_caption(monkeypatch, tmp_path, content_kind):
    """
    冻结附件及说明的分段后，限流只重试附件，保留已确认说明及原受众。
    """
    client = WeChat.__new__(WeChat)
    client._appid = "app"
    monkeypatch.setattr(client, "_WeChat__get_access_token", lambda: "fixture-token")
    upload = Mock(return_value="media")
    monkeypatch.setattr(client, "_upload_temp_media", upload)
    post = Mock(side_effect=[
        Mock(status_code=200, **{"json.return_value": {"errcode": code}}) for code in (0, 45009, 0)
    ])
    monkeypatch.setattr("app.modules.wechat.wechat.RequestUtils", Mock(**{"return_value.post": post}))
    module = WechatModule()
    module._channel = NotificationChannel.Wechat
    config = NotificationConf(id="app", name="app", type="wechat", enabled=True, identity_namespace="binding")
    monkeypatch.setattr(module, "get_configs", lambda: {"app": config})
    monkeypatch.setattr(module, "get_config", lambda _: config)
    monkeypatch.setattr(module, "get_instance", lambda _: client)
    path = tmp_path / "movie.srt"
    path.write_bytes(b"subtitle bytes")
    attachment = (
        {"file_path": str(path)} if content_kind == "file"
        else {"image": "data:image/png;base64,iVBORw0KGgoAAQ==", "native_image": True}
    )
    progress = {}
    initial = True

    def freeze(parts):
        """
        保存初次尝试生成的分段清单。
        """
        nonlocal progress
        assert [(part.target_id, part.part) for part in parts] == [("alice", 0), ("alice", 1)]
        progress = freeze_notification_parts(progress, parts)

    def observe(results):
        """
        保存已提交的回执，供后续认领查询。
        """
        nonlocal progress
        progress = merge_notification_progress(progress, results)

    def reserve(part, should_submit):
        """
        通过真实恢复规则复用说明回执，允许附件失败后重试。
        """
        nonlocal progress
        result, progress = claim_notification_part(
            progress, part, initial_attempt=initial, should_submit=should_submit,
        )
        return result

    def deliver():
        """
        从通知模块的公开发送入口获取逐段回执。
        """
        message = Message(channel=NotificationChannel.Wechat, userid="alice", title="说明", **attachment)
        results = message.collect_delivery_results()
        module.post_message(message)
        return [(item.target_id, item.part, item.status) for item in results]

    with observe_notification_progress(observe, reserve=reserve, freeze=freeze):
        with collect_notification_preflight():
            deliver()
        upload.assert_not_called()
        post.assert_not_called()
        assert deliver() == [("alice", 0, "confirmed"), ("alice", 1, "retryable_failure")]
        initial = False
        assert deliver() == [("alice", 0, "confirmed"), ("alice", 1, "confirmed")]
    posted = [json.loads(call.kwargs["data"]) for call in post.call_args_list]
    assert [(payload["touser"], payload["msgtype"]) for payload in posted] == [
        ("alice", "text"), ("alice", content_kind), ("alice", content_kind),
    ]
    assert upload.call_count == 2



@pytest.mark.parametrize(
    ("recipient", "expected"), [
        (None, (None, 0, "skipped", "no_target")),
        ("member|@all", (None, 0, "permanent_failure", "invalid_target")),
    ],
)
def test_wechat_app_tracked_notification_requires_explicit_audience(recipient, expected):
    """
    缺少目标或混合全员地址时，在触达发送边界前结束通知。
    """
    client = WeChat.__new__(WeChat)
    part_sender = Mock()
    receipt = Mock()
    assert client.send_tracked_message(
        "测试", None, None, recipient, None, receipt=receipt, part_sender=part_sender,
    ) is False
    receipt.assert_called_once_with(*expected)
    part_sender.assert_not_called()



def test_wechat_app_voice_timeout_preserves_attachment_and_publishes_unknown(monkeypatch, tmp_path):
    """
    语音提交超时后不发送同一消息的文本，也不删除调用方持有的源附件。
    """
    source = tmp_path / "speech.mp3"
    source.write_bytes(b"audio")
    client = WeChat.__new__(WeChat)
    client._appid = "fixture-app"
    def convert(_source, destination):
        """
        在本次派发独占的输出路径写入转换结果。
        """
        destination.write_bytes(b"converted")
        return destination

    monkeypatch.setattr(client, "_convert_voice_to_amr", convert)
    upload = Mock(return_value="temporary-media")
    monkeypatch.setattr(client, "_upload_temp_media", upload)
    send = Mock(return_value=("unknown", "response_unconfirmed"))
    monkeypatch.setattr(client, "_send_tracked_part", send)
    config = NotificationConf(id="app", name="app", type="wechat", enabled=True, identity_namespace="binding")
    module = WechatModule()
    message = Message(channel=NotificationChannel.Wechat, userid="member", text="正文", voice_path=str(source))
    results = message.collect_delivery_results()

    module._post_tracked_notification(client, config, message, "member")
    assert [(item.status, item.code) for item in results] == [("unknown", "response_unconfirmed")]
    assert [call.args[0]["msgtype"] for call in send.call_args_list] == ["voice"]
    assert source.is_file() and not upload.call_args.args[0].exists()

    source.unlink()
    missing = Message(channel=NotificationChannel.Wechat, userid="member", text="正文", voice_path=str(source))
    results = missing.collect_delivery_results()
    module._post_tracked_notification(client, config, missing, "member")
    assert [(item.status, item.code) for item in results] == [("permanent_failure", "attachment_unavailable")]
    assert send.call_count == 1



def test_wechat_voice_conversion_failure_uses_original_target_and_tracked_text(monkeypatch, tmp_path):
    """
    本地转换失败时，正文走原地址和同一份持久清单，恢复不重复发送。
    """
    source = tmp_path / "speech.mp3"
    source.write_bytes(b"audio")
    client = WeChat.__new__(WeChat)
    client._appid = "fixture-app"
    monkeypatch.setattr(client, "_convert_voice_to_amr", Mock(return_value=None))
    upload = Mock()
    monkeypatch.setattr(client, "_upload_temp_media", upload)
    send = Mock(return_value=("confirmed", None))
    monkeypatch.setattr(client, "_send_tracked_part", send)
    config = NotificationConf(id="app", name="app", type="wechat", enabled=True, identity_namespace="binding")
    module = WechatModule()
    progress = {}
    for initial in (True, False):
        message = Message(channel=NotificationChannel.Wechat, userid="member", text="原正文",
                          voice_path=str(source), private_delivery=True)
        results = message.collect_delivery_results()
        with _observe_recovery(progress, initial=initial):
            module._post_tracked_notification(client, config, message, "member")
        result, = results
        assert (result.target_id, result.status) == ("member", "confirmed")
    assert send.call_count == 1
    payload = send.call_args.args[0]
    assert (payload["touser"], payload["msgtype"], payload["text"]["content"]) == ("member", "text", "原正文")
    upload.assert_not_called()
    assert source.is_file()
