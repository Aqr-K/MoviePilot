"""覆盖媒体交互链渠道用户名映射的测试。

内建枚举渠道应按渠道用户 ID 查询系统用户名；插件登记的扩展渠道是字符串，
不具备用户表字段映射，应直接得到 ``None`` 而不是抛出 ``AttributeError``。
"""

from unittest.mock import patch

from app.application.orchestration.interaction import MediaInteractionChain
from app.application.messaging.media import media_interaction_manager
from app.domain.context import Context, MediaInfo, TorrentInfo
from app.domain.meta.metabase import MetaBase
from app.schemas.types import MediaType, NotificationChannel


def _build_meta(name: str) -> MetaBase:
    """构造媒体识别元数据。"""
    meta = MetaBase(name)
    meta.name = name
    meta.begin_season = 1
    return meta


def _build_movie_context(title: str = "星际穿越") -> Context:
    """构造可用于媒体交互下载测试的资源上下文。"""
    return Context(
        meta_info=_build_meta(title),
        media_info=MediaInfo(
            type=MediaType.MOVIE,
            title=title,
            year="2014",
            tmdb_id=1,
        ),
        torrent_info=TorrentInfo(
            title=f"{title}.2014.1080p",
            site_name="TestSite",
            enclosure="https://example.com/demo.torrent",
            seeders=10,
        ),
    )


def _build_tv_context(title: str = "葬送的芙莉莲") -> Context:
    """构造可用于媒体交互下载测试的电视剧上下文。"""
    return Context(
        meta_info=_build_meta(title),
        media_info=MediaInfo(
            type=MediaType.TV,
            title=title,
            year="2023",
            tmdb_id=2,
        ),
        torrent_info=TorrentInfo(
            title=f"{title}.S01.1080p",
            site_name="TestSite",
            enclosure="https://example.com/demo-tv.torrent",
            seeders=10,
        ),
    )


def teardown_function(_function):
    """清理媒体交互状态，避免用例之间共享内存会话。"""
    media_interaction_manager.clear()


# ---------------------------------------------------------------------------
# 直接覆盖渠道用户名解析辅助逻辑
# ---------------------------------------------------------------------------

def test_resolve_channel_username_builtin_channel_queries_by_userid_field():
    """内建枚举渠道应以渠道成员名小写拼接的字段名查询用户名。"""
    with patch(
        "app.application.orchestration.interaction.get_chain_user_port"
    ) as get_user_port:
        get_user_port.return_value.get_name.return_value = "张三"
        result = MediaInteractionChain._resolve_channel_username(
            NotificationChannel.Telegram, "10001"
        )

    get_user_port.return_value.get_name.assert_called_once_with(telegram_userid="10001")
    assert result == "张三"


def test_resolve_channel_username_accepts_builtin_enum_name_string():
    """渠道以枚举成员名字符串传入时仍应归一为内建渠道并查询。"""
    with patch(
        "app.application.orchestration.interaction.get_chain_user_port"
    ) as get_user_port:
        get_user_port.return_value.get_name.return_value = "李四"
        result = MediaInteractionChain._resolve_channel_username("Wechat", "20002")

    get_user_port.return_value.get_name.assert_called_once_with(wechat_userid="20002")
    assert result == "李四"


def test_resolve_channel_username_extension_channel_returns_none_without_query():
    """扩展渠道是字符串标识，没有对应的用户表字段，应直接返回 None 且不查库。"""
    with patch(
        "app.application.orchestration.interaction.get_chain_user_port"
    ) as get_user_port:
        result = MediaInteractionChain._resolve_channel_username(
            "p115strmhelper", "30003"
        )

    get_user_port.return_value.get_name.assert_not_called()
    assert result is None


def test_resolve_channel_username_returns_none_for_missing_channel():
    """渠道为 None 时应直接返回 None 且不查库。"""
    with patch(
        "app.application.orchestration.interaction.get_chain_user_port"
    ) as get_user_port:
        result = MediaInteractionChain._resolve_channel_username(None, "40004")

    get_user_port.return_value.get_name.assert_not_called()
    assert result is None


def test_resolve_channel_username_returns_none_for_blank_channel():
    """渠道为空字符串时应直接返回 None 且不查库。"""
    with patch(
        "app.application.orchestration.interaction.get_chain_user_port"
    ) as get_user_port:
        result = MediaInteractionChain._resolve_channel_username("", "50005")

    get_user_port.return_value.get_name.assert_not_called()
    assert result is None


# ---------------------------------------------------------------------------
# 端到端覆盖两处调用点：_subscribe_media 与 _auto_download
# ---------------------------------------------------------------------------

def test_subscribe_media_with_extension_channel_does_not_raise():
    """扩展渠道触发订阅时不应抛出 AttributeError，用户名回退为渠道用户名。"""
    chain = MediaInteractionChain()
    context = _build_movie_context()
    request = media_interaction_manager.create_or_replace(
        user_id="20001",
        channel="p115strmhelper",
        source="p115strmhelper-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )

    with patch(
        "app.application.orchestration.interaction.DownloadChain.get_no_exists_info",
        return_value=(False, {}),
    ), patch(
        "app.application.orchestration.interaction.SubscribeChain.add",
    ) as subscribe_add, patch(
        "app.application.orchestration.interaction.get_chain_user_port",
    ) as get_user_port:
        chain._subscribe_media(
            request=request,
            mediainfo=context.media_info,
            channel="p115strmhelper",
            source="p115strmhelper-test",
            userid="20001",
            username="tester",
        )

    get_user_port.return_value.get_name.assert_not_called()
    subscribe_add.assert_called_once()
    assert subscribe_add.call_args.kwargs["username"] == "tester"
    assert subscribe_add.call_args.kwargs["channel"] == "p115strmhelper"


def test_subscribe_media_with_builtin_channel_maps_username():
    """内建渠道触发订阅时应把查库得到的系统用户名传给 SubscribeChain。"""
    chain = MediaInteractionChain()
    context = _build_movie_context()
    request = media_interaction_manager.create_or_replace(
        user_id="20002",
        channel=NotificationChannel.Telegram,
        source="telegram-test",
        username="tester",
        action="Search",
        keyword="星际穿越",
        title="星际穿越",
        meta=_build_meta("星际穿越"),
        items=[context],
    )

    with patch(
        "app.application.orchestration.interaction.DownloadChain.get_no_exists_info",
        return_value=(False, {}),
    ), patch(
        "app.application.orchestration.interaction.SubscribeChain.add",
    ) as subscribe_add, patch(
        "app.application.orchestration.interaction.get_chain_user_port",
    ) as get_user_port:
        get_user_port.return_value.get_name.return_value = "张三"
        chain._subscribe_media(
            request=request,
            mediainfo=context.media_info,
            channel=NotificationChannel.Telegram,
            source="telegram-test",
            userid="20002",
            username="tester",
        )

    get_user_port.return_value.get_name.assert_called_once_with(telegram_userid="20002")
    assert subscribe_add.call_args.kwargs["username"] == "张三"


def test_auto_download_with_extension_channel_does_not_raise():
    """扩展渠道触发自动下载补建订阅时不应抛出 AttributeError。"""
    chain = MediaInteractionChain()
    context = _build_tv_context()
    request = media_interaction_manager.create_or_replace(
        user_id="20003",
        channel="p115strmhelper",
        source="p115strmhelper-test",
        username="tester",
        action="Search",
        keyword="葬送的芙莉莲",
        title="葬送的芙莉莲",
        meta=_build_meta("葬送的芙莉莲"),
        items=[context],
    )
    request.current_media = context.media_info

    with patch(
        "app.application.orchestration.interaction.DownloadChain.batch_download",
        return_value=([], ["left-item"]),
    ), patch(
        "app.application.orchestration.interaction.SubscribeChain.add",
    ) as subscribe_add, patch(
        "app.application.orchestration.interaction.get_chain_user_port",
    ) as get_user_port:
        chain._auto_download(
            request=request,
            cache_list=[context],
            channel="p115strmhelper",
            source="p115strmhelper-test",
            userid="20003",
            username="tester",
            no_exists={},
        )

    get_user_port.return_value.get_name.assert_not_called()
    subscribe_add.assert_called_once()
    assert subscribe_add.call_args.kwargs["username"] == "tester"
