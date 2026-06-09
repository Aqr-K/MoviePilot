import pytest

from app.api.endpoints.search import _parse_media_type
from app.chain.search import SearchChain
from app.core.context import MediaInfo, SubtitleInfo
from app.schemas.types import MediaType


def test_search_media_type_parser_accepts_agent_values():
    """
    搜索入口应兼容前端使用的 movie/tv 媒体类型值。
    """
    assert _parse_media_type("movie") == MediaType.MOVIE
    assert _parse_media_type("tv") == MediaType.TV
    assert _parse_media_type("电影") == MediaType.MOVIE
    assert _parse_media_type("电视剧") == MediaType.TV


def test_exact_subtitle_match_keeps_same_tv_episode(monkeypatch):
    """
    精确字幕搜索应识别字幕名称，并只保留同一剧集的字幕结果。
    """
    chain = object.__new__(SearchChain)

    def fail_filter(*_args, **_kwargs):
        """
        字幕精确搜索不能调用资源过滤规则。
        """
        pytest.fail("字幕精确搜索不应调用过滤规则")

    monkeypatch.setattr(chain, "filter_torrents", fail_filter)

    mediainfo = MediaInfo(
        type=MediaType.TV,
        title="Example Show",
        original_title="Example Show",
        en_title="Example Show",
        year="2024",
        season=1,
        names=["Example Show"],
        season_years={1: "2024"},
    )
    subtitles = [
        SubtitleInfo(site_name="SiteA", title="Example Show S01E03 1080p WEB-DL CHS", subtitle_id="1"),
        SubtitleInfo(site_name="SiteA", title="Example Show S01E04 1080p WEB-DL CHS", subtitle_id="2"),
        SubtitleInfo(site_name="SiteA", title="Example Show S02E03 1080p WEB-DL CHS", subtitle_id="3"),
        SubtitleInfo(site_name="SiteA", title="Other Show S01E03 1080p WEB-DL CHS", subtitle_id="4"),
    ]

    result = chain._SearchChain__parse_subtitle_result(
        subtitles=subtitles,
        mediainfo=mediainfo,
        season_episodes={1: [3]},
        episode=3,
    )

    assert [item.subtitle_id for item in result] == ["1"]


def test_exact_subtitle_match_uses_file_name_candidate():
    """
    精确字幕搜索应同时识别字幕标题和下载文件名。
    """
    chain = object.__new__(SearchChain)
    mediainfo = MediaInfo(
        type=MediaType.TV,
        title="Example Show",
        original_title="Example Show",
        en_title="Example Show",
        year="2024",
        season=1,
        names=["Example Show"],
        season_years={1: "2024"},
    )
    subtitles = [
        SubtitleInfo(
            site_name="SiteA",
            title="Example Show subtitle package",
            file_name="Example.Show.S01E03.1080p.WEB-DL.CHS.srt",
            subtitle_id="1",
        ),
        SubtitleInfo(
            site_name="SiteA",
            title="Example Show subtitle package",
            file_name="Example.Show.S01E04.1080p.WEB-DL.CHS.srt",
            subtitle_id="2",
        ),
    ]

    result = chain._SearchChain__parse_subtitle_result(
        subtitles=subtitles,
        mediainfo=mediainfo,
        season_episodes={1: [3]},
        episode=3,
    )

    assert [item.subtitle_id for item in result] == ["1"]


def test_subtitle_search_params_keep_episode():
    """
    精确字幕搜索缓存参数时应保留集数，便于前端刷新后继续按同一集搜索。
    """
    params = SearchChain._normalize_search_params(
        {
            "keyword": "tmdb:123",
            "type": MediaType.TV,
            "season": 1,
            "episode": 3,
            "sites": "1,2",
            "result_type": "subtitle",
        }
    )

    assert params["episode"] == "3"
    assert params["result_type"] == "subtitle"
