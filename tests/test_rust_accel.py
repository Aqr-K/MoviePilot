from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.helper import rss as rss_module
from app.helper.rss import RssHelper
from app.core import metainfo as metainfo_module
from app.core.config import settings
from app.core.meta.customization import CustomizationMatcher
from app.core.meta.releasegroup import ReleaseGroupsMatcher
from app.db.systemconfig_oper import SystemConfigOper
from app.modules.indexer.spider import SiteSpider
from app.schemas.types import SystemConfigKey
from app.schemas.types import MediaType
from app.utils import rust_accel


pytestmark = pytest.mark.skipif(
    not rust_accel.is_available(),
    reason="moviepilot_rust 扩展未安装",
)


def test_rust_filter_rule_parser_matches_boolean_semantics():
    """
    Rust 过滤规则解析应保持 pyparsing 的布尔表达式结构。
    """
    result = rust_accel.parse_filter_rule("HDR & !BLU")

    assert result == [["HDR", "and", ["not", "BLU"]]]


def test_rust_filter_rule_parser_handles_parentheses_and_or():
    """
    Rust 过滤规则解析应保持括号、与、或的优先级语义。
    """
    result = rust_accel.parse_filter_rule("CNSUB & (4K | 1080P) & !BLU")

    assert result == [[["CNSUB", "and", ["4K", "or", "1080P"]], "and", ["not", "BLU"]]]


def test_rust_rss_parser_extracts_rss_and_atom_items():
    """
    Rust RSS解析应覆盖 RSS item、Atom entry、命名空间和日期字段。
    """
    xml = """
    <root xmlns:dc="http://purl.org/dc/elements/1.1/">
      <rss>
        <channel>
          <item>
            <title>Movie &amp; Show</title>
            <description><![CDATA[Desc <b>bold</b>]]></description>
            <link>https://example.com/details/1</link>
            <enclosure url="https://example.com/download/1.torrent" length="123456" />
            <pubDate>Tue, 19 May 2026 08:30:00 GMT</pubDate>
            <dc:creator>豆瓣用户</dc:creator>
          </item>
        </channel>
      </rss>
      <feed>
        <entry>
          <title>Atom Title</title>
          <summary>Atom Summary</summary>
          <link href="https://example.com/atom/2" />
          <updated>2026-05-19T09:30:00Z</updated>
        </entry>
      </feed>
    </root>
    """

    result = rust_accel.parse_rss_items(xml, max_items=100)

    assert len(result) == 2
    assert result[0]["title"] == "Movie & Show"
    assert result[0]["description"] == "Desc <b>bold</b>"
    assert result[0]["link"] == "https://example.com/details/1"
    assert result[0]["enclosure"] == "https://example.com/download/1.torrent"
    assert result[0]["size"] == 123456
    assert result[0]["nickname"] == "豆瓣用户"
    assert int(result[0]["pubdate"].timestamp()) == int(datetime(2026, 5, 19, 8, 30, tzinfo=timezone.utc).timestamp())
    assert result[1]["title"] == "Atom Title"
    assert result[1]["description"] == "Atom Summary"
    assert result[1]["link"] == "https://example.com/atom/2"
    assert result[1]["enclosure"] == "https://example.com/atom/2"
    assert int(result[1]["pubdate"].timestamp()) == int(datetime(2026, 5, 19, 9, 30, tzinfo=timezone.utc).timestamp())


def test_rust_rss_parser_skips_incomplete_items():
    """
    Rust RSS解析应保持原逻辑，跳过无标题或无链接的条目。
    """
    xml = """
    <rss>
      <channel>
        <item><title></title><link>https://example.com/a</link></item>
        <item><title>No Link</title></item>
        <item><title>OK</title><link>https://example.com/ok</link></item>
      </channel>
    </rss>
    """

    result = rust_accel.parse_rss_items(xml, max_items=100)

    assert result == [{
        "title": "OK",
        "enclosure": "https://example.com/ok",
        "size": 0,
        "description": "",
        "link": "https://example.com/ok",
        "pubdate": "",
    }]


def test_rss_helper_parse_uses_rust_parser(monkeypatch):
    """
    RssHelper.parse 应在请求和编码处理后直接使用 Rust 解析结果。
    """
    xml = """
    <rss>
      <channel>
        <item>
          <title>Helper Title</title>
          <description>Helper Description</description>
          <link>https://example.com/details/3</link>
          <pubDate>2026-05-19T10:30:00Z</pubDate>
        </item>
      </channel>
    </rss>
    """

    class FakeRequestUtils:
        """
        测试用 RequestUtils，避免真实网络请求。
        """

        def __init__(self, **_kwargs):
            """
            保存构造参数占位，兼容 RssHelper 的调用方式。
            """

        def get_res(self, _url):
            """
            返回带 content/text/status_code 的最小响应对象。
            """
            return SimpleNamespace(
                status_code=200,
                content=xml.encode("utf-8"),
                text=xml,
                apparent_encoding="utf-8",
                encoding="utf-8",
            )

    monkeypatch.setattr(rss_module, "RequestUtils", FakeRequestUtils)

    result = RssHelper().parse("https://example.com/rss")

    assert len(result) == 1
    assert result[0]["title"] == "Helper Title"
    assert result[0]["enclosure"] == "https://example.com/details/3"
    assert int(result[0]["pubdate"].timestamp()) == int(datetime(2026, 5, 19, 10, 30, tzinfo=timezone.utc).timestamp())


def _metainfo_options(custom_words=None):
    """
    构造 Rust MetaInfo 测试所需的配置，保持和生产入口一致。
    """
    systemconfig = SystemConfigOper()
    custom_release_groups = systemconfig.get(SystemConfigKey.CustomReleaseGroups)
    if isinstance(custom_release_groups, list):
        custom_release_groups = list(filter(None, custom_release_groups))
    release_groups = ReleaseGroupsMatcher()._ReleaseGroupsMatcher__release_groups
    if custom_release_groups:
        release_groups = f"{release_groups}|{'|'.join(custom_release_groups)}"
    customization = CustomizationMatcher._normalize_customization(
        systemconfig.get(SystemConfigKey.Customization)
    )
    return {
        "custom_words": custom_words or [],
        "media_exts": settings.RMT_MEDIAEXT + settings.RMT_SUBEXT + settings.RMT_AUDIOEXT,
        "release_groups": release_groups,
        "customization": customization,
    }


def test_rust_metainfo_parser_handles_video_from_entry():
    """
    Rust MetaInfo 入口应完整识别普通影视标题。
    """
    result = rust_accel.parse_metainfo(
        "The Long Season 2017 2160p WEB-DL H265 120FPS AAC-XXX",
        options=_metainfo_options(),
    )

    assert result["kind"] == "video"
    assert result["type"] == "未知"
    assert result["en_name"] == "The Long Season"
    assert result["year"] == "2017"
    assert result["resource_type"] == "WEB-DL"
    assert result["resource_pix"] == "2160p"
    assert result["video_encode"] == "H265"
    assert result["audio_encode"] == "AAC"
    assert result["fps"] == 120


def test_rust_metainfo_parser_handles_anime_from_entry():
    """
    Rust MetaInfo 入口应完整识别 Anime 标题。
    """
    result = rust_accel.parse_metainfo(
        "[ANi] OVERLORD 第四季 - 04 [1080P][Baha][WEB-DL][AAC AVC][CHT].mp4",
        options=_metainfo_options(),
    )

    assert result["kind"] == "anime"
    assert result["type"] == "电视剧"
    assert result["en_name"] == "Overlord"
    assert result["begin_season"] == 4
    assert result["begin_episode"] == 4
    assert result["resource_pix"] == "1080p"
    assert result["video_encode"] == "AVC"
    assert result["audio_encode"] == "AAC"


def test_rust_metainfo_path_parser_merges_parent_title():
    """
    Rust MetaInfoPath 入口应在 Rust 内完成父目录标题合并。
    """
    result = rust_accel.parse_metainfo_path(
        "/Marty Supreme 2025 2160p DoVi HDR Atmos TrueHD 7.1 x265-PbK/简英双语特效.mp4",
        options=_metainfo_options(),
    )

    assert result["kind"] == "video"
    assert result["en_name"] == "Marty Supreme"
    assert result["year"] == "2025"
    assert result["original_name"] == "Marty Supreme"
    assert result["resource_pix"] == "2160p"


def test_metainfo_public_entry_uses_rust(monkeypatch):
    """
    MetaInfo 公共入口应调用 Rust 解析器，而不是直接进入 Python 旧解析逻辑。
    """
    calls = []
    original_parse = metainfo_module.rust_accel.parse_metainfo

    def wrapped_parse(*args, **kwargs):
        """
        记录 Rust 入口调用并透传结果。
        """
        calls.append(args[0])
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(metainfo_module.rust_accel, "parse_metainfo", wrapped_parse)

    meta = metainfo_module.MetaInfo("旧名 第03集", custom_words=["旧名 => 新名 && 第 <> 集 >> EP+1"])

    assert calls == ["旧名 第03集"]
    assert meta.name == "新名"
    assert meta.episode == "E04"
    assert meta.apply_words == ["旧名 => 新名 && 第 <> 集 >> EP+1"]


def test_rust_indexer_parser_handles_jinja_pyquery_filters_and_links():
    """
    Rust indexer 解析应覆盖普通站点配置的 Jinja、PyQuery selector 和过滤器。
    """
    html = """
    <table class="torrents">
      <tr>
        <td><a href="?cat=402">TV</a></td>
        <td>
          <table class="torrentname">
            <tr>
              <td class="embedded">
                <a href="details.php?id=100" title="Optional.Title">Default.Title</a>
                <a href="download.php?id=100">DL</a>
                <a href="https://www.imdb.com/title/tt1234567/">IMDb</a>
                <font class="subtitle">Main description <span>remove</span><a>link</a></font>
                <span class="label">FREE</span>
                <img class="hitandrun" />
              </td>
            </tr>
          </table>
        </td>
        <td></td>
        <td><span title="2025-05-01 12:13:14">1 hour ago</span></td>
        <td>1.5 GB</td>
        <td>1,234</td>
        <td>5/7</td>
        <td>9</td>
      </tr>
    </table>
    """
    indexer = {
        "id": "unit",
        "name": "Unit",
        "domain": "https://example.com/",
        "search": {"paths": [{"path": "torrents.php"}]},
        "category": {
            "movie": [{"id": "401"}],
            "tv": [{"id": "402"}],
        },
        "torrents": {
            "list": {"selector": 'table.torrents > tr:has("table.torrentname")'},
            "fields": {
                "title_default": {"selector": 'a[href*="details.php?id="]'},
                "title_optional": {
                    "selector": 'a[title][href*="details.php?id="]',
                    "attribute": "title",
                },
                "title": {
                    "text": "{% if fields['title_optional'] %}{{ fields['title_optional'] }}{% else %}"
                            "{{ fields['title_default'] }}{% endif %}"
                },
                "details": {"selector": 'a[href*="details.php?id="]', "attribute": "href"},
                "download": {"selector": 'a[href*="download.php?id="]', "attribute": "href"},
                "imdbid": {
                    "selector": 'a[href*="imdb.com/title/tt"]',
                    "attribute": "href",
                    "filters": [{"name": "re_search", "args": ["tt\\d+", 0]}],
                },
                "date_elapsed": {"selector": "td:nth-child(4) > span"},
                "date_added": {"selector": "td:nth-child(4) > span", "attribute": "title"},
                "date": {
                    "text": "{% if fields['date_elapsed'] or fields['date_added'] %}"
                            "{{ fields['date_added'] if fields['date_added'] else fields['date_elapsed'] }}"
                            "{% else %}now{% endif %}",
                    "filters": [{"name": "dateparse", "args": "%Y-%m-%d %H:%M:%S"}],
                },
                "size": {"selector": "td:nth-child(5)"},
                "seeders": {"selector": "td:nth-child(6)"},
                "leechers": {"selector": "td:nth-child(7)"},
                "grabs": {"selector": "td:nth-child(8)"},
                "downloadvolumefactor": {"case": {"img.free": 0, "*": 1}},
                "uploadvolumefactor": {"case": {"*": 1}},
                "description": {
                    "selector": "font.subtitle",
                    "remove": "span,a",
                },
                "labels": {"selector": "span.label"},
                "hr": {"selector": "img.hitandrun"},
                "category": {
                    "selector": 'a[href*="?cat="]',
                    "attribute": "href",
                    "filters": [{"name": "querystring", "args": "cat"}],
                },
            },
        },
    }

    result = SiteSpider(indexer, mtype=MediaType.TV).parse(html)

    assert result == [{
        "page_url": "https://example.com/details.php?id=100",
        "enclosure": "https://example.com/download.php?id=100",
        "downloadvolumefactor": 1.0,
        "uploadvolumefactor": 1.0,
        "pubdate": "2025-05-01 12:13:14",
        "title": "Optional.Title",
        "description": "Main description",
        "imdbid": "tt1234567",
        "size": 1610612736,
        "peers": 5,
        "seeders": 1234,
        "grabs": 9,
        "date_elapsed": "1 hour ago",
        "labels": ["FREE"],
        "hit_and_run": True,
        "category": "电视剧",
    }]


def test_rust_indexer_parser_handles_default_values_and_template_arithmetic():
    """
    Rust indexer 解析应支持 defualt_value、Jinja int filter 和模板算术表达式。
    """
    html = """
    <table class="torrents">
      <tr>
        <td><a href="details.php?id=200">Default.Title</a></td>
      </tr>
    </table>
    """
    fields = {
        "title_default": {"selector": 'a[href*="details.php?id="]'},
        "missing_days": {"defualt_value": "2", "selector": "span.missing"},
        "title": {"text": "{{ fields['title_default'] }} {{ (fields['missing_days']|int)*86400 }}"},
    }

    result = rust_accel.parse_indexer_torrents(
        html_text=html,
        domain="https://example.com/",
        list_config={"selector": "table.torrents > tr"},
        fields=fields,
        category=None,
        result_num=100,
    )

    assert result == [{"title": "Default.Title 172800"}]


def test_rust_indexer_parser_handles_lstrip_and_english_elapsed_date():
    """
    Rust indexer 解析应覆盖 IPT 配置用到的 lstrip 和 date_en_elapsed_parse 过滤器。
    """
    html = """
    <table id="torrents">
      <tr>
        <td><a href="/t/123">Title</a><a href="/download.php/123">download</a></td>
        <td><div>Uploaded | 2 hours ago</div></td>
      </tr>
    </table>
    """
    fields = {
        "title": {"selector": 'a[href*="/t/"]'},
        "download": {
            "selector": 'a[href*="/download.php/"]',
            "attribute": "href",
            "filters": [{"name": "lstrip", "args": ["/"]}],
        },
        "date": {
            "selector": "td:nth-child(2) > div",
            "filters": [
                {"name": "split", "args": ["|", 1]},
                {"name": "date_en_elapsed_parse"},
            ],
        },
    }

    result = rust_accel.parse_indexer_torrents(
        html_text=html,
        domain="https://iptorrents.com/",
        list_config={"selector": 'table[id="torrents"] tr'},
        fields=fields,
        category=None,
        result_num=100,
    )

    assert len(result) == 1
    assert result[0]["title"] == "Title"
    assert result[0]["enclosure"] == "https://iptorrents.com/download.php/123"
    assert result[0]["pubdate"]


def test_rust_indexer_parser_prefers_date_added_when_date_template_returns_elapsed_text():
    """
    Rust indexer 解析 date 模板产出相对时间时，应使用 date_added 里的标准时间。
    """
    html = """
    <table class="torrents">
      <tr>
        <td><span title="2025-06-02 03:04:05">1 hour ago</span></td>
      </tr>
    </table>
    """
    fields = {
        "date_elapsed": {"selector": "span"},
        "date_added": {"selector": "span", "attribute": "title"},
        "date": {
            "text": "{% if fields['date_elapsed'] or fields['date_added'] %}"
                    "{{ fields['date_elapsed'] if fields['date_elapsed'] else fields['date_added'] }}"
                    "{% else %}now{% endif %}",
            "filters": [{"name": "dateparse", "args": "%Y-%m-%d %H:%M:%S"}],
        },
    }

    result = rust_accel.parse_indexer_torrents(
        html_text=html,
        domain="https://example.com/",
        list_config={"selector": "table.torrents > tr"},
        fields=fields,
        category=None,
        result_num=100,
    )

    assert result[0]["pubdate"] == "2025-06-02 03:04:05"
