import pytest

from app.core.context import TorrentInfo
from app.modules.filter import FilterModule
from app.modules.indexer.spider import SiteSpider
from app.schemas.types import MediaType
from app.utils import rust_accel


pytestmark = pytest.mark.skipif(
    not rust_accel.is_available(),
    reason="moviepilot_rust 扩展未安装",
)


def test_rust_metainfo_fast_path_extracts_emby_override():
    """
    Rust 内嵌媒体标签识别应保持 Emby tmdbid 标签优先级。
    """
    title, metainfo = rust_accel.find_metainfo("Movie {[tmdbid=111;type=movies]} [tmdbid=222]")

    assert title == "Movie"
    assert metainfo["tmdbid"] == "222"
    assert metainfo["type"] == MediaType.MOVIE


def test_rust_video_title_fast_path_extracts_common_resource_fields():
    """
    Rust 影视标题预解析应能提取常见资源字段。
    """
    result = rust_accel.parse_video_title(
        "The 355 2022 BluRay 1080p DTS-HD MA5.1 X265.10bit 60FPS"
    )

    assert result["year"] == "2022"
    assert result["resource_pix"] == "1080p"
    assert result["resource_type"] == "BluRay"
    assert result["video_encode"] == "x265 10bit"
    assert result["video_bit"] == "10bit"
    assert result["fps"] == 60


def test_rust_filter_fast_path_matches_priority_semantics():
    """
    Rust 批量过滤应保持优先级和布尔表达式语义。
    """
    module = FilterModule()
    module.rule_set = {
        "HDR": {"include": "HDR"},
        "DV": {"include": "DOVI"},
        "BLU": {"include": "BluRay"},
    }
    torrents = [
        TorrentInfo(title="Movie HDR WEB-DL", description=""),
        TorrentInfo(title="Movie DOVI", description=""),
        TorrentInfo(title="Movie HDR BluRay", description=""),
    ]

    result = module._FilterModule__filter_torrents_by_rust(  # noqa: SLF001
        groups=[type("RuleGroup", (), {"rule_string": "HDR & !BLU > DV"})()],
        torrent_list=torrents,
        mediainfo=None,
    )

    assert result == torrents[:2]
    assert result[0].pri_order == 100
    assert result[1].pri_order == 99


def test_rust_indexer_search_url_keeps_existing_query_and_category():
    """
    Rust URL 生成应保留路径原有查询参数并应用分类参数。
    """
    spider = SiteSpider(
        indexer={
            "id": "ttg",
            "name": "TTG",
            "domain": "https://totheglory.im/",
            "search": {
                "paths": [{"path": "browse.php?c=M"}],
                "params": {"search_field": "{keyword}", "c": "M"},
                "imdbid_format": "imdb{imdbid_num}",
            },
            "category": {
                "field": "search_field",
                "delimiter": " 分类:",
                "movie": [{"id": "电影DVDRip", "cat": "Movies/SD"}],
            },
            "torrents": {"list": {}, "fields": {}},
        },
        keyword="tt0049406",
        mtype=MediaType.MOVIE,
    )

    search_url = spider._SiteSpider__get_search_url()  # noqa: SLF001

    assert search_url.count("?") == 1
    assert "c=M" in search_url
    assert "search_field=imdb0049406" in search_url


def test_rust_rss_parser_extracts_common_rss_and_atom_fields():
    """
    Rust RSS 解析应同时覆盖 RSS item 和 Atom entry 的核心字段。
    """
    xml_text = """
    <rss><channel>
      <item>
        <title>Example Torrent</title>
        <description><![CDATA[Desc]]></description>
        <link>https://example.org/details/1</link>
        <enclosure url="https://example.org/download/1.torrent" length="1024" />
        <pubDate>Tue, 19 May 2026 08:30:00 GMT</pubDate>
        <dc:creator>豆瓣用户</dc:creator>
      </item>
      <entry>
        <title>Atom Torrent</title>
        <summary>Atom Desc</summary>
        <link href="https://example.org/atom/2" />
        <updated>2026-05-19T09:30:00Z</updated>
      </entry>
    </channel></rss>
    """

    items = rust_accel.parse_rss_items(xml_text, 100)

    assert items[0]["title"] == "Example Torrent"
    assert items[0]["enclosure"] == "https://example.org/download/1.torrent"
    assert items[0]["size"] == 1024
    assert items[0]["nickname"] == "豆瓣用户"
    assert items[1]["title"] == "Atom Torrent"
    assert items[1]["enclosure"] == "https://example.org/atom/2"


def test_rust_indexer_page_parser_handles_common_fields():
    """
    Rust 普通 indexer 页面解析应批量提取列表行核心字段。
    """
    spider = SiteSpider(
        indexer={
            "id": "demo",
            "name": "Demo",
            "domain": "https://example.org/",
            "search": {"paths": [{"path": "torrents.php"}]},
            "category": {
                "movie": [{"id": "401"}],
                "tv": [{"id": "402"}],
            },
            "torrents": {
                "list": {"selector": "tr.torrent"},
                "fields": {
                    "title": {"selector": "a.title"},
                    "description": {"selector": ".desc"},
                    "details": {"selector": "a.title", "attribute": "href"},
                    "download": {"selector": "a.dl", "attribute": "href"},
                    "size": {"selector": ".size"},
                    "seeders": {"selector": ".seeders"},
                    "leechers": {"selector": ".leechers"},
                    "grabs": {"selector": ".grabs"},
                    "downloadvolumefactor": {"case": {".free": 0}},
                    "uploadvolumefactor": {"selector": ".up"},
                    "labels": {"selector": ".label"},
                    "hr": {"selector": ".hr"},
                    "category": {"selector": ".cat"},
                },
            },
        },
    )
    html = """
    <table>
      <tr class="torrent">
        <td><a class="title" href="/details/1">Movie 2024 1080p</a><span class="desc">BluRay</span></td>
        <td><a class="dl" href="/download/1">DL</a></td>
        <td class="size">1.5 GB</td><td class="seeders">1,234</td><td class="leechers">5/10</td>
        <td class="grabs">42</td><td class="free">Free</td><td class="up">2x</td>
        <td><span class="label">DIY</span><span class="label">HDR</span></td>
        <td class="hr">H&R</td><td class="cat">401</td>
      </tr>
    </table>
    """

    torrents = spider.parse(html)

    assert torrents == [{
        "title": "Movie 2024 1080p",
        "description": "BluRay",
        "page_url": "https://example.org/details/1",
        "enclosure": "https://example.org/download/1",
        "size": 1610612736,
        "seeders": 1234,
        "peers": 5,
        "grabs": 42,
        "downloadvolumefactor": 0,
        "uploadvolumefactor": 2,
        "labels": ["DIY", "HDR"],
        "hit_and_run": True,
        "category": MediaType.MOVIE.value,
    }]
