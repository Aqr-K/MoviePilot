import pytest

from app.modules.indexer.spider import SiteSpider
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
