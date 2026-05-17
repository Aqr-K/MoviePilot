from urllib.parse import parse_qs, urlparse

from app.modules.indexer.spider import SiteSpider
from app.schemas.types import MediaType


def _build_indexer(**kwargs):
    """
    构造 SiteSpider 生成搜索 URL 所需的最小站点配置。
    """
    indexer = {
        "id": "test",
        "name": "测试站点",
        "domain": "https://example.com/",
        "search": {
            "paths": [{"path": "torrents.php"}],
            "params": {"search": "{keyword}"},
        },
        "torrents": {"list": {}, "fields": {}},
    }
    indexer.update(kwargs)
    return indexer


def _get_search_url(indexer: dict, keyword: str | list[str], mtype: MediaType = None) -> str:
    """
    调用 SiteSpider 私有 URL 构造逻辑，避免真实请求站点。
    """
    spider = SiteSpider(indexer=indexer, keyword=keyword, mtype=mtype)
    return spider._SiteSpider__get_search_url()


def test_eastgame_imdb_search_uses_imdb_area():
    """
    TLF 支持 IMDb ID 搜索时应使用站点配置的 IMDb 搜索区域。
    """
    indexer = _build_indexer(
        id="eastgame",
        domain="https://pt.eastgame.org/",
        search={
            "paths": [{"path": "torrents.php"}],
            "params": {
                "search_area": 4,
                "search": "{keyword}",
            },
        },
    )

    parsed_url = urlparse(_get_search_url(indexer, "tt16311594"))
    query = parse_qs(parsed_url.query)

    assert parsed_url.geturl().startswith("https://pt.eastgame.org/torrents.php?")
    assert query["search"] == ["tt16311594"]
    assert query["search_area"] == ["4"]


def test_eastgame_title_search_keeps_title_area():
    """
    TLF 普通标题搜索不应误用 IMDb 搜索区域。
    """
    indexer = _build_indexer(
        id="eastgame",
        domain="https://pt.eastgame.org/",
        search={
            "paths": [{"path": "torrents.php"}],
            "params": {
                "search_area": 4,
                "search": "{keyword}",
            },
        },
    )

    query = parse_qs(urlparse(_get_search_url(indexer, "普通标题")).query)

    assert query["search"] == ["普通标题"]
    assert query["search_area"] == ["0"]


def test_eastgame_batch_search_keeps_title_area():
    """
    TLF 批量搜索不是单个 IMDb ID，不能触发 IMDb 搜索区域。
    """
    indexer = _build_indexer(
        id="eastgame",
        domain="https://pt.eastgame.org/",
        search={
            "paths": [{"path": "torrents.php"}],
            "params": {
                "search_area": 4,
                "search": "{keyword}",
            },
        },
    )

    query = parse_qs(urlparse(_get_search_url(indexer, ["tt1234567", "tt7654321"])).query)

    assert query["search"] == ["tt1234567 tt7654321"]
    assert query["search_mode"] == ["1"]
    assert query["search_area"] == ["0"]


def test_ttg_imdb_search_formats_keyword_and_keeps_existing_query():
    """
    TTG 的 IMDb 搜索需要 tt 前缀转换，并且路径自带查询参数不能生成双问号。
    """
    indexer = _build_indexer(
        id="ttg",
        domain="https://totheglory.im/",
        search={
            "paths": [{"path": "browse.php?c=M"}],
            "params": {
                "search_field": "{keyword}",
                "c": "M",
            },
            "imdbid_format": "imdb{imdbid_num}",
        },
        category={
            "field": "search_field",
            "delimiter": " 分类:",
            "movie": [{"id": "电影DVDRip", "cat": "Movies/SD"}],
        },
    )

    search_url = _get_search_url(indexer, "tt0049406", MediaType.MOVIE)
    query = parse_qs(urlparse(search_url).query)

    assert search_url.count("?") == 1
    assert query["c"] == ["M"]
    assert query["search_field"] == ["imdb0049406 分类:电影DVDRip"]


def test_ttg_title_search_does_not_format_keyword():
    """
    TTG 普通标题搜索不能被 IMDb ID 格式化规则影响。
    """
    indexer = _build_indexer(
        id="ttg",
        domain="https://totheglory.im/",
        search={
            "paths": [{"path": "browse.php?c=M"}],
            "params": {
                "search_field": "{keyword}",
                "c": "M",
            },
            "imdbid_format": "imdb{imdbid_num}",
        },
        category={
            "field": "search_field",
            "delimiter": " 分类:",
            "movie": [{"id": "电影DVDRip", "cat": "Movies/SD"}],
        },
    )

    query = parse_qs(urlparse(_get_search_url(indexer, "The Movie", MediaType.MOVIE)).query)

    assert query["search_field"] == ["The Movie 分类:电影DVDRip"]
