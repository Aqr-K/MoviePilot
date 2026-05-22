import argparse
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lxml import etree

from app.utils import rust_accel
from app.utils.string import StringUtils


def _time_call(func: Callable[[], None], loops: int) -> float:
    """
    执行指定函数多轮并返回总耗时。
    """
    start = time.perf_counter()
    for _ in range(loops):
        func()
    return time.perf_counter() - start


def _median_time(func: Callable[[], None], loops: int, repeat: int) -> float:
    """
    重复测量指定函数并返回中位耗时。
    """
    return statistics.median(_time_call(func, loops) for _ in range(repeat))


def _rss_xml(item_count: int = 200) -> str:
    """
    生成稳定的 RSS 测试数据，避免网络和站点波动影响结果。
    """
    items = []
    for index in range(item_count):
        items.append(
            f"""
            <item>
              <title>Example Torrent {index}</title>
              <description><![CDATA[Example Desc {index}]]></description>
              <link>https://example.org/details/{index}</link>
              <enclosure url="https://example.org/download/{index}.torrent" length="{index + 1024}" />
              <pubDate>Tue, 19 May 2026 08:30:00 GMT</pubDate>
              <dc:creator>User {index}</dc:creator>
            </item>
            """
        )
    return "<rss xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><channel>" + "".join(items) + "</channel></rss>"


def _python_rss_parse(xml_text: str) -> None:
    """
    执行与 RssHelper 原 XPath 路径等价的 RSS 条目字段提取。
    """
    root = etree.fromstring(
        xml_text.encode("utf-8"),
        parser=etree.XMLParser(recover=True, strip_cdata=False, resolve_entities=False, no_network=True),
    )
    parsed = []
    for item in root.xpath(".//item | .//entry")[:1000]:
        title_nodes = item.xpath(".//title")
        title = title_nodes[0].text if title_nodes and title_nodes[0].text else ""
        desc_nodes = item.xpath(".//description | .//summary")
        description = desc_nodes[0].text if desc_nodes and desc_nodes[0].text else ""
        link_nodes = item.xpath(".//link")
        link = link_nodes[0].text if link_nodes and link_nodes[0].text else ""
        enclosure_nodes = item.xpath(".//enclosure")
        enclosure = enclosure_nodes[0].get("url", "") if enclosure_nodes else link
        pubdate_nodes = item.xpath('./pubDate | ./published | ./updated')
        pubdate = StringUtils.get_time(pubdate_nodes[0].text) if pubdate_nodes and pubdate_nodes[0].text else ""
        parsed.append((title, description, link, enclosure, pubdate))
    root.clear()


def _print_result(name: str, python_seconds: float, rust_seconds: float) -> None:
    """
    输出单项基准耗时和提升倍数。
    """
    speedup = python_seconds / rust_seconds if rust_seconds else 0
    print(f"{name}: Python {python_seconds:.4f}s, Rust {rust_seconds:.4f}s, speedup {speedup:.2f}x")


def run_benchmark(loops: int, repeat: int) -> None:
    """
    运行核心 Rust 加速模块的本地微基准。
    """
    print(f"moviepilot_rust available: {rust_accel.is_available()}")

    xml_text = _rss_xml()
    _print_result(
        "rss item parse",
        _median_time(lambda: _python_rss_parse(xml_text), loops, repeat),
        _median_time(lambda: rust_accel.parse_rss_items(xml_text, 1000), loops, repeat),
    )


def main() -> None:
    """
    命令行入口。
    """
    parser = argparse.ArgumentParser(description="Benchmark MoviePilot Rust acceleration paths.")
    parser.add_argument("--loops", type=int, default=20)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    run_benchmark(max(args.loops, 1), max(args.repeat, 1))


if __name__ == "__main__":
    main()
