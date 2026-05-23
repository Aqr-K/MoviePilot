import argparse
import statistics
import sys
import time
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.core import metainfo as metainfo_module
from app.core.metainfo import MetaInfo, MetaInfoPath
from tests.cases.meta import meta_cases


def build_inputs(repeat: int):
    """
    构造覆盖 MetaInfo 和 MetaInfoPath 的基准输入。
    """
    inputs = []
    for _ in range(repeat):
        for item in meta_cases:
            if item.get("path"):
                inputs.append(("path", item["path"], item.get("subtitle")))
            else:
                inputs.append(("title", item["title"], item.get("subtitle")))
    return inputs


def disabled_rust_parse(*_args, **_kwargs):
    """
    关闭 Rust MetaInfo 快路径，用于测量旧 Python 链路。
    """
    return None


@contextmanager
def selected_meta_parser(use_rust: bool):
    """
    在 Rust 入口和 Python 旧实现之间切换。
    """
    original_parse = metainfo_module.rust_accel.parse_metainfo
    original_parse_path = metainfo_module.rust_accel.parse_metainfo_path
    original_find = metainfo_module.rust_accel.find_metainfo
    if not use_rust:
        metainfo_module.rust_accel.parse_metainfo = disabled_rust_parse
        metainfo_module.rust_accel.parse_metainfo_path = disabled_rust_parse
        metainfo_module.rust_accel.find_metainfo = disabled_rust_parse
    try:
        yield
    finally:
        metainfo_module.rust_accel.parse_metainfo = original_parse
        metainfo_module.rust_accel.parse_metainfo_path = original_parse_path
        metainfo_module.rust_accel.find_metainfo = original_find


def parse_all(inputs, use_rust: bool):
    """
    执行一轮完整 MetaInfo/MetaInfoPath 入口解析。
    """
    with selected_meta_parser(use_rust):
        parsed = []
        for kind, value, subtitle in inputs:
            if kind == "path":
                parsed.append(MetaInfoPath(Path(value)))
            else:
                parsed.append(MetaInfo(title=value, subtitle=subtitle, custom_words=["#"]))
        return parsed


def measure(inputs, use_rust: bool, loops: int, repeats: int):
    """
    多轮测量 MetaInfo 入口解析耗时。
    """
    samples = []
    parsed_count = 0
    for _ in range(repeats):
        start = time.perf_counter()
        for _ in range(loops):
            parsed = parse_all(inputs, use_rust)
            parsed_count = len(parsed)
        samples.append((time.perf_counter() - start) * 1000 / loops)
    return statistics.median(samples), parsed_count


def parse_args():
    """
    解析命令行参数。
    """
    parser = argparse.ArgumentParser(description="Benchmark MetaInfo parsing through public entries")
    parser.add_argument("--repeat-inputs", type=int, default=20, help="Repeat meta cases per loop")
    parser.add_argument("--loops", type=int, default=10, help="Loops per repeat")
    parser.add_argument("--repeats", type=int, default=5, help="Repeat count")
    return parser.parse_args()


def main() -> int:
    """
    运行 MetaInfo Rust 与 Python 入口链路基准测试。
    """
    args = parse_args()
    inputs = build_inputs(args.repeat_inputs)
    rust_ms, rust_count = measure(inputs, use_rust=True, loops=args.loops, repeats=args.repeats)
    python_ms, python_count = measure(inputs, use_rust=False, loops=args.loops, repeats=args.repeats)
    speedup = python_ms / rust_ms if rust_ms else 0

    print(f"items_per_loop={len(inputs)} loops={args.loops} repeats={args.repeats}")
    print(f"rust_items={rust_count} python_items={python_count}")
    print(f"rust_chain_ms_per_loop={rust_ms:.3f}")
    print(f"python_chain_ms_per_loop={python_ms:.3f}")
    print(f"speedup={speedup:.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
