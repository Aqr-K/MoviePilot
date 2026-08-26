"""内核层对外挂第三方包的依赖护栏。

v3-lite 把 agent、workflow 与冷门接入商模块移出内核，它们各自携带的第三方包随之
离开本体。内核层从此不得再 import 这些包——一旦某个内核文件用上，该包就必须留在
本体依赖里，减负即告失效。

护栏按阶段推进：`GUARDED_ROOTS` 列出已完成解耦的内核目录，随各阶段落地逐步扩大。
未列入的目录不是「允许依赖」，而是「尚未解耦」，其待清偿的边记在 `PENDING_ROOTS`。
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator, Set, Tuple

PROJECT_ROOT = Path(__file__).parents[1]
APP_ROOT = PROJECT_ROOT / "app"

# 随外挂子系统一并移出本体的第三方顶层包。
# 判据是「该包只为被外挂的功能存在」：numpy 由 langchain/openai 间接引入，
# websocket-client 因保留模块 wechat 仍在使用而不列入。
EXTERNALIZED_DISTRIBUTIONS: frozenset[str] = frozenset({
    # agent 域
    "langchain",
    "langchain_anthropic",
    "langchain_aws",
    "langchain_classic",
    "langchain_community",
    "langchain_core",
    "langchain_deepseek",
    "langchain_google_genai",
    "langchain_openai",
    "langchain_text_splitters",
    "langgraph",
    "langgraph_checkpoint",
    "langgraph_prebuilt",
    "langgraph_sdk",
    "anthropic",
    "openai",
    "boto3",
    "botocore",
    "numpy",
    # 冷门接入商模块域
    "lark_oapi",
    "discord",
    "slack_bolt",
    "slack_sdk",
    "smbclient",
    "smbprotocol",
})

# 已完成解耦、现在起受护栏约束的内核目录（相对 app/）。
GUARDED_ROOTS: frozenset[str] = frozenset({
    "schemas",
})

# 尚未解耦的内核目录及其待清偿方向。这里列出的目录本轮不受约束；
# 某目录解耦完成后，把它从本表移入 GUARDED_ROOTS，不要放宽 GUARDED_ROOTS 的判定。
PENDING_ROOTS: dict[str, str] = {
    "agent": "整体外挂为插件，届时目录不再属于内核",
    "workflow": "整体外挂为插件，届时目录不再属于内核",
    "modules": "28 个冷门接入商外挂后，其余模块应满足护栏",
    "adapters": "cloakbrowser 保留在内核，本表仅覆盖外挂包，解耦后可纳入",
}


def _iter_python_files(root: Path) -> Iterator[Path]:
    """遍历目录下的 Python 源文件，跳过字节码缓存。

    :param root: 起始目录
    :return: Python 源文件路径的迭代器
    """
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        yield path


def _imported_top_level_packages(path: Path) -> Set[str]:
    """解析单个源文件里被 import 的第三方顶层包名。

    只取 import 语句的第一段：``from langchain_core.messages import X`` 记作
    ``langchain_core``。语法错误的文件返回空集合，由既有语法检查负责报告。

    :param path: 源文件路径
    :return: 顶层包名集合
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return set()

    packages: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                packages.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            # 相对 import 的 module 为 None 或 level > 0，均属包内引用
            if node.level == 0 and node.module:
                packages.add(node.module.split(".", 1)[0])
    return packages


def _violations_under(root_name: str) -> list[Tuple[str, str]]:
    """收集指定内核目录下对外挂包的引用。

    :param root_name: 相对 ``app/`` 的目录名
    :return: (相对路径, 被引用的外挂包) 二元组列表
    """
    root = APP_ROOT / root_name
    found: list[Tuple[str, str]] = []
    for path in _iter_python_files(root):
        offending = _imported_top_level_packages(path) & EXTERNALIZED_DISTRIBUTIONS
        for package in sorted(offending):
            found.append((str(path.relative_to(PROJECT_ROOT)), package))
    return found


def test_guarded_kernel_roots_do_not_import_externalized_packages() -> None:
    """受护栏约束的内核目录不得 import 任何将被外挂的第三方包。"""
    violations: list[Tuple[str, str]] = []
    for root_name in sorted(GUARDED_ROOTS):
        violations.extend(_violations_under(root_name))

    assert not violations, "内核层引用了外挂第三方包：" + "; ".join(
        f"{path} -> {package}" for path, package in violations
    )


def test_guarded_roots_exist_on_disk() -> None:
    """护栏与待清偿表登记的目录必须真实存在，避免条目失效后静默失守。"""
    missing = [
        name
        for name in sorted(GUARDED_ROOTS | PENDING_ROOTS.keys())
        if not (APP_ROOT / name).is_dir()
    ]
    assert not missing, f"登记的内核目录不存在：{missing}"


def test_guarded_and_pending_roots_are_disjoint() -> None:
    """同一目录不能既受约束又列为待清偿，否则清偿状态无法判读。"""
    overlap = GUARDED_ROOTS & PENDING_ROOTS.keys()
    assert not overlap, f"目录同时出现在两张表中：{sorted(overlap)}"
