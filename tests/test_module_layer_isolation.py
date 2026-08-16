"""模块层不得反向依赖 chain 层。

chain 通过 ``run_module`` 向下分发到模块。模块再去调 chain，就会在一次分发的执行过程中
重新进入分发：``run_module("recommend_name")`` → 模块 → ``run_module("tmdb_episodes")``。
这既让模块脱离整条链无法单测，也把模块和某个具体数据源绑死。

需要上游数据时，正确做法是由调用方备好后传入——``transfer`` 一直是这么做的，它的
``episodes_info`` 由 ``app/chain/transfer.py`` 取好再传。

架构门禁（``tests/test_architecture_dependencies.py``）不覆盖这条：``app.modules`` 不在
它的分层前缀表里。
"""
import ast
import pathlib
from typing import Dict, List, Set

MODULES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "app" / "modules"

# 已知违例及其原因，出现新的即失败
KNOWN_CHAIN_DEPENDENCIES: Dict[str, str] = {
    "enrichment/subtitle": "轮询下载目录出现，依赖 StorageChain 的文件项查询",
}


def chain_importers() -> Dict[str, Set[str]]:
    """
    扫描模块层对 chain 层的静态导入

    :return: {模块相对路径: {被导入的 chain 模块, ...}}
    """
    found: Dict[str, Set[str]] = {}
    for path in sorted(MODULES_ROOT.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app.chain"):
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names
                                if alias.name.startswith("app.chain"))
        if imported:
            relative = path.relative_to(MODULES_ROOT).parent.as_posix()
            found.setdefault(relative, set()).update(imported)
    return found


def test_no_module_depends_on_a_chain():
    """模块层不得导入 chain，已知违例须显式登记。"""
    unexpected: List[str] = [
        f"{module} -> {sorted(chains)}"
        for module, chains in chain_importers().items()
        if module not in KNOWN_CHAIN_DEPENDENCIES
    ]

    assert unexpected == []


def test_every_known_violation_still_exists():
    """已登记的违例修好后要从表里摘掉，不留过期条目。"""
    stale = set(KNOWN_CHAIN_DEPENDENCIES) - set(chain_importers())

    assert stale == set()


def test_the_file_manager_no_longer_reaches_into_a_chain():
    """文件整理模块不再回调 chain 取剧集信息。"""
    assert "filemanager" not in chain_importers()
