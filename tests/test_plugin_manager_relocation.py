"""
S9 回归：PluginManager god-object 迁出 core → app.helper.plugin_manager。

原 app/core/plugin.py（2026 行 god-object）迁至 helper 层（relocate），
core/plugin.py 留 PEP 562 惰性 __getattr__ 兼容垫片。验证：
- 迁移消除「god-object 在 core」+ core 顶层 app.db 反向边清零（plugin.py 是最后 2 条所在）；
- 守护 core↔helper 解环里程碑：core 顶层零 app.helper，垫片惰性不在 import-time 拉 helper；
- 新旧路径解析为同一 PluginManager 类（向后兼容，仓内 0 外部插件引用，纯防御性垫片）。
"""
import ast
import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
CORE_DIR = REPO_DIR / "app" / "core"
NEW = REPO_DIR / "app" / "helper" / "plugin_manager.py"
SHIM = CORE_DIR / "plugin.py"


def _top_level_imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
        elif isinstance(node, ast.Import):
            mods.extend(alias.name for alias in node.names)
    return mods


def test_pluginmanager_relocated_to_helper():
    assert NEW.exists(), "PluginManager 应已迁至 app/helper/plugin_manager.py"
    assert "class PluginManager(" in NEW.read_text(encoding="utf-8")


def test_core_plugin_is_lazy_shim():
    """core/plugin.py 仅为惰性垫片：顶层无 app.helper，提供 __getattr__。"""
    mods = _top_level_imports(SHIM)
    assert not any(m.startswith("app.helper") for m in mods), f"垫片顶层不应 import helper: {mods}"
    assert "def __getattr__" in SHIM.read_text(encoding="utf-8")


def test_core_has_no_top_level_helper_or_db():
    """里程碑守护：core/*.py 顶层零 app.helper（解环）+ 零 app.db（plugin.py 迁出后）。"""
    bad = {}
    for py in CORE_DIR.glob("*.py"):
        edges = [m for m in _top_level_imports(py) if m.startswith("app.helper") or m.startswith("app.db")]
        if edges:
            bad[py.name] = edges
    assert not bad, f"core 顶层仍有 helper/db 反向边: {bad}"


def test_shim_lazy_and_identity():
    """全新解释器：import app.core.plugin 不拉 helper；新旧路径同一类。"""
    code = (
        "import sys, app.core.plugin as cp\n"
        "assert 'app.helper.plugin_manager' not in sys.modules, '垫片非惰性'\n"
        "PM = cp.PluginManager\n"  # 触发 __getattr__
        "import app.helper.plugin_manager as pm\n"
        "assert PM is pm.PluginManager, '新旧路径类不同一'\n"
        "print('OK')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=str(REPO_DIR), capture_output=True, text=True)
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "OK" in r.stdout


def test_importing_core_event_does_not_pull_plugin_manager():
    """里程碑：导入 core.event 不在 import-time 拉 helper.plugin_manager（其引用为 lazy）。"""
    code = (
        "import sys, app.core.event\n"
        "assert 'app.helper.plugin_manager' not in sys.modules, 'core.event 拉了 plugin_manager'\n"
        "print('OK')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=str(REPO_DIR), capture_output=True, text=True)
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "OK" in r.stdout
