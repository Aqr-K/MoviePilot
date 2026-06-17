"""
S1d / P1 收尾：移除 core/auth_bridge 的 2 条直接 core→db 顶层反向边。

- `User`（仅用作类型注解）→ TYPE_CHECKING 块 + 引号前向引用；
- `SystemConfigOper`（调用期使用）→ build_token_response 内函数级惰性导入。

auth_bridge.py 自身顶层 app.db 清零。注意：导入 auth_bridge 仍会经其它 core
依赖传递拉起 app.db —— 完整 core db-free 是跨多文件工程（plugin.py 剩余的 2 条
core→db 边由 S9 把 PluginManager 迁出 core 时消除），本 PR 仅清本文件的直接边。
"""
import ast
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
AB = REPO_DIR / "app" / "core" / "auth_bridge.py"


def _top_level_imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
        elif isinstance(node, ast.Import):
            mods.extend(alias.name for alias in node.names)
    return mods


def test_auth_bridge_no_top_level_db_import():
    bad = [m for m in _top_level_imports(AB) if m.startswith("app.db")]
    assert not bad, f"auth_bridge 顶层不应直接 import app.db: {bad}"


def test_user_is_type_only_and_systemconfig_lazy():
    src = AB.read_text(encoding="utf-8")
    # User 仅在 TYPE_CHECKING 下导入（类型专用，运行期不拉 db.models.user）
    assert "if TYPE_CHECKING:" in src and "from app.db.models.user import User" in src
    # SystemConfigOper 的导入必须在函数体内（缩进 = 惰性）
    lines = [ln for ln in src.splitlines() if "from app.db.systemconfig_oper import SystemConfigOper" in ln]
    assert lines and all(ln.startswith(" ") for ln in lines), lines


def test_ticket_roundtrip_and_one_time():
    """db-free 路径（票据存取）行为未变。"""
    import app.core.auth_bridge as ab

    assert callable(ab.build_token_response)  # 引号注解未破坏函数定义
    ticket = ab.create_plugin_auth_ticket(user_id=7, provider_id="probe")
    data = ab.consume_plugin_auth_ticket(ticket)
    assert data and data["user_id"] == 7 and data["provider_id"] == "probe"
    assert ab.consume_plugin_auth_ticket(ticket) is None  # 一次性票据
