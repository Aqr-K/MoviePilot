"""
S9b 回归：PluginManager god-object 的纯文件/AST 改写逻辑抽至 app.helper.plugin_cloner。

clone_plugin 仍是有状态编排器（保留在 PluginManager），但 4 个无状态文件改写方法
（_modify_plugin_files / _modify_python_file / _modify_federation_files /
_rename_federation_assets）抽成 plugin_cloner 的模块级**纯函数**；`_plugins` 取类名的
单处读取上提到 clone_plugin，按 original_class_name/clone_class_name 传参。

纯函数可直接对临时文件做**行为单测**（证明抽取逐字等价），不依赖 downloader/DB/集成环境。
"""
import tempfile
from pathlib import Path

from app.helper import plugin_cloner
from app.helper.plugin_manager import PluginManager

SAMPLE = '''from app.plugins import _PluginBase


class FooPlugin(_PluginBase):
    plugin_name = "Foo"
    plugin_desc = "old desc"
    plugin_config_prefix = "foo_"
    plugin_version = "1.0"
    plugin_icon = "old.png"

    def init_plugin(self, config=None):
        pass
'''


# ---- (a) 结构契约：编排器留下、纯逻辑迁出 ----

def test_clone_orchestrator_stays_helpers_moved_out():
    assert hasattr(PluginManager, "clone_plugin"), "clone_plugin 必须留在 PluginManager"
    for gone in ("_modify_plugin_files", "_modify_python_file",
                 "_modify_federation_files", "_rename_federation_assets"):
        assert not hasattr(PluginManager, gone), f"{gone} 不应在 PluginManager 上"
    for fn in ("modify_plugin_files", "modify_python_file",
               "modify_federation_files", "rename_federation_assets"):
        assert hasattr(plugin_cloner, fn), f"plugin_cloner 缺函数 {fn}"


# ---- (b) 行为单测：__init__.py 改写六项变换 ----

def test_modify_python_file_all_transforms():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "__init__.py"
        f.write_text(SAMPLE, encoding="utf-8")
        ok, msg = plugin_cloner.modify_python_file(
            f, "FooPlugin", "FooPluginBak",
            name="Foo备份", description="new desc", version="2.0", icon="new.png",
        )
        out = f.read_text(encoding="utf-8")
    assert ok, msg
    assert "class FooPluginBak(" in out and "class FooPlugin(" not in out  # 类名
    assert 'plugin_name = "Foo备份"' in out
    assert 'plugin_desc = "new desc"' in out
    assert 'plugin_config_prefix = "foopluginbak_"' in out               # 前缀=分身类名小写
    assert 'plugin_version = "2.0"' in out
    assert 'plugin_icon = "new.png"' in out
    assert "is_clone = True" in out                                       # 分身标志注入


def test_modify_python_file_keeps_icon_when_not_provided():
    """未提供 icon 时保留原图标（与原方法分支一致）。"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "__init__.py"
        f.write_text(SAMPLE, encoding="utf-8")
        ok, _ = plugin_cloner.modify_python_file(
            f, "FooPlugin", "FooPluginBak", name="X", description="Y", version=None, icon=None,
        )
        out = f.read_text(encoding="utf-8")
    assert ok
    assert 'plugin_icon = "old.png"' in out          # 原图标不变
    assert 'plugin_version = "1.0"' in out            # 未传 version → 原值不变


# ---- (c) 联邦前端文件改写 + 资源重命名 ----

def test_modify_federation_files_and_rename():
    with tempfile.TemporaryDirectory() as d:
        dist = Path(d) / "dist"
        dist.mkdir()
        # 联邦构建产物文件名含小写类名（rename_federation_assets 按 .lower() 匹配，与原方法逐字一致）
        js = dist / "fooplugin.umd.js"
        js.write_text("export const FooPlugin = 1; const k = 'FooPlugin';", encoding="utf-8")
        ok, msg = plugin_cloner.modify_federation_files(dist, "FooPlugin", "FooPluginBak")
        assert ok, msg
        # 资源文件按小写类名重命名 fooplugin -> foopluginbak
        renamed = dist / "foopluginbak.umd.js"
        assert renamed.exists(), f"联邦资源未重命名: {[p.name for p in dist.iterdir()]}"
        # 内容中的类名引用被精确改写
        assert renamed.read_text(encoding="utf-8") == "export const FooPluginBak = 1; const k = 'FooPluginBak';"
