import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


def load_publish_plugin_module() -> Any:
    """加载插件发布脚本模块。"""
    script_path = (
        Path(__file__).resolve().parents[1]
        / "skills"
        / "publish-moviepilot-plugin"
        / "scripts"
        / "publish_plugin.py"
    )
    spec = importlib.util.spec_from_file_location("publish_plugin_skill", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_collect_local_files_excludes_secrets_and_keeps_dist(tmp_path: Path) -> None:
    """收集本地插件文件时应排除敏感文件并保留前端构建产物。"""
    module = load_publish_plugin_module()
    plugin_dir = tmp_path / "plugins.v2" / "myplugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text("class MyPlugin:\n    pass\n", encoding="utf-8")
    (plugin_dir / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (plugin_dir / "dist" / "assets").mkdir(parents=True)
    (plugin_dir / "dist" / "assets" / "remoteEntry.js").write_text(
        "export default {};\n",
        encoding="utf-8",
    )

    layout = module.Layout(package_file="package.v2.json", plugin_root="plugins.v2")
    files, rejected = module.collect_local_files(
        tmp_path,
        layout,
        "MyPlugin",
        list(module.DEFAULT_EXCLUDES),
        [],
    )

    assert "plugins.v2/myplugin/__init__.py" in files
    assert "plugins.v2/myplugin/dist/assets/remoteEntry.js" in files
    assert rejected == {"plugins.v2/myplugin/.env": ".env"}


def test_merge_package_content_preserves_other_plugins() -> None:
    """合并 package 文件时只更新目标插件条目。"""
    module = load_publish_plugin_module()
    remote_content = json.dumps(
        {
            "OtherPlugin": {"name": "其他插件", "version": "1.0.0"},
            "MyPlugin": {"name": "旧插件", "version": "0.9.0"},
        },
        ensure_ascii=False,
    ).encode("utf-8")

    merged = module.merge_package_content(
        remote_content,
        "MyPlugin",
        {"name": "新插件", "version": "1.0.0"},
    )
    package_data = json.loads(merged.decode("utf-8"))

    assert package_data["OtherPlugin"] == {"name": "其他插件", "version": "1.0.0"}
    assert package_data["MyPlugin"] == {"name": "新插件", "version": "1.0.0"}
