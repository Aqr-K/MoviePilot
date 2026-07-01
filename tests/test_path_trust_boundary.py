"""P0 信任边界（PR-A）单测：is_within 目录守卫、release 解压 Zip Slip 防护、
Agent extra_context_files 路径穿越防护。"""
import tempfile
from pathlib import Path

import pytest

from app.utils.system import SystemUtils
from app.helper.plugin import plan_release_zip_extraction
from app.agent.runtime import AgentRuntimeManager, AgentRuntimeConfigError


class TestIsWithin:
    """SystemUtils.is_within 目录包含判定。"""

    def test_child_path_is_within(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            assert SystemUtils.is_within(base, base / "a" / "b.txt") is True

    def test_base_itself_is_within(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            assert SystemUtils.is_within(base, base) is True

    def test_parent_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "sub"
            base.mkdir()
            assert SystemUtils.is_within(base, base / ".." / ".." / "etc" / "passwd") is False

    def test_absolute_outside_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            assert SystemUtils.is_within(Path(d), Path("/etc/passwd")) is False

    def test_sibling_prefix_not_confused(self):
        # /x/foobar 与 /x/foobar_evil 前缀相似，但后者不在前者内（按路径分段判定）
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "foobar"
            base.mkdir()
            sibling = Path(d) / "foobar_evil"
            sibling.mkdir()
            assert SystemUtils.is_within(base, sibling / "x") is False


class TestPlanReleaseZipExtraction:
    """plugin.plan_release_zip_extraction 的路径规划与 Zip Slip 防护。"""

    def test_normal_zip_strips_common_prefix(self):
        names = ["MyPlugin/__init__.py", "MyPlugin/sub/x.py"]
        planned, err = plan_release_zip_extraction(names, Path("/opt/app/plugins/myplugin"))
        assert err is None
        rels = sorted(rel for _, rel in planned)
        assert rels == ["__init__.py", "sub/x.py"]

    def test_zip_slip_traversal_is_rejected(self):
        names = ["MyPlugin/__init__.py", "MyPlugin/../../../../etc/evil.py"]
        planned, err = plan_release_zip_extraction(names, Path("/opt/app/plugins/myplugin"))
        assert err is not None
        assert planned == []

    def test_absolute_entry_mixed_is_rejected(self):
        # 绝对路径条目与普通条目混合时公共前缀不被剥离，绝对路径逃逸应被拦截
        names = ["MyPlugin/__init__.py", "/etc/evil.py"]
        planned, err = plan_release_zip_extraction(names, Path("/opt/app/plugins/myplugin"))
        assert err is not None
        assert planned == []

    def test_empty_namelist_is_rejected(self):
        planned, err = plan_release_zip_extraction([], Path("/opt/app/plugins/x"))
        assert err is not None
        assert planned == []


class TestRuntimeResolveRelativePath:
    """AgentRuntimeManager._resolve_relative_path 对 extra_context_files 的越界拦截。"""

    def test_relative_within_root_ok(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            resolved = AgentRuntimeManager._resolve_relative_path(root, "ctx/notes.md")
            assert SystemUtils.is_within(root, resolved)

    def test_parent_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "runtime"
            root.mkdir()
            with pytest.raises(AgentRuntimeConfigError):
                AgentRuntimeManager._resolve_relative_path(root, "../../etc/passwd")

    def test_absolute_path_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with pytest.raises(AgentRuntimeConfigError):
                AgentRuntimeManager._resolve_relative_path(Path(d), "/etc/passwd")


class TestCloneSuffixWhitelist:
    """PluginManager.clone_plugin 分身后缀白名单（防目录穿越 / 生成代码注入）。"""

    @staticmethod
    def _pm():
        from app.helper.plugin_manager import PluginManager
        # 绕过单例初始化，仅测试早退的参数校验分支（不触及 self._plugins）
        return PluginManager.__new__(PluginManager)

    def test_traversal_suffix_rejected(self):
        ok, msg = self._pm().clone_plugin("Demo", "../evil", "n", "d")
        assert ok is False
        assert "后缀" in msg

    def test_hyphen_suffix_rejected(self):
        ok, _ = self._pm().clone_plugin("Demo", "a-b", "n", "d")
        assert ok is False

    def test_injection_suffix_rejected(self):
        ok, _ = self._pm().clone_plugin("Demo", 'x"\n', "n", "d")
        assert ok is False

    def test_slash_suffix_rejected(self):
        ok, _ = self._pm().clone_plugin("Demo", "a/b", "n", "d")
        assert ok is False
