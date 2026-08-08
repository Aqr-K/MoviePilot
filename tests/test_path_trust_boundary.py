"""P0 信任边界（PR-A）单测：is_within 目录守卫、
Agent extra_context_files 路径穿越防护。

release 压缩包解压的 Zip Slip 防护由 PluginHelper.__iter_release_zip_targets
（经 __install_from_release / __async_install_from_release 调用）承担，
对应用例见 tests/test_plugin_helper.py 的
test_install_from_release_rejects_unsafe_zip_member 等测试。"""
import tempfile
from pathlib import Path

import pytest

from app.utils.system import SystemUtils
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
