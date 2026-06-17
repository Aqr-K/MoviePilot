# -*- coding: utf-8 -*-
"""
S5a 解耦回归测试：本地插件来源标识(local:// URL)的纯工具函数从
app.helper.plugin.PluginHelper 抽取到 app.utils.plugin_repo,
core/plugin 改用 utils,PluginHelper 保留同名静态方法委托至 utils。

验证：
  1. is_local_repo_url / make_local_repo_url 纯函数行为正确;
  2. PluginHelper 的同名静态方法委托到 utils,结果一致（插件/agent 调用方零改动）;
  3. core/plugin 的 6 处调用已改用 utils,不再经由 PluginHelper.{is_local,make_local}_repo_url;
  4. utils.plugin_repo 自身零 app 依赖（纯工具层）。
"""
from pathlib import Path
from unittest import TestCase

import app.utils.plugin_repo as plugin_repo
from app.utils.plugin_repo import LOCAL_REPO_PREFIX, is_local_repo_url, make_local_repo_url


class PluginRepoUrlTest(TestCase):

    def test_is_local_repo_url(self):
        self.assertTrue(is_local_repo_url("local://demo"))
        self.assertFalse(is_local_repo_url("https://github.com/u/r"))
        self.assertFalse(is_local_repo_url(""))
        self.assertFalse(is_local_repo_url(None))

    def test_make_local_repo_url_and_roundtrip(self):
        self.assertEqual(make_local_repo_url("demo"), f"{LOCAL_REPO_PREFIX}demo")
        # 空格等字符被转义
        self.assertEqual(make_local_repo_url("a b"), f"{LOCAL_REPO_PREFIX}a%20b")
        # path / version 参数
        self.assertEqual(make_local_repo_url("p", repo_path=Path("/a/b")), f"{LOCAL_REPO_PREFIX}p?path=/a/b")
        self.assertEqual(make_local_repo_url("p", package_version="1.0"), f"{LOCAL_REPO_PREFIX}p?version=1.0")
        # 生成的标识应被 is_local_repo_url 识别
        self.assertTrue(is_local_repo_url(make_local_repo_url("p", repo_path=Path("/x"), package_version="2")))

    def test_plugin_helper_delegates_to_utils(self):
        """PluginHelper 的同名静态方法委托到 utils,结果一致"""
        from app.helper.plugin import PluginHelper
        self.assertEqual(PluginHelper.is_local_repo_url("local://demo"), is_local_repo_url("local://demo"))
        self.assertFalse(PluginHelper.is_local_repo_url("https://x"))
        self.assertEqual(
            PluginHelper.make_local_repo_url("p", package_version="3"),
            make_local_repo_url("p", package_version="3"),
        )

    def test_core_plugin_uses_utils_not_pluginhelper_for_url(self):
        """app/core/plugin.py 不再经由 PluginHelper 调用这两个 URL 工具"""
        import app.core.plugin as plugin
        source = Path(plugin.__file__).read_text(encoding="utf-8")
        self.assertNotIn("PluginHelper.is_local_repo_url", source)
        self.assertNotIn("PluginHelper.make_local_repo_url", source)
        self.assertIn("from app.utils.plugin_repo import", source)

    def test_util_module_has_no_app_dependency(self):
        """app/utils/plugin_repo.py 为纯工具层,无 app 依赖"""
        source = Path(plugin_repo.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import app.", source)
        self.assertNotIn("from app.", source)
