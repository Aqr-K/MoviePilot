# -*- coding: utf-8 -*-
"""
S1b 解耦回归测试：core/security 与 core/auth_bridge 通过注入式 seam 读取站点认证等级,
不再直接 import app.helper.sites（SitesHelper 为资源包拉取的编译 .so 模块,属 helper 层）。

验证：
  1. 未注册 provider 时 get_auth_level() 返回未认证默认等级（与全新 SitesHelper().auth_level 一致）;
  2. 注册 provider 后返回注入值（组合根在 lifespan 注入 lambda: SitesHelper().auth_level）;
  3. core 层不再反向依赖 helper.sites:
     - app/core/security.py 不再 import app.helper.sites;
     - app/core/auth_bridge.py 不再 import app.helper.sites;
     - app/core/auth_level.py 自身无 app.helper 依赖。
"""
from pathlib import Path
from unittest import TestCase

import app.core.auth_level as auth_level
from app.core.auth_level import DEFAULT_AUTH_LEVEL, get_auth_level, set_auth_level_provider


class CoreAuthLevelSeamTest(TestCase):

    def tearDown(self) -> None:
        # 复位全局 provider,避免测试间状态泄漏
        auth_level._provider = None

    def test_default_when_no_provider(self):
        """未注册 provider 时返回未认证默认等级 1"""
        auth_level._provider = None
        self.assertEqual(get_auth_level(), DEFAULT_AUTH_LEVEL)
        self.assertEqual(DEFAULT_AUTH_LEVEL, 1)

    def test_injected_provider_is_used(self):
        """注册 provider 后 get_auth_level() 返回注入值"""
        set_auth_level_provider(lambda: 2)
        self.assertEqual(get_auth_level(), 2)

    def test_core_security_no_longer_imports_helper_sites(self):
        """app/core/security.py 不再 import app.helper.sites"""
        import app.core.security as security
        source = Path(security.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from app.helper.sites", source)
        self.assertNotIn("import app.helper.sites", source)

    def test_core_auth_bridge_no_longer_imports_helper_sites(self):
        """app/core/auth_bridge.py 不再 import app.helper.sites"""
        import app.core.auth_bridge as auth_bridge
        source = Path(auth_bridge.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from app.helper.sites", source)
        self.assertNotIn("import app.helper.sites", source)

    def test_core_plugin_no_longer_imports_helper_sites(self):
        """app/core/plugin.py 的 auth_level 读取改走 seam,不再 import app.helper.sites
        （plugin.py 仍保留 helper.server / helper.plugin,属各自独立接缝）"""
        import app.helper.plugin_manager as plugin
        source = Path(plugin.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from app.helper.sites", source)
        self.assertNotIn("import app.helper.sites", source)
        self.assertNotIn("SitesHelper", source)

    def test_seam_module_has_no_helper_dependency(self):
        """app/core/auth_level.py 自身不依赖 app.helper（方向正确）"""
        source = Path(auth_level.__file__).read_text(encoding="utf-8")
        self.assertNotIn("app.helper", source)
