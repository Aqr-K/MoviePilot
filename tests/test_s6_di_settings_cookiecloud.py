"""S6 DI #3：settings 经构造注入（CookieCloudHelper pilot），默认回退全局单例。

这是 S6 把「构造注入 + 默认回退全局」模板（#1 ThreadHelper、#2 ChainBase 8 依赖）
扩到**最广引用的全局 `settings`**（193 文件）的首个 pilot：CookieCloudHelper 不再直读
模块级 `settings`，而是经 __init__ 注入、默认回退全局单例，配置读取走 self._settings。

价值：测试可注入 fake 配置对象、不触碰全局 settings；现有 CookieCloudHelper() 无参调用
（chain/site.py:344）= 取全局单例、行为不变。
"""
import inspect
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.core.config import settings as _global_settings
from app.helper.cookiecloud import CookieCloudHelper


def _fake_settings(**overrides):
    base = dict(
        COOKIECLOUD_HOST="http://cc.example",
        COOKIECLOUD_KEY="  mykey  ",
        COOKIECLOUD_PASSWORD="  mypass  ",
        COOKIECLOUD_ENABLE_LOCAL=True,
        COOKIE_PATH=Path("/cookies"),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class CookieCloudSettingsInjectionTest(unittest.TestCase):
    def test_init_exposes_injectable_settings_defaulting_none(self):
        """__init__ 暴露 settings 形参且默认 None（不传 = 回退全局单例）。"""
        sig = inspect.signature(CookieCloudHelper.__init__)
        self.assertIn("settings", sig.parameters)
        self.assertIsNone(sig.parameters["settings"].default)

    def test_sync_reads_from_injected_settings(self):
        """注入 fake settings → 配置从 fake 读取（key/password 经 safe_strip 去空白）。"""
        helper = CookieCloudHelper(settings=_fake_settings())
        self.assertEqual("mykey", helper._key)
        self.assertEqual("mypass", helper._password)
        self.assertTrue(helper._enable_local)
        self.assertEqual(Path("/cookies"), helper._local_path)
        self.assertIn("cc.example", helper._server)

    def test_default_falls_back_to_global_settings(self):
        """不传 settings → 持有的就是全局单例（零破坏：现有无参调用行为不变）。"""
        helper = CookieCloudHelper()
        self.assertIs(_global_settings, helper._settings)


if __name__ == "__main__":
    unittest.main()
