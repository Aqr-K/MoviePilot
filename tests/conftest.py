"""pytest 全局引导：隔离 CONFIG_DIR、补 sites 垫片、建表、装载网络守卫。

引导与网络守卫均复用 ``app/testing`` 的共享 harness（与插件仓 conftest 同源），
引导逻辑只在 ``app/testing`` 维护一处。
"""
import sys

# 必须早于首个 import app.db（其在 import 期即按 CONFIG_PATH 连库）：prepare_backend 内部
# 先隔离 CONFIG_DIR、补 app.helper.sites 垫片，再建表。app/testing 仅依赖标准库、import 不连库，
# 故此处先 import 再调用是安全的。
from app.testing.bootstrap import prepare_backend

prepare_backend()

# 复用共享 autouse 网络守卫；同一实现亦供各插件仓 conftest import 复用，避免逐仓维护
from app.testing.network_guard import block_real_network  # noqa: E402,F401

# 已安装的真实下载器 SDK 须先于测试桩进入 sys.modules：部分测试以
# ``sys.modules.setdefault("qbittorrentapi", ...)`` 注入仅含 TorrentFilesList 的假模块供无该包的 CI 用；
# 若假桩在真包导入前先落位，会令 test_downloader_file_normalization 的
# ``from qbittorrentapi import TorrentDictionary`` 失败。已装环境下此处优先导入真包使桩 setdefault no-op，
# 未装环境走 except 由桩兜底。
for _downloader_sdk in ("qbittorrentapi", "transmission_rpc"):
    try:
        __import__(_downloader_sdk)
    except ImportError:
        pass

import pytest  # noqa: E402


@pytest.fixture
def register_demo_step():
    """注册一枚最小 ``IAuthStep`` 到全局步骤注册表（owner="demo"），fixture 退出后按 owner 卸载。

    供"装配桥读注册表"类测试用：让 ``_build_flow_service`` 能从 ``all_auth_steps()`` 看到一枚真步骤。
    """
    from app.core.auth.flow import AuthStepResult
    from app.core.auth.steps import register_auth_step, unregister_auth_steps

    class _DemoStep:
        step_id = "demo-cred-step"
        step_kind = "credential"
        priority = 50

        def applies_to(self, context):
            return context.resolved_user_id is None

        def advance(self, context, submission):
            return AuthStepResult(status="pending")

    step = _DemoStep()
    register_auth_step(step, owner="demo")
    try:
        yield step
    finally:
        unregister_auth_steps("demo")


@pytest.fixture
def make_plugin_with_steps():
    """构造一个仅声明 ``provides_auth_steps()`` 的插件替身，并经**真实** PluginManager 注册管线激活。

    返回工厂 ``make(plugin_id, steps)`` → harness；harness.activate(plugin_id) 把插件注入运行态并驱动
    ``_register_plugin_modules`` 走单 SPI 接线（register_auth_step(owner=plugin_id)）。fixture 退出时按
    owner 卸载步骤并移出运行态，避免污染 PluginManager 单例。
    """
    from app.helper.plugin_manager import PluginManager

    pm = PluginManager()
    activated: list = []

    class _StepPlugin:
        """仅声明统一认证步骤的插件替身（真实类实例，确保 ObjectUtils.check_method 识别钩子）。"""

        def __init__(self, steps):
            self._steps = steps

        def get_state(self):
            return True

        def provides_auth_steps(self):
            return self._steps

    class _Harness:
        def __init__(self, steps):
            self._steps = steps

        def activate(self, plugin_id):
            pm._running_plugins[plugin_id] = _StepPlugin(self._steps)
            pm._register_plugin_modules(plugin_id)
            if plugin_id not in activated:
                activated.append(plugin_id)
            return self

        def deactivate(self, plugin_id):
            """手动卸载并从 activated 列表移除，防止 fixture teardown 双重卸载。"""
            pm._unregister_plugin_modules([plugin_id])
            pm._running_plugins.pop(plugin_id, None)
            try:
                activated.remove(plugin_id)
            except ValueError:
                pass

    def _make(plugin_id, steps):
        return _Harness(steps)

    try:
        yield _make
    finally:
        for plugin_id in activated:
            pm._unregister_plugin_modules([plugin_id])
            pm._running_plugins.pop(plugin_id, None)


def _report_session_cleanup_error(name: str, err: Exception) -> None:
    """测试收尾清理失败只记录诊断，不覆盖原始 pytest 退出状态。"""
    sys.stderr.write(f"\npytest session cleanup failed: {name}: {err!r}\n")


def pytest_sessionfinish(session, exitstatus):
    """释放测试过程中按需创建的全局后台资源，避免解释器退出时等待非 daemon worker。"""
    try:
        from app.agent.tools.base import shutdown_blocking_executors

        shutdown_blocking_executors(cancel_futures=True)
    except Exception as err:
        _report_session_cleanup_error("agent blocking executors", err)

    try:
        from app.core.thread import ThreadHelper
        from app.utils.singleton import Singleton

        helper = Singleton._instances.get((ThreadHelper, (), frozenset()))
        if helper:
            helper.shutdown()
    except Exception as err:
        _report_session_cleanup_error("thread helper", err)

    try:
        from app.log import LoggerManager

        LoggerManager.shutdown()
    except Exception as err:
        _report_session_cleanup_error("logger manager", err)
