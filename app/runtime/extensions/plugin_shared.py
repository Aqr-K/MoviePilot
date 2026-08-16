"""插件管理器各功能域共享的依赖与可注入服务。

功能域按模块属性访问这里的名字，因此启动组合根注入实现后各域立即取到最新值。
本模块置于插件管理器包之外，使各功能域不反向依赖包入口。
"""
from typing import Callable

from watchfiles import watch
from app.adapters.external.market import PluginHelper
from app.db.oper.plugindata import PluginDataOper
from app.db.oper.systemconfig import SystemConfigOper
from app.runtime.config import settings

__all__ = [
    "PluginDataOper",
    "PluginHelper",
    "SystemConfigOper",
    "configure_plugin_install_reporter",
    "configure_plugin_legacy_import_services",
    "configure_plugin_resource_import_preparer",
    "configure_site_auth_level_provider",
    "settings",
    "watch",
]


LegacyDiagnosticsConfigurator = Callable[..., None]
LegacyImportScanner = Callable[..., None]
LegacyPluginImportPreparer = Callable[..., None]
PluginInstallReporter = Callable[..., None]
SiteAuthLevelProvider = Callable[[], int]


def _ignore_legacy_diagnostics(**_kwargs) -> None:
    """在启动组合根尚未注入兼容服务时保持插件加载可用。"""


def _ignore_plugin_resource_imports(**_kwargs) -> None:
    """未进入应用启动组合时不主动创建进程级宿主资源。"""


def _unavailable_site_auth_level() -> int:
    """站点能力尚未装配时返回未认证等级。"""
    return 0


_legacy_diagnostics_configurator: LegacyDiagnosticsConfigurator = (
    _ignore_legacy_diagnostics
)
_legacy_import_scanner: LegacyImportScanner = _ignore_legacy_diagnostics
_legacy_plugin_import_preparer: LegacyPluginImportPreparer = (
    _ignore_plugin_resource_imports
)
_plugin_install_reporter: PluginInstallReporter = _ignore_legacy_diagnostics
_site_auth_level_provider: SiteAuthLevelProvider = _unavailable_site_auth_level


def configure_plugin_legacy_import_services(
    *,
    diagnostics_configurator: LegacyDiagnosticsConfigurator,
    import_scanner: LegacyImportScanner,
) -> None:
    """由启动组合根注入插件旧导入诊断服务，避免扩展层反向依赖兼容层。"""
    global _legacy_diagnostics_configurator, _legacy_import_scanner
    _legacy_diagnostics_configurator = diagnostics_configurator
    _legacy_import_scanner = import_scanner


def configure_plugin_resource_import_preparer(
    preparer: LegacyPluginImportPreparer,
) -> None:
    """注入旧插件导入前的宿主资源准备器。"""
    global _legacy_plugin_import_preparer
    _legacy_plugin_import_preparer = preparer


def configure_plugin_install_reporter(reporter: PluginInstallReporter) -> None:
    """由启动组合根注入插件安装上报器，避免扩展层依赖远程服务。"""
    global _plugin_install_reporter
    _plugin_install_reporter = reporter


def configure_site_auth_level_provider(provider: SiteAuthLevelProvider) -> None:
    """由启动组合根注入站点认证等级，避免扩展运行时依赖应用服务。"""
    global _site_auth_level_provider
    _site_auth_level_provider = provider

