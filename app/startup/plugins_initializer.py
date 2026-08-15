from app.runtime.compat.diagnostics import (
    configure_legacy_import_diagnostics,
    scan_plugin_legacy_imports,
)
from app.runtime.config import global_vars
from app.runtime.extensions.plugin_manager import (
    PluginManager,
    configure_plugin_legacy_import_services,
    configure_site_auth_level_provider,
)
from app.runtime.extensions.plugin_watcher import PluginWatcher
from app.application.plugin_market import (
    PluginMarket,
    configure_plugin_install_reporter,
)
from app.application.site.sites import SitesHelper  # pylint: disable=no-name-in-module
from app.adapters.external.server import MoviePilotServerHelper
from app.runtime.log import logger


def _configure_plugin_services() -> None:
    """把兼容诊断和站点认证等级装配到插件管理器，把远程上报装配到插件市场服务。"""
    configure_plugin_legacy_import_services(
        diagnostics_configurator=configure_legacy_import_diagnostics,
        import_scanner=scan_plugin_legacy_imports,
    )
    configure_plugin_install_reporter(MoviePilotServerHelper.install_plugin_reg)
    configure_site_auth_level_provider(lambda: SitesHelper().auth_level)


async def sync_plugins() -> bool:
    """
    初始化安装插件，并动态注册后台任务及API
    """
    try:
        _configure_plugin_services()
        loop = global_vars.loop
        plugin_manager = PluginManager()
        plugin_market = PluginMarket(plugin_manager)

        sync_result = await execute_task(loop, plugin_market.sync, "插件同步到本地")
        resolved_dependencies = await execute_task(loop, plugin_market.install_plugin_missing_dependencies,
                                                   "缺失依赖项安装")
        # 判断是否需要进行插件初始化
        if not sync_result and not resolved_dependencies:
            logger.debug("没有新的插件同步到本地或缺失依赖项需要安装")
            return False

        # 继续执行后续的插件初始化步骤
        logger.info("正在重新初始化插件")
        # 重新初始化插件
        plugin_manager.init_config()
        # 重新注册插件API
        register_plugin_api()
        logger.info("所有插件初始化完成")
        return True
    except Exception as e:
        logger.error(f"插件初始化过程中出现异常: {e}")
        return False


async def execute_task(loop, task_func, task_name):
    """
    执行后台任务
    """
    try:
        result = await loop.run_in_executor(None, task_func)
        if isinstance(result, list) and result:
            logger.debug(f"{task_name} 已完成，共处理 {len(result)} 个项目")
        else:
            logger.debug(f"没有新的 {task_name} 需要处理")
        return result
    except Exception as e:
        logger.error(f"{task_name} 时发生错误：{e}", exc_info=True)
        return []


def register_plugin_api():
    """
    插件启动后注册插件API
    """
    from app.api.endpoints import plugin
    plugin.register_plugin_api()


def init_plugins():
    """
    初始化插件
    """
    _configure_plugin_services()
    # 热加载监视器按 DEV / PLUGIN_AUTO_RELOAD 自行决定是否起线程
    PluginWatcher().start_monitor()
    PluginManager().start()
    register_plugin_api()


def stop_plugins():
    """
    停止插件
    """
    # 插件运行态与热加载监视器是两个独立子系统，任一停止失败都不得连累另一个
    try:
        PluginManager().stop()
    except Exception as e:
        logger.error(f"停止插件时发生错误：{e}", exc_info=True)
    try:
        PluginWatcher().stop_monitor()
    except Exception as e:
        logger.error(f"停止插件文件监视器时发生错误：{e}", exc_info=True)
