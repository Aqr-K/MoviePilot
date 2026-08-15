"""插件 Python 模块的导入与缓存清理。

按已安装清单选择性扫描插件目录，只导入需要的插件包并从中筛出插件类；停止插件时把该插件
及其全部子模块从 ``sys.modules`` 摘除并让查找器缓存失效，热重载才能拿到磁盘上的新代码。

旧导入诊断由启动组合根注入，未装配时导入照常进行。
"""
import importlib
import sys
import traceback
from typing import Any, Callable, List, Optional

from app.runtime.config import settings
from app.runtime.log import logger

LegacyDiagnosticsConfigurator = Callable[..., None]
LegacyImportScanner = Callable[..., None]


def _ignore_legacy_diagnostics(**_kwargs) -> None:
    """在启动组合根尚未注入兼容服务时保持插件加载可用。"""


_legacy_diagnostics_configurator: LegacyDiagnosticsConfigurator = (
    _ignore_legacy_diagnostics
)
_legacy_import_scanner: LegacyImportScanner = _ignore_legacy_diagnostics


def configure_plugin_legacy_import_services(
    *,
    diagnostics_configurator: LegacyDiagnosticsConfigurator,
    import_scanner: LegacyImportScanner,
) -> None:
    """由启动组合根注入插件旧导入诊断服务，避免扩展层反向依赖兼容层。"""
    global _legacy_diagnostics_configurator, _legacy_import_scanner
    _legacy_diagnostics_configurator = diagnostics_configurator
    _legacy_import_scanner = import_scanner


def apply_legacy_import_diagnostics(*, enabled: bool, emitter: Callable[..., None]) -> None:
    """
    按当前开关设置插件旧导入诊断的启用状态与提示出口

    :param enabled: 是否输出旧导入提示
    :param emitter: 提示输出函数
    """
    _legacy_diagnostics_configurator(enabled=enabled, emitter=emitter)


def load_selective_plugins(pid: Optional[str], installed_plugins: List[str],
                           check_module_func: Callable) -> List[Any]:
    """
    选择性加载插件，只import符合条件的插件
    :param pid: 指定插件ID，为空则加载所有已安装插件
    :param installed_plugins: 已安装插件列表
    :param check_module_func: 模块检查函数
    :return: 插件类列表
    """
    plugins = []
    plugins_dir = settings.ROOT_PATH / "app" / "plugins"

    if not plugins_dir.exists():
        logger.warning(f"插件目录不存在：{plugins_dir}")
        return plugins

    # 确定需要加载的插件目录名称列表
    if pid:
        # 加载指定插件
        target_plugins = [pid.lower()]
    else:
        # 加载已安装插件
        target_plugins = [plugin_id.lower() for plugin_id in installed_plugins]

    if not target_plugins:
        logger.debug("没有需要加载的插件")
        return plugins

    # 扫描plugins目录
    _loaded_modules = set()
    for plugin_dir in plugins_dir.iterdir():
        if not plugin_dir.is_dir() or plugin_dir.name.startswith('_'):
            continue

        # 检查是否是需要加载的插件
        if plugin_dir.name not in target_plugins:
            logger.debug(f"跳过插件目录：{plugin_dir.name}（不在加载列表中）")
            continue

        # 检查__init__.py是否存在
        init_file = plugin_dir / "__init__.py"
        if not init_file.exists():
            logger.debug(f"跳过插件目录：{plugin_dir.name}（缺少__init__.py）")
            continue

        try:
            # 构建模块名
            module_name = f"app.plugins.{plugin_dir.name}"
            logger.debug(f"正在导入插件模块：{module_name}")

            _legacy_import_scanner(
                plugin_id=plugin_dir.name,
                plugin_dir=plugin_dir,
            )

            # 导入模块
            module = importlib.import_module(module_name)

            # 检查模块中的类
            for name, obj in module.__dict__.items():
                if name.startswith('_') or not isinstance(obj, type):
                    continue
                if name in _loaded_modules:
                    continue
                if check_module_func(obj):
                    _loaded_modules.add(name)
                    plugins.append(obj)
                    logger.debug(f"找到符合条件的插件类：{name}")
                    break

        except Exception as err:
            logger.error(f"加载插件 {plugin_dir.name} 失败：{str(err)} - {traceback.format_exc()}")

    return plugins


def clear_plugin_modules(plugin_id: Optional[str] = None) -> None:
    """
    清除插件及其所有子模块的缓存
    :param plugin_id: 插件ID
    """

    # 构建插件模块前缀
    if plugin_id:
        plugin_module_prefix = f"app.plugins.{plugin_id.lower()}"
    else:
        plugin_module_prefix = "app.plugins"

    # 收集需要删除的模块名（创建模块名列表的副本以避免迭代时修改字典）
    modules_to_remove = []
    for module_name in list(sys.modules.keys()):
        if module_name == plugin_module_prefix or module_name.startswith(plugin_module_prefix + "."):
            modules_to_remove.append(module_name)

    # 删除模块
    for module_name in modules_to_remove:
        try:
            del sys.modules[module_name]
            logger.debug(f"已清除插件模块缓存：{module_name}")
        except KeyError:
            # 模块可能已经被删除
            pass

    importlib.invalidate_caches()
    logger.debug("已清除查找器的缓存")

    if plugin_id:
        if modules_to_remove:
            logger.info(f"插件 {plugin_id} 共清除 {len(modules_to_remove)} 个模块缓存：{modules_to_remove}")
        else:
            logger.debug(f"插件 {plugin_id} 没有找到需要清除的模块缓存")
