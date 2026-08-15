"""插件市场应用服务。

从远程仓库和本地插件仓库拉取插件索引，按包版本与主系统版本判定兼容性，合并去重后
输出统一的插件清单；并据此把缺失或过期的插件及其依赖安装到运行目录。插件的运行态
注册表由 PluginManager 提供，本服务只读取其中的插件类与运行实例。
"""

import asyncio
import concurrent
import concurrent.futures
import importlib.util
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple

from app import schemas
from app.adapters.external.market import PluginHelper, VERSION_BACKWARD_COMPATIBLE_FLAGS
from app.adapters.system.host import SystemUtils
from app.db.oper.systemconfig import SystemConfigOper
from app.foundation.reflection import ObjectUtils
from app.foundation.version import compare_version
from app.runtime.cache import fresh, async_fresh
from app.runtime.config import settings
from app.runtime.extensions.plugin_auth import set_and_check_auth_level
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.log import logger
from app.schemas.types import SystemConfigKey

PluginInstallReporter = Callable[..., None]


def _ignore_plugin_install(**_kwargs) -> None:
    """在启动组合根尚未注入上报器时保持插件安装可用。"""


_plugin_install_reporter: PluginInstallReporter = _ignore_plugin_install


def configure_plugin_install_reporter(reporter: PluginInstallReporter) -> None:
    """由启动组合根注入插件安装上报器，避免应用服务直接依赖远程服务。"""
    global _plugin_install_reporter
    _plugin_install_reporter = reporter


class PluginMarket:
    """插件市场服务"""

    def __init__(self, plugin_manager: Optional[PluginManager] = None):
        """绑定插件运行态注册表，未指定时使用进程内的插件管理器。"""
        self._plugin_manager = plugin_manager or PluginManager()

    def sync(self) -> List[str]:
        """
        安装本地不存在或需要更新的插件
        """

        def install_plugin(plugin):
            start_time = time.time()
            state, msg = PluginHelper().install(pid=plugin.id, repo_url=plugin.repo_url, force_install=True)
            elapsed_time = time.time() - start_time
            if state:
                _plugin_install_reporter(
                    plugin_id=plugin.id,
                    repo_url=plugin.repo_url,
                )
                logger.info(
                    f"插件 {plugin.plugin_name} 安装成功，版本：{plugin.plugin_version}，耗时：{elapsed_time:.2f} 秒")
                sync_plugins.append(plugin.id)
            else:
                logger.error(
                    f"插件 {plugin.plugin_name} v{plugin.plugin_version} 安装失败：{msg}，耗时：{elapsed_time:.2f} 秒")
                failed_plugins.append(plugin.id)

        if SystemUtils.is_frozen():
            return []

        # 获取已安装插件列表
        install_plugins = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 获取远程和本地仓库来源插件列表
        online_plugins = self.get_online_plugins()
        local_repo_plugins = self.get_local_repo_plugins()
        candidate_plugins = self.process_plugins_list(online_plugins + local_repo_plugins, []) \
            if online_plugins or local_repo_plugins else []
        # 确定需要安装的插件
        plugins_to_install = [
            plugin for plugin in candidate_plugins
            if plugin.id in install_plugins
            and plugin.system_version_compatible is not False
            and not self.is_plugin_exists(plugin.id, plugin.plugin_version)
        ]

        if not plugins_to_install:
            return []
        logger.info("开始安装第三方插件...")
        sync_plugins = []
        failed_plugins = []

        # 使用 ThreadPoolExecutor 进行并发安装
        total_start_time = time.time()
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(install_plugin, plugin): plugin
                for plugin in plugins_to_install
            }
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error(f"插件 {plugin.plugin_name} 安装过程中出现异常: {exc}")

        total_elapsed_time = time.time() - total_start_time
        logger.info(
            f"第三方插件安装完成，成功：{len(sync_plugins)} 个，"
            f"失败：{len(failed_plugins)} 个，总耗时：{total_elapsed_time:.2f} 秒"
        )
        return sync_plugins

    @staticmethod
    def install_plugin_missing_dependencies() -> List[str]:
        """
        安装插件中缺失或不兼容的依赖项
        """
        pluginhelper = PluginHelper()
        # 第一步：获取需要安装的依赖项列表
        missing_dependencies = pluginhelper.find_missing_dependencies()
        if not missing_dependencies:
            return missing_dependencies
        logger.debug(f"检测到缺失的依赖项: {missing_dependencies}")
        logger.info(f"开始安装缺失的依赖项，共 {len(missing_dependencies)} 个...")
        # 第二步：安装依赖项并返回结果
        total_start_time = time.time()
        success, message = pluginhelper.install_dependencies(missing_dependencies)
        total_elapsed_time = time.time() - total_start_time
        if success:
            logger.info(f"已完成 {len(missing_dependencies)} 个依赖项安装，总耗时：{total_elapsed_time:.2f} 秒")
        else:
            logger.warning(f"存在缺失依赖项安装失败，请尝试手动安装，总耗时：{total_elapsed_time:.2f} 秒")
        return missing_dependencies

    def get_online_plugins(self, force: bool = False) -> List[schemas.Plugin]:
        """
        获取所有在线插件信息
        """
        if not settings.PLUGIN_MARKET:
            return []

        # 拉取当前索引及可扫描的旧索引；旧条目可用当前版本 false 显式排除。
        compatible_flags = (
            [settings.VERSION_FLAG] + VERSION_BACKWARD_COMPATIBLE_FLAGS.get(settings.VERSION_FLAG, [])
            if settings.VERSION_FLAG else []
        )
        markets = [m for m in settings.PLUGIN_MARKET.split(",") if m]

        # 使用多线程获取线上插件
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # future -> (market_index, is_higher, flag_priority)
            futures_meta: Dict[concurrent.futures.Future, Tuple[int, bool, int]] = {}
            for market_index, m in enumerate(markets):
                # 默认索引只展示声明 V2 或当前版本兼容的共享实现。
                base_future = executor.submit(self.get_plugins_from_market, m, None, force)
                futures_meta[base_future] = (market_index, False, 0)
                # 提交当前专用索引（如 v3）及可扫描的旧索引（如 v2）。
                for flag_priority, flag in enumerate(compatible_flags):
                    higher_future = executor.submit(self.get_plugins_from_market, m, flag, force)
                    futures_meta[higher_future] = (market_index, True, flag_priority)

            # 收集结果，按市场顺序、高版本优先、兼容版本优先级排序，保证去重时优先保留高版本来源
            collected: List[Tuple[int, bool, int, List[schemas.Plugin]]] = []
            for future in concurrent.futures.as_completed(futures_meta):
                plugins = future.result()
                market_index, is_higher, flag_priority = futures_meta[future]
                collected.append((market_index, is_higher, flag_priority, plugins or []))

        collected.sort(key=lambda item: (item[0], 0 if item[1] else 1, item[2]))
        higher_version_plugins: List[schemas.Plugin] = []
        base_version_plugins: List[schemas.Plugin] = []
        for _market_index, is_higher, _flag_priority, plugins in collected:
            if not plugins:
                continue
            if is_higher:
                higher_version_plugins.extend(plugins)
            else:
                base_version_plugins.extend(plugins)

        result = self.process_plugins_list(higher_version_plugins, base_version_plugins)
        logger.info(f"获取到 {len(result)} 个线上插件")
        return result

    async def async_get_online_plugins(
            self,
            force: bool = False,
            progress_callback: Optional[Callable[..., None]] = None,
    ) -> List[schemas.Plugin]:
        """
        异步获取所有在线插件信息
        :param force: 是否强制刷新（忽略缓存）
        :param progress_callback: 定时服务进度更新回调
        """
        if not settings.PLUGIN_MARKET:
            if progress_callback:
                progress_callback(value=100, text="未配置插件市场，跳过刷新")
            return []

        async def fetch_market(
                market: str,
                package_version: Optional[str],
                result_version: str,
                task_index: int,
        ) -> Tuple[int, str, List[schemas.Plugin]]:
            """
            获取单个市场版本的插件列表并保留结果分组。
            """
            plugins = await self.async_get_plugins_from_market(
                market,
                package_version,
                force,
            )
            return task_index, result_version, plugins or []

        higher_version_plugins = []
        base_version_plugins = []
        tasks = []

        # 拉取当前索引及可扫描的旧索引；旧条目可用当前版本 false 显式排除。
        compatible_flags = (
            [settings.VERSION_FLAG] + VERSION_BACKWARD_COMPATIBLE_FLAGS.get(settings.VERSION_FLAG, [])
            if settings.VERSION_FLAG else []
        )
        for market in settings.PLUGIN_MARKET.split(","):
            if not market:
                continue
            tasks.append(
                asyncio.create_task(
                    fetch_market(market, None, "base_version", len(tasks))
                )
            )
            for flag in compatible_flags:
                tasks.append(
                    asyncio.create_task(
                        fetch_market(
                            market,
                            flag,
                            "higher_version",
                            len(tasks),
                        )
                    )
                )

        if tasks:
            total_tasks = len(tasks)
            finished_tasks = 0
            task_results = {}
            if progress_callback:
                progress_callback(
                    value=0,
                    text=f"开始刷新插件市场，共 {total_tasks} 个请求 ...",
                    data={"total": total_tasks, "finished": 0},
                )
            for completed_task in asyncio.as_completed(tasks):
                try:
                    task_index, version, plugins = await completed_task
                    task_results[task_index] = (version, plugins)
                except Exception as err:
                    logger.error(f"获取插件市场数据失败：{str(err)}")
                finished_tasks += 1
                if progress_callback:
                    progress_callback(
                        value=finished_tasks / total_tasks * 100,
                        text=(
                            f"插件市场请求"
                            f"（{finished_tasks}/{total_tasks}）处理完成"
                        ),
                        data={"total": total_tasks, "finished": finished_tasks},
                    )
            for task_index in sorted(task_results):
                version, plugins = task_results[task_index]
                if plugins:
                    if version == "higher_version":
                        higher_version_plugins.extend(plugins)
                    else:
                        base_version_plugins.extend(plugins)

        result = self.process_plugins_list(higher_version_plugins, base_version_plugins)
        logger.info(f"获取到 {len(result)} 个线上插件")
        if progress_callback:
            progress_callback(value=100, text="插件市场缓存刷新完成")
        return result

    def get_plugins_from_market(self, market: str,
                                package_version: Optional[str] = None,
                                force: bool = False) -> Optional[List[schemas.Plugin]]:
        """
        从指定的市场获取插件信息
        :param market: 市场的 URL 或标识
        :param package_version: 首选插件版本 (如 "v2", "v3")，如果不指定则获取 v1 版本
        :param force: 是否强制刷新（忽略缓存）
        :return: 返回插件的列表，若获取失败返回 []
        """
        if not market:
            return []
        # 已安装插件
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 获取在线插件
        with fresh(force):
            online_plugins = PluginHelper().get_plugins(market, package_version)
        if online_plugins is None:
            logger.warning(
                f"获取{package_version if package_version else ''}插件库失败：{market}，请检查 GitHub 网络连接")
            return []
        ret_plugins = []
        add_time = len(online_plugins)
        for pid, plugin_info in online_plugins.items():
            plugin = self._process_plugin_info(pid, plugin_info, market, installed_apps, add_time, package_version)
            if plugin:
                ret_plugins.append(plugin)
            add_time -= 1

        return ret_plugins

    async def async_get_plugins_from_market(self, market: str,
                                            package_version: Optional[str] = None,
                                            force: bool = False) -> Optional[List[schemas.Plugin]]:
        """
        异步从指定的市场获取插件信息
        :param market: 市场的 URL 或标识
        :param package_version: 首选插件版本 (如 "v2", "v3")，如果不指定则获取 v1 版本
        :param force: 是否强制刷新（忽略缓存）
        :return: 返回插件的列表，若获取失败返回 []
        """
        if not market:
            return []
        # 已安装插件
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        # 获取在线插件
        async with async_fresh(force):
            online_plugins = await PluginHelper().async_get_plugins(market, package_version)
        if online_plugins is None:
            logger.warning(
                f"获取{package_version if package_version else ''}插件库失败：{market}，请检查 GitHub 网络连接")
            return []
        ret_plugins = []
        add_time = len(online_plugins)
        for pid, plugin_info in online_plugins.items():
            plugin = self._process_plugin_info(pid, plugin_info, market, installed_apps, add_time, package_version)
            if plugin:
                ret_plugins.append(plugin)
            add_time -= 1

        return ret_plugins

    def get_local_repo_plugins(self) -> List[schemas.Plugin]:
        """
        获取本地插件仓库目录中的插件信息
        """
        plugins = []
        installed_apps = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        local_candidates = PluginHelper().get_local_plugin_candidates()
        if not local_candidates:
            return []
        for pid, plugin_info in local_candidates.items():
            package_version = plugin_info.get("package_version")
            plugin = self._process_plugin_info(
                pid=pid,
                plugin_info=plugin_info,
                market=PluginHelper.make_local_repo_url(
                    pid,
                    plugin_info.get("repo_path"),
                    package_version
                ),
                installed_apps=installed_apps,
                add_time=0,
                package_version=package_version
            )
            if not plugin:
                continue
            plugin.is_local = True
            plugins.append(plugin)

        plugins.sort(key=lambda x: x.plugin_order if hasattr(x, "plugin_order") else 0)
        logger.info(f"获取到 {len(plugins)} 个本地插件")
        return plugins

    def is_plugin_exists(self, pid: str, version: str = None) -> bool:
        """
        判断插件是否存在，并满足版本要求(有传入version时)
        :param pid: 插件ID
        :param version: 插件版本
        """
        if not pid:
            return False
        try:
            # 构建包名
            package_name = f"app.plugins.{pid.lower()}"
            # 检查包是否存在
            spec = importlib.util.find_spec(package_name)
            package_exists = spec is not None and spec.origin is not None
            logger.debug(f"{pid} exists: {package_exists}")
            if not package_exists:
                return False

            local_version = self._plugin_manager.get_plugin_attr(pid=pid, attr="plugin_version")
            if not local_version:
                return False

            if version and not compare_version(local_version, ">=", version):
                logger.warn(f"Plugin {pid} version: {local_version} (older than version: {version})")
                return False

            return True
        except Exception as e:
            logger.debug(f"获取插件是否在本地包中存在失败，{e}")
            return False

    @staticmethod
    def process_plugins_list(higher_version_plugins: List[schemas.Plugin],
                             base_version_plugins: List[schemas.Plugin]) -> List[schemas.Plugin]:
        """
        处理插件列表：合并、去重、排序、保留最高版本
        :param higher_version_plugins: 高版本插件列表
        :param base_version_plugins: 基础版本插件列表
        :return: 处理后的插件列表
        """
        # 优先处理高版本插件
        all_plugins = []
        all_plugins.extend(higher_version_plugins)
        # 将未出现在高版本插件列表中的 v1 插件加入 all_plugins
        higher_plugin_ids = {f"{p.id}{p.plugin_version}" for p in higher_version_plugins}
        all_plugins.extend([p for p in base_version_plugins if f"{p.id}{p.plugin_version}" not in higher_plugin_ids])
        markets = [item for item in settings.PLUGIN_MARKET.split(",") if item]

        def repo_order(plugin: schemas.Plugin) -> int:
            if PluginHelper.is_local_repo_url(plugin.repo_url):
                return len(markets) + 1
            if plugin.repo_url in markets:
                return markets.index(plugin.repo_url)
            return len(markets)

        # 去重：同 ID + 版本优先保留市场来源，其次按来源顺序稳定保留。
        dedup_plugins = {}
        for plugin in sorted(all_plugins, key=repo_order):
            key = f"{plugin.id}{plugin.plugin_version}"
            exists = dedup_plugins.get(key)
            if not exists:
                dedup_plugins[key] = plugin
                continue
            if PluginHelper.is_local_repo_url(exists.repo_url) and not PluginHelper.is_local_repo_url(plugin.repo_url):
                dedup_plugins[key] = plugin

        # 相同 ID 的插件保留版本号最大的版本；同版本市场来源优先。
        result_by_id = {}
        for plugin in sorted(dedup_plugins.values(), key=repo_order):
            exists = result_by_id.get(plugin.id)
            if not exists:
                result_by_id[plugin.id] = plugin
                continue
            if compare_version(plugin.plugin_version, ">", exists.plugin_version):
                result_by_id[plugin.id] = plugin
            elif plugin.plugin_version == exists.plugin_version \
                    and PluginHelper.is_local_repo_url(exists.repo_url) \
                    and not PluginHelper.is_local_repo_url(plugin.repo_url):
                result_by_id[plugin.id] = plugin

        return list(result_by_id.values())

    def _process_plugin_info(self, pid: str, plugin_info: dict, market: str,
                             installed_apps: List[str], add_time: int,
                             package_version: Optional[str] = None) -> Optional[schemas.Plugin]:
        """
        处理单个插件信息，创建 schemas.Plugin 对象
        :param pid: 插件ID
        :param plugin_info: 插件信息字典
        :param market: 市场URL
        :param installed_apps: 已安装插件列表
        :param add_time: 添加顺序
        :param package_version: 包版本
        :return: 创建的插件对象，如果验证失败返回None
        """
        if not isinstance(plugin_info, dict):
            return None

        plugin_info = PluginHelper.annotate_plugin_system_version(plugin_info.copy())
        if not PluginHelper.is_package_plugin_compatible(
                plugin_info, package_version or ""
        ):
            # 插件当前版本不兼容
            return None

        # 运行状插件
        plugin_obj = self._plugin_manager.get_running_plugin(pid)
        # 非运行态插件
        plugin_static = self._plugin_manager.get_plugin_class(pid)
        # 基本属性
        plugin = schemas.Plugin()
        # ID
        plugin.id = pid
        # 安装状态
        if pid in installed_apps and plugin_static:
            plugin.installed = True
        else:
            plugin.installed = False
        # 是否有新版本
        plugin.has_update = False
        if plugin_static:
            installed_version = getattr(plugin_static, "plugin_version")
            if compare_version(installed_version, "<", plugin_info.get("version")):
                # 需要更新
                plugin.has_update = True
        # 主系统版本兼容性
        if plugin_info.get("system_version"):
            plugin.system_version = plugin_info.get("system_version")
        if plugin_info.get("system_version_compatible") is False:
            plugin.system_version_compatible = False
            plugin.system_version_message = plugin_info.get("system_version_message")
        # 运行状态
        if plugin_obj and hasattr(plugin_obj, "get_state"):
            try:
                state = plugin_obj.get_state()
            except Exception as e:
                logger.error(f"获取插件 {pid} 状态出错：{str(e)}")
                state = False
            plugin.state = state
        else:
            plugin.state = False
        # 是否有详情页面
        plugin.has_page = False
        if plugin_obj and hasattr(plugin_obj, "get_page"):
            if ObjectUtils.check_method(plugin_obj.get_page):
                plugin.has_page = True
        # 公钥
        if plugin_info.get("key"):
            plugin.plugin_public_key = plugin_info.get("key")
        # 权限
        if not set_and_check_auth_level(plugin=plugin, source=plugin_info):
            return None
        # 名称
        if plugin_info.get("name"):
            plugin.plugin_name = plugin_info.get("name")
        # 描述
        if plugin_info.get("description"):
            plugin.plugin_desc = plugin_info.get("description")
        # 版本
        if plugin_info.get("version"):
            plugin.plugin_version = plugin_info.get("version")
        # 图标
        if plugin_info.get("icon"):
            plugin.plugin_icon = plugin_info.get("icon")
        # 标签
        plugin.plugin_label = self._normalize_plugin_label(plugin_info.get("labels"))
        # 作者
        if plugin_info.get("author"):
            plugin.plugin_author = plugin_info.get("author")
        # 更新历史
        if plugin_info.get("history"):
            plugin.history = plugin_info.get("history")
        # Release 能力位来自插件市场索引，用于前端展示和后端安装入口双重校验。
        plugin.release = bool(plugin_info.get("release"))
        # 仓库链接
        plugin.repo_url = market
        # 本地标志
        plugin.is_local = False
        # 添加顺序
        plugin.add_time = add_time

        return plugin

    @staticmethod
    def _normalize_plugin_label(labels: Any) -> Optional[str]:
        """
        规整插件市场标签字段，兼容旧字符串和新列表格式。

        :param labels: 插件市场 package 中的 labels 字段
        :return: 用空格拼接后的标签字符串，无法识别或为空时返回 None
        """
        if isinstance(labels, str):
            label = labels.strip()
            return label or None
        if isinstance(labels, list):
            normalized_labels = [str(item).strip() for item in labels if str(item).strip()]
            return " ".join(normalized_labels) or None
        return None
