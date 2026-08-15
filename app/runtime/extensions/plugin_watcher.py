"""插件源码的热加载监视。

在独立守护线程里监视运行目录和本地插件仓库的文件变化，把每一批变化归成两类动作：本地
仓库的源码与联邦构建产物先同步到运行目录，运行目录的 Python 变化直接触发插件热重载。
同步刚写入运行目录的插件会进入短时忽略窗口，避免复制动作把自己再次唤醒。

监视器只向插件管理器发起重载和读取运行态实例，管理器不感知监视器的存在；启停由启动组合
根装配，监视开关随 DEV / PLUGIN_AUTO_RELOAD 配置变更即时生效。
"""
import ast
import shutil
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from watchfiles import watch

from app.adapters.external.market import PluginHelper
from app.db.oper.systemconfig import SystemConfigOper
from app.foundation.singleton import Singleton
from app.runtime.config import settings
from app.runtime.extensions.plugin_instance import plugin_id_of, resolve_running_plugin
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.log import logger
from app.runtime.reload import ConfigReloadMixin
from app.schemas.types import SystemConfigKey


class PluginWatcher(ConfigReloadMixin, metaclass=Singleton):
    """插件文件修改监视器"""
    CONFIG_WATCH = {"DEV", "PLUGIN_AUTO_RELOAD", "PLUGIN_LOCAL_REPO_PATHS"}

    def __init__(self):
        """初始化监视线程状态和本地插件同步的忽略窗口。"""
        # 监控线程
        self._monitor_thread: Optional[threading.Thread] = None
        # 监控停止事件
        self._stop_monitor_event = threading.Event()
        # 本地插件同步写入运行目录后的短时忽略窗口
        self._recent_local_sync: Dict[str, float] = {}

    def on_config_changed(self):
        """在插件监控配置变化后重建文件监控。"""
        self.reload_monitor()

    def get_reload_name(self) -> str:
        """返回配置重载日志使用的功能名称。"""
        return "插件文件修改监测"

    @staticmethod
    def _monitor_enabled() -> bool:
        """
        判断当前配置是否需要监测插件文件修改

        :return: 开发者模式或显式开启自动重载时为 True
        """
        return bool(settings.DEV or settings.PLUGIN_AUTO_RELOAD)

    def start_monitor(self):
        """
        按当前配置启用插件文件修改监测
        """
        if not self._monitor_enabled():
            return
        self.__start_monitor()

    def reload_monitor(self):
        """
        重新加载插件文件修改监测
        """
        # 先关闭已有监测，再按当前配置决定是否重新启动
        self.stop_monitor()
        self.start_monitor()

    def __start_monitor(self):
        """
        启用监测插件文件修改监测
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.info("插件文件修改监测已经在运行中...")
            return

        logger.info("开始监测插件文件修改...")

        # 在启动新线程之前，确保停止事件是清除状态
        self._stop_monitor_event.clear()

        # 创建并启动监控线程
        self._monitor_thread = threading.Thread(
            target=self._run_file_watcher,
            daemon=True
        )
        self._monitor_thread.start()

    def stop_monitor(self):
        """
        停止监测插件文件修改监测
        """
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.info("正在停止插件文件修改监测...")
            self._stop_monitor_event.set()
            self._monitor_thread.join(timeout=5)
            if self._monitor_thread.is_alive():
                logger.warning("插件文件修改监测线程在5秒内未能正常停止。")
            self._monitor_thread = None
            logger.info("插件文件修改监测停止完成")
        else:
            logger.info("未启用插件文件修改监测，无需停止")

    def _run_file_watcher(self):
        """
        运行 watchfiles 监视器的主循环。
        """
        # 监视插件目录
        plugin_paths = [str(settings.ROOT_PATH / "app" / "plugins")]
        for local_repo_path in PluginHelper.get_local_repo_paths():
            if local_repo_path.exists() and local_repo_path.is_dir():
                plugin_paths.append(str(local_repo_path))
        logger.info(">>> 监控线程已启动，准备进入watch循环...")
        # 使用 watchfiles 监视目录变化，并响应变化事件
        # Todo: yield_on_timeout = True 时，每秒检查停止事件，会返回空集合；后续可以考虑用来做心跳之类的功能？
        for changes in watch(*plugin_paths, stop_event=self._stop_monitor_event, rust_timeout=1000,
                             yield_on_timeout=True):
            # 如果收到停止事件，退出循环
            if not changes:
                continue

            # 处理变化事件
            plugins_to_reload = set()
            local_plugins_to_sync = {}
            for _change_type, path_str in changes:
                event_path = Path(path_str)

                # 跳过 pycache 目录中的文件
                if "__pycache__" in event_path.parts:
                    continue

                if event_path.name == "requirements.txt":
                    candidate = self._get_local_plugin_candidate_from_path(event_path)
                    if candidate:
                        if candidate.get("compatible") is False:
                            logger.info(
                                f"检测到本地插件 {candidate.get('id')} 依赖文件变化，"
                                f"但跳过处理：{candidate.get('skip_reason')}"
                            )
                            continue
                        logger.warn(f"检测到本地插件 {candidate.get('id')} 依赖文件变化，请重新安装本地插件以安装依赖")
                    continue

                federated_change = self._get_federated_plugin_change(event_path)
                if federated_change:
                    pid, candidate, remote_entry_ready = federated_change
                    # 运行目录由构建方直接写入；外部本地仓库只在入口完整时同步运行副本。
                    if candidate and remote_entry_ready:
                        if candidate.get("compatible") is False:
                            logger.info(
                                f"检测到本地插件 {pid} 联邦构建产物变化，"
                                f"但跳过同步：{candidate.get('skip_reason')}"
                            )
                        elif pid not in local_plugins_to_sync:
                            local_plugins_to_sync[pid] = (candidate, event_path, False)
                    continue

                # 跳过非 .py 文件
                if not event_path.name.endswith(".py"):
                    continue

                # 解析插件ID
                runtime_pid = self._get_plugin_id_from_path(event_path)
                local_candidate = self._get_local_plugin_candidate_from_path(event_path) if not runtime_pid else None
                if runtime_pid:
                    last_sync_time = self._recent_local_sync.get(runtime_pid)
                    if last_sync_time and time.time() - last_sync_time < 2:
                        continue
                    # 运行目录变化只重载，不能反向触发本地同步。
                    plugins_to_reload.add(runtime_pid)
                elif local_candidate:
                    if local_candidate.get("compatible") is False:
                        package_version = local_candidate.get("package_version")
                        source_root = f"plugins.{package_version}" if package_version else "plugins"
                        logger.info(
                            f"检测到本地插件 {local_candidate.get('id')} 文件变化，来源：{source_root}，"
                            f"文件：{event_path}，但跳过同步：{local_candidate.get('skip_reason')}"
                        )
                        continue
                    local_plugins_to_sync[local_candidate.get("id")] = (local_candidate, event_path, True)

            for pid, (candidate, event_path, should_reload) in local_plugins_to_sync.items():
                package_version = candidate.get("package_version")
                source_root = f"plugins.{package_version}" if package_version else "plugins"
                change_name = "Python 文件" if should_reload else "联邦构建产物"
                logger.info(f"检测到本地插件 {pid} {change_name}变化，来源：{source_root}，文件：{event_path}")
                if self._sync_local_plugin_if_installed(pid, candidate) and should_reload:
                    plugins_to_reload.add(pid)

            # 触发重载
            if plugins_to_reload:
                logger.info(f"检测到插件文件变化，准备重载: {list(plugins_to_reload)}")
                plugin_manager = PluginManager()
                for pid in plugins_to_reload:
                    try:
                        plugin_manager.reload_plugin(pid)
                    except Exception as e:
                        logger.error(f"插件 {pid} 热重载失败: {e}", exc_info=True)

    def _get_federated_plugin_change(
        self,
        event_path: Path,
    ) -> Optional[Tuple[str, Optional[dict], bool]]:
        """
        识别运行态 Vue 插件声明目录内的构建产物变化。

        :return: 插件 ID、本地仓库候选和联邦入口是否完整；非联邦目录变化返回 None。
        """
        try:
            running_plugins = PluginManager().running_plugins
            event_path = event_path.resolve()
            candidate = self._get_local_plugin_candidate_from_path(event_path)
            if candidate:
                pid = candidate.get("id")
                plugin_dir = Path(candidate.get("path")).resolve()
            else:
                runtime_root = (settings.ROOT_PATH / "app" / "plugins").resolve()
                if not event_path.is_relative_to(runtime_root):
                    return None
                relative_parts = event_path.relative_to(runtime_root).parts
                if not relative_parts:
                    return None
                plugin_dir = runtime_root / relative_parts[0]
                pid = next(
                    (
                        plugin_id_of(key)
                        for key in running_plugins
                        if plugin_id_of(key).lower() == relative_parts[0].lower()
                    ),
                    None,
                )

            if not pid:
                return None
            plugin = resolve_running_plugin(running_plugins, pid)
            if not plugin:
                return None

            render_mode, dist_path = plugin.get_render_mode()
            if render_mode != "vue" or not isinstance(dist_path, str) or not dist_path:
                return None

            relative_dist_path = Path(dist_path)
            if relative_dist_path.is_absolute() or ".." in relative_dist_path.parts or "\\" in dist_path:
                return None

            plugin_dir = plugin_dir.resolve()
            dist_dir = (plugin_dir / relative_dist_path).resolve()
            if (
                dist_dir == plugin_dir
                or not dist_dir.is_relative_to(plugin_dir)
                or not event_path.is_relative_to(dist_dir)
            ):
                return None

            remote_entry = dist_dir / "remoteEntry.js"
            remote_entry_ready = (
                remote_entry.is_file()
                and remote_entry.resolve().is_relative_to(plugin_dir)
            )
            return pid, candidate, remote_entry_ready
        except Exception as e:
            logger.error(f"识别插件联邦构建产物变化时出错: {e}")
            return None

    @staticmethod
    def _get_plugin_id_from_path(event_path: Path) -> Optional[str]:
        """
        根据文件路径解析出插件的ID。
        :param event_path: 被修改文件的 Path 对象。
        :return: 插件ID字符串，如果不是有效插件文件则返回 None。
        """
        try:
            event_path = event_path.resolve()
            plugins_root = settings.ROOT_PATH / "app" / "plugins"
            # 确保修改的文件在 plugins 目录下
            if not event_path.is_relative_to(plugins_root):
                return None

            try:
                plugin_dir_name = event_path.relative_to(plugins_root).parts[0]
                plugin_dir = plugins_root / plugin_dir_name
            except (ValueError, IndexError):
                return None

            init_file = plugin_dir / "__init__.py"
            if not init_file.exists():
                return None

            # 读取 __init__.py 文件，查找插件主类名
            with open(init_file, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()

            tree = ast.parse(source_code)

            # 遍历AST，查找继承自 _PluginBase 的类
            for node in ast.walk(tree):
                # 检查节点是否为类定义
                if isinstance(node, ast.ClassDef):
                    # 遍历该类的所有基类
                    for base in node.bases:
                        # 检查基类是否是我们寻找的 _PluginBase
                        # ast.Name 用于处理简单的基类名
                        if isinstance(base, ast.Name) and base.id == '_PluginBase':
                            # 返回这个类的名字
                            return node.name

            return None
        except Exception as e:
            logger.error(f"从路径解析插件ID时出错: {e}")
            return None

    @staticmethod
    def _get_local_plugin_candidate_from_path(event_path: Path) -> Optional[dict]:
        """
        根据本地插件仓库路径解析具体插件候选，保留 plugins/plugins.v2 来源差异
        """
        try:
            event_path = event_path.resolve()
            for local_repo_path in PluginHelper.get_local_repo_paths():
                if not local_repo_path.exists() or not local_repo_path.is_dir():
                    continue
                if not event_path.is_relative_to(local_repo_path):
                    continue
                try:
                    relative_parts = event_path.relative_to(local_repo_path).parts
                except (ValueError, IndexError):
                    continue
                if len(relative_parts) < 2:
                    continue
                if relative_parts[0] == "plugins":
                    package_version = ""
                elif relative_parts[0].startswith("plugins."):
                    package_version = relative_parts[0].split(".", 1)[1]
                else:
                    continue
                plugin_dir_name = relative_parts[1]
                candidate = PluginHelper().get_local_plugin_candidate(
                    pid=plugin_dir_name,
                    package_version=package_version,
                    repo_path=local_repo_path,
                    strict_compat=False,
                    strict_system_version=not settings.DEV
                )
                if candidate:
                    return candidate
            return None
        except Exception as e:
            logger.error(f"从本地插件仓库路径解析插件候选时出错: {e}")
            return None

    @staticmethod
    def _sync_local_plugin_if_installed(pid: str, candidate: Optional[dict] = None) -> bool:
        """
        已安装本地插件源码变化时，同步到运行目录
        """
        installed_plugins = SystemConfigOper().get(SystemConfigKey.UserInstalledPlugins) or []
        if pid not in installed_plugins:
            logger.info(f"本地插件 {pid} 尚未安装，跳过自动同步和热重载")
            return False

        candidate = candidate or PluginHelper().get_local_plugin_candidate(pid)
        if not candidate:
            return False
        if candidate.get("compatible") is False:
            logger.info(f"本地插件 {pid} 不满足同步条件，跳过自动同步：{candidate.get('skip_reason')}")
            return False

        source_dir = Path(candidate.get("path"))
        dest_dir = settings.ROOT_PATH / "app" / "plugins" / pid.lower()
        try:
            if source_dir.resolve() == dest_dir.resolve():
                return True
            if dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)
            shutil.copytree(
                source_dir,
                dest_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store", "node_modules")
            )
            PluginWatcher()._recent_local_sync[pid] = time.time()
            logger.info(f"已同步本地插件 {pid}：{source_dir} -> {dest_dir}")
            return True
        except Exception as e:
            logger.error(f"同步本地插件 {pid} 失败：{e}")
            return False
