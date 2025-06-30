import json
import platform
import re
import threading
import time
import traceback
from pathlib import Path
from threading import Lock
from typing import Any, Optional, Dict, List

from apscheduler.schedulers.background import BackgroundScheduler
from cachetools import TTLCache
from watchdog.events import FileSystemEventHandler, FileSystemMovedEvent, FileSystemEvent
from watchdog.observers.polling import PollingObserver

from app.chain import ChainBase
from app.chain.storage import StorageChain
from app.chain.transfer import TransferChain
from app.core.config import settings
from app.core.event import Event, eventmanager
from app.helper.directory import DirectoryHelper
from app.helper.message import MessageHelper
from app.log import logger
from app.schemas import ConfigChangeEventData
from app.schemas import FileItem
from app.schemas.types import SystemConfigKey, EventType
from app.utils.singleton import Singleton

lock = Lock()
snapshot_lock = Lock()


class MonitorChain(ChainBase):
    pass


class FileMonitorHandler(FileSystemEventHandler):
    """
    目录监控响应类
    """

    def __init__(self, mon_path: Path, callback: Any, **kwargs):
        super(FileMonitorHandler, self).__init__(**kwargs)
        self._watch_path = mon_path
        self.callback = callback

    def on_created(self, event: FileSystemEvent):
        self.callback.event_handler(event=event, text="创建", event_path=event.src_path,
                                    file_size=Path(event.src_path).stat().st_size)

    def on_moved(self, event: FileSystemMovedEvent):
        self.callback.event_handler(event=event, text="移动", event_path=event.dest_path,
                                    file_size=Path(event.dest_path).stat().st_size)


class Monitor(metaclass=Singleton):
    """
    目录监控处理链，单例模式
    """

    # 退出事件
    _event = threading.Event()

    # 监控服务
    _observers = []

    # 定时服务
    _scheduler = None

    # 存储快照缓存目录
    _snapshot_cache_dir = None

    # 存储过照间隔（分钟）
    _snapshot_interval = 5

    # TTL缓存，10秒钟有效
    _cache = TTLCache(maxsize=1024, ttl=10)

    def __init__(self):
        super().__init__()
        self.all_exts = settings.RMT_MEDIAEXT
        # 初始化快照缓存目录
        self._snapshot_cache_dir = settings.TEMP_PATH / "snapshots"
        self._snapshot_cache_dir.mkdir(exist_ok=True)
        # 启动目录监控和文件整理
        self.init()

    @eventmanager.register(EventType.ConfigChanged)
    def handle_config_changed(self, event: Event):
        """
        处理配置变更事件
        :param event: 事件对象
        """
        if not event:
            return
        event_data: ConfigChangeEventData = event.event_data
        if event_data.key not in [SystemConfigKey.Directories.value]:
            return
        logger.info("配置变更事件触发，重新初始化目录监控...")
        self.init()

    def save_snapshot(self, storage: str, snapshot: Dict, file_count: int = 0):
        """
        保存快照到文件
        :param storage: 存储名称
        :param snapshot: 快照数据
        :param file_count: 文件数量，用于调整监控间隔
        """
        try:
            cache_file = self._snapshot_cache_dir / f"{storage}_snapshot.json"
            snapshot_data = {
                'timestamp': time.time(),
                'file_count': file_count,
                'snapshot': snapshot
            }
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot_data, f, ensure_ascii=False, indent=2)
            logger.debug(f"快照已保存到 {cache_file}")
        except Exception as e:
            logger.error(f"保存快照失败: {e}")

    def load_snapshot(self, storage: str) -> Optional[Dict]:
        """
        从文件加载快照
        :param storage: 存储名称
        :return: 快照数据或None
        """
        try:
            cache_file = self._snapshot_cache_dir / f"{storage}_snapshot.json"
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data
            return None
        except Exception as e:
            logger.error(f"加载快照失败: {e}")
            return None

    @staticmethod
    def adjust_monitor_interval(file_count: int) -> int:
        """
        根据文件数量动态调整监控间隔
        :param file_count: 文件数量
        :return: 监控间隔（分钟）
        """
        if file_count < 100:
            return 5  # 5分钟
        elif file_count < 500:
            return 10  # 10分钟
        elif file_count < 1000:
            return 15  # 15分钟
        else:
            return 30  # 30分钟

    @staticmethod
    def compare_snapshots(old_snapshot: Dict, new_snapshot: Dict) -> Dict[str, List]:
        """
        比对快照，找出变化的文件（只处理新增和修改，不处理删除）
        :param old_snapshot: 旧快照
        :param new_snapshot: 新快照
        :return: 变化信息
        """
        changes = {
            'added': [],
            'modified': []
        }

        old_files = set(old_snapshot.keys())
        new_files = set(new_snapshot.keys())

        # 新增文件
        changes['added'] = list(new_files - old_files)

        # 修改文件（大小或时间变化）
        for file_path in old_files & new_files:
            old_info = old_snapshot[file_path]
            new_info = new_snapshot[file_path]

            # 检查文件大小变化
            old_size = old_info.get('size', 0) if isinstance(old_info, dict) else old_info
            new_size = new_info.get('size', 0) if isinstance(new_info, dict) else new_info

            # 检查修改时间变化（如果有的话）
            old_time = old_info.get('modify_time', 0) if isinstance(old_info, dict) else 0
            new_time = new_info.get('modify_time', 0) if isinstance(new_info, dict) else 0

            if old_size != new_size or (old_time and new_time and old_time != new_time):
                changes['modified'].append(file_path)

        return changes

    def init(self):
        """
        启动监控
        """
        # 停止现有任务
        self.stop()

        # 读取目录配置
        monitor_dirs = DirectoryHelper().get_download_dirs()
        if not monitor_dirs:
            return

        # 按下载目录去重
        monitor_dirs = list({f"{d.storage}_{d.download_path}": d for d in monitor_dirs}.values())

        # 启动定时服务进程
        self._scheduler = BackgroundScheduler(timezone=settings.TZ)

        messagehelper = MessageHelper()
        for mon_dir in monitor_dirs:
            if not mon_dir.library_path:
                continue
            if mon_dir.monitor_type != "monitor":
                continue
            # 检查媒体库目录是不是下载目录的子目录
            mon_path = Path(mon_dir.download_path)
            target_path = Path(mon_dir.library_path)
            if target_path.is_relative_to(mon_path):
                logger.warn(f"{target_path} 是监控目录 {mon_path} 的子目录，无法监控！")
                messagehelper.put(f"{target_path} 是监控目录 {mon_path} 的子目录，无法监控", title="目录监控")
                continue

            # 启动监控
            if mon_dir.storage == "local":
                # 本地目录监控
                try:
                    if mon_dir.monitor_mode == "fast":
                        observer = self.__choose_observer()
                    else:
                        observer = PollingObserver()
                    self._observers.append(observer)
                    observer.schedule(FileMonitorHandler(mon_path=mon_path, callback=self),
                                      path=str(mon_path),
                                      recursive=True)
                    observer.daemon = True
                    observer.start()
                    logger.info(f"已启动 {mon_path} 的目录监控服务, 监控模式：{mon_dir.monitor_mode}")
                except Exception as e:
                    err_msg = str(e)
                    if "inotify" in err_msg and "reached" in err_msg:
                        logger.warn(
                            f"目录监控服务启动出现异常：{err_msg}，请在宿主机上（不是docker容器内）执行以下命令并重启："
                            + """
                             echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
                             echo fs.inotify.max_user_instances=524288 | sudo tee -a /etc/sysctl.conf
                             sudo sysctl -p
                             """)
                    else:
                        logger.error(f"{mon_path} 启动目录监控失败：{err_msg}")
                    messagehelper.put(f"{mon_path} 启动目录监控失败：{err_msg}", title="目录监控")
            else:
                # 远程目录监控 - 使用智能间隔
                # 先尝试加载已有快照获取文件数量
                snapshot_data = self.load_snapshot(mon_dir.storage)
                file_count = snapshot_data.get('file_count', 0) if snapshot_data else 0
                interval = self.adjust_monitor_interval(file_count)

                self._scheduler.add_job(
                    self.polling_observer,
                    'interval',
                    minutes=interval,
                    kwargs={
                        'storage': mon_dir.storage,
                        'mon_path': mon_path
                    },
                    id=f"monitor_{mon_dir.storage}_{mon_dir.download_path}",
                    replace_existing=True
                )
                logger.info(f"已启动 {mon_path} 的远程目录监控，存储：{mon_dir.storage}，间隔：{interval}分钟")

        # 启动定时服务
        if self._scheduler.get_jobs():
            self._scheduler.print_jobs()
            self._scheduler.start()

    @staticmethod
    def __choose_observer() -> Any:
        """
        选择最优的监控模式
        """
        system = platform.system()

        try:
            if system == 'Linux':
                from watchdog.observers.inotify import InotifyObserver
                return InotifyObserver()
            elif system == 'Darwin':
                from watchdog.observers.fsevents import FSEventsObserver
                return FSEventsObserver()
            elif system == 'Windows':
                from watchdog.observers.read_directory_changes import WindowsApiObserver
                return WindowsApiObserver()
        except Exception as error:
            logger.warn(f"导入模块错误：{error}，将使用 PollingObserver 监控目录")
        return PollingObserver()

    def polling_observer(self, storage: str, mon_path: Path):
        """
        轮询监控（改进版）
        """
        with snapshot_lock:
            try:
                logger.debug(f"开始对 {storage}:{mon_path} 进行快照...")

                # 加载上次快照数据
                old_snapshot_data = self.load_snapshot(storage)
                old_snapshot = old_snapshot_data.get('snapshot', {}) if old_snapshot_data else {}
                last_snapshot_time = old_snapshot_data.get('timestamp', 0) if old_snapshot_data else 0

                # 生成新快照（增量模式）
                new_snapshot = StorageChain().snapshot_storage(
                    storage=storage,
                    path=mon_path,
                    last_snapshot_time=last_snapshot_time
                )

                if new_snapshot is None:
                    logger.warn(f"获取 {storage}:{mon_path} 快照失败")
                    return

                file_count = len(new_snapshot)
                logger.info(f"{storage}:{mon_path} 快照完成，发现 {file_count} 个文件")

                if old_snapshot:
                    # 比较快照找出变化
                    changes = self.compare_snapshots(old_snapshot, new_snapshot)

                    # 处理新增文件
                    for new_file in changes['added']:
                        logger.info(f"发现新增文件：{new_file}")
                        file_info = new_snapshot.get(new_file, {})
                        file_size = file_info.get('size', 0) if isinstance(file_info, dict) else file_info
                        self.__handle_file(storage=storage, event_path=Path(new_file), file_size=file_size)

                    # 处理修改文件
                    for modified_file in changes['modified']:
                        logger.info(f"发现修改文件：{modified_file}")
                        file_info = new_snapshot.get(modified_file, {})
                        file_size = file_info.get('size', 0) if isinstance(file_info, dict) else file_info
                        self.__handle_file(storage=storage, event_path=Path(modified_file), file_size=file_size)

                    if changes['added'] or changes['modified']:
                        logger.info(
                            f"{storage}:{mon_path} 发现 {len(changes['added'])} 个新增文件，{len(changes['modified'])} 个修改文件")
                else:
                    logger.info(f"{storage}:{mon_path} 首次快照，暂不处理文件")

                # 保存新快照
                self.save_snapshot(storage, new_snapshot, file_count)

                # 动态调整监控间隔
                new_interval = self.adjust_monitor_interval(file_count)
                current_job = self._scheduler.get_job(f"monitor_{storage}_{mon_path}")
                if current_job and current_job.trigger.interval.total_seconds() / 60 != new_interval:
                    # 重新安排任务
                    self._scheduler.modify_job(
                        f"monitor_{storage}_{mon_path}",
                        trigger='interval',
                        minutes=new_interval
                    )
                    logger.info(f"{storage}:{mon_path} 监控间隔已调整为 {new_interval} 分钟")

            except Exception as e:
                logger.error(f"轮询监控 {storage}:{mon_path} 出现错误：{e}")
                logger.debug(traceback.format_exc())

    def event_handler(self, event, text: str, event_path: str, file_size: float = None):
        """
        处理文件变化
        :param event: 事件
        :param text: 事件描述
        :param event_path: 事件文件路径
        :param file_size: 文件大小
        """
        if not event.is_directory:
            # 文件发生变化
            logger.debug(f"文件 {event_path} 发生了 {text}")
            # 整理文件
            self.__handle_file(storage="local", event_path=Path(event_path), file_size=file_size)

    def __handle_file(self, storage: str, event_path: Path, file_size: float = None):
        """
        整理一个文件
        :param storage: 存储
        :param event_path: 事件文件路径
        :param file_size: 文件大小
        """

        def __is_bluray_sub(_path: Path) -> bool:
            """
            判断是否蓝光原盘目录内的子目录或文件
            """
            return True if re.search(r"BDMV[/\\]STREAM", str(_path), re.IGNORECASE) else False

        def __get_bluray_dir(_path: Path) -> Optional[Path]:
            """
            获取蓝光原盘BDMV目录的上级目录
            """
            for p in _path.parents:
                if p.name == "BDMV":
                    return p.parent
            return None

        # 全程加锁
        with lock:
            # 蓝光原盘文件处理
            if __is_bluray_sub(event_path):
                event_path = __get_bluray_dir(event_path)
                if not event_path:
                    return

            # TTL缓存控重
            if self._cache.get(str(event_path)):
                return
            self._cache[str(event_path)] = True

            try:
                # 开始整理
                TransferChain().do_transfer(
                    fileitem=FileItem(
                        storage=storage,
                        path=str(event_path).replace("\\", "/"),
                        type="file",
                        name=event_path.name,
                        basename=event_path.stem,
                        extension=event_path.suffix[1:],
                        size=file_size
                    )
                )
            except Exception as e:
                logger.error("目录监控发生错误：%s - %s" % (str(e), traceback.format_exc()))

    def stop(self):
        """
        退出插件
        """
        self._event.set()
        if self._observers:
            for observer in self._observers:
                try:
                    logger.info(f"正在停止目录监控服务：{observer}...")
                    observer.stop()
                    observer.join()
                    logger.info(f"{observer} 目录监控已停止")
                except Exception as e:
                    logger.error(f"停止目录监控服务出现了错误：{e}")
            self._observers = []
        if self._scheduler:
            self._scheduler.remove_all_jobs()
            if self._scheduler.running:
                try:
                    self._scheduler.shutdown()
                except Exception as e:
                    logger.error(f"停止定时服务出现了错误：{e}")
            self._scheduler = None
        self._event.clear()
