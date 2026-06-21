from abc import abstractmethod, ABCMeta
from enum import Enum
from typing import Generic, Tuple, Union, TypeVar, Type, Dict, List, Set, Optional, Callable, \
    Generator, Protocol, runtime_checkable, TYPE_CHECKING
from pathlib import Path

from app.helper.service import ServiceConfigHelper
from app.schemas import Notification, NotificationConf, MediaServerConf, DownloaderConf
from app.schemas.types import ModuleType, DownloaderType, MediaServerType, MessageChannel, StorageSchema, \
    OtherModulesType, SystemConfigKey
from app.utils.mixins import ConfigReloadMixin

if TYPE_CHECKING:
    # 仅用于类型注解，避免在早期导入的 app.modules 顶层引入 schemas 重负载/潜在环。
    from app.core.context import MediaInfo
    from app.schemas import DownloaderTorrent, DownloaderFile, DownloaderInfo, \
        MediaServerLibrary, MediaServerItem, MediaServerSeasonInfo, MediaServerPlayItem, \
        ExistMediaInfo, Statistic
    from app.schemas.types import TorrentStatus


class _ModuleBase(ConfigReloadMixin, metaclass=ABCMeta):
    """
    模块基类，实现对应方法，在有需要时会被自动调用，返回None代表不启用该模块，将继续执行下一模块
    输入参数与输出参数一致的，或没有输出的，可以被多个模块重复实现
    """

    def on_config_changed(self):
        self.init_module()

    def get_reload_name(self):
        return self.get_name()

    @abstractmethod
    def init_module(self) -> None:
        """
        模块初始化
        """
        pass

    @abstractmethod
    def init_setting(self) -> Tuple[str, Union[str, bool]]:
        """
        模块开关设置，返回开关名和开关值，开关值为True时代表有值即打开，不实现该方法或返回None代表不使用开关
        部分模块支持同时开启多个，此时设置项以,分隔，开关值使用in判断
        """
        pass

    @staticmethod
    def get_name() -> str:
        """
        获取模块名称
        """
        pass

    @staticmethod
    def get_type() -> ModuleType:
        """
        获取模块类型
        """
        pass

    @staticmethod
    def get_subtype() -> Union[DownloaderType, MediaServerType, MessageChannel, StorageSchema, OtherModulesType, str]:
        """
        获取模块子类型（下载器、媒体服务器、消息通道、存储类型、其他杂项模块类型）
        """
        pass

    def get_subtype_id(self) -> str:
        """
        获取模块子类型的字符串标识。默认取 get_subtype().value，使内建模块零改动即具备字符串标识；
        插件可重写此方法返回封闭枚举之外的任意字符串（如 "aria2"）以新增子类型，
        无需改动 schemas/types.py 中的封闭枚举。get_subtype() 返回 None 时回退为空串。
        """
        subtype = self.get_subtype()
        if subtype is None:
            return ""
        return str(subtype.value) if isinstance(subtype, Enum) else str(subtype)

    @staticmethod
    def get_priority() -> int:
        """
        获取模块优先级，数字越小优先级越高，只有同一接口下优先级才生效
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        如果关闭时模块有服务需要停止，需要实现此方法
        :return: None，该方法可被多个模块同时处理
        """
        pass

    @abstractmethod
    def test(self) -> Optional[Tuple[bool, str]]:
        """
        模块测试, 返回测试结果和错误信息
        """
        pass


# 定义泛型，用于表示具体的服务类型和配置类型
TService = TypeVar("TService", bound=object)
TConf = TypeVar("TConf")


class ServiceBase(Generic[TService, TConf], metaclass=ABCMeta):
    """
    抽象服务基类，负责服务的初始化、获取实例和配置管理
    """

    def __init__(self):
        """
        初始化 ServiceBase 类的实例
        """
        self._configs: Optional[Dict[str, TConf]] = None
        self._instances: Optional[Dict[str, TService]] = None
        self._service_name: Optional[str] = None

    def init_service(self, service_name: str,
                     service_type: Optional[Union[Type[TService], Callable[..., TService]]] = None):
        """
        初始化服务，获取配置并实例化对应服务

        :param service_name: 服务名称，作为配置匹配的依据
        :param service_type: 服务的类型，可以是类类型（Type[TService]）、工厂函数（Callable）或 None 来跳过实例化
        """
        if not service_name:
            raise Exception("service_name is null")
        self._service_name = service_name
        configs = self.get_configs()
        if configs is None:
            return
        self._configs = configs
        self._instances = {}
        if not service_type:
            return
        for conf in self._configs.values():
            # 通过服务类型或工厂函数来创建实例
            if isinstance(service_type, type):
                # 如果传入的是类类型，调用构造函数实例化
                self._instances[conf.name] = service_type(name=conf.name, **conf.config)
            else:
                # 如果传入的是工厂函数，直接调用工厂函数
                self._instances[conf.name] = service_type(conf)

    def get_instances(self) -> Dict[str, TService]:
        """
        获取服务实例列表

        :return: 返回服务实例列表
        """
        return self._instances or {}

    def get_instance(self, name: Optional[str] = None) -> Optional[TService]:
        """
        获取指定名称的服务实例

        :param name: 实例名称，可选。如果为 None，则返回默认实例
        :return: 返回符合条件的服务实例，若不存在则返回 None
        """
        if not self._instances:
            return None
        if name:
            return self._instances.get(name)
        name = self.get_default_config_name()
        return self._instances.get(name) if name else None

    @abstractmethod
    def get_configs(self) -> Dict[str, TConf]:
        """
        获取已启用的服务配置字典

        :return: 返回配置字典
        """
        pass

    def get_config(self, name: Optional[str] = None) -> Optional[TConf]:
        """
        获取指定名称的服务配置

        :param name: 配置名称，可选。如果为 None，则返回默认服务配置
        :return: 返回符合条件的配置，若不存在则返回 None
        """
        if not self._configs:
            return None
        if name:
            return self._configs.get(name)
        name = self.get_default_config_name()
        return self._configs.get(name) if name else None

    def get_default_config_name(self) -> Optional[str]:
        """
        获取默认服务配置的名称

        :return: 默认第一个配置的名称
        """
        # 默认使用第一个配置的名称
        first_conf = next(iter(self._configs.values()), None)
        return first_conf.name if first_conf else None


class _MessageBase(ServiceBase[TService, NotificationConf]):
    """
    消息基类
    """
    CONFIG_WATCH = {SystemConfigKey.Notifications.value}

    def __init__(self):
        """
        初始化消息基类，并设置消息通道
        """
        super().__init__()
        self._channel: Optional[MessageChannel] = None

    def get_configs(self) -> Dict[str, NotificationConf]:
        """
        获取已启用的消息通知渠道的配置字典

        :return: 返回消息通知的配置字典
        """
        configs = ServiceConfigHelper.get_notification_configs()
        if not self._service_name:
            return {}
        return {conf.name: conf for conf in configs if conf.type == self._service_name and conf.enabled}

    def check_message(self, message: Notification, source: str = None) -> bool:
        """
        检查消息渠道及消息类型，判断是否处理消息

        :param message: 要检查的通知消息
        :param source: 消息来源，可选
        :return: 返回布尔值，表示是否处理该消息
        """
        # 检查消息渠道
        if message.channel and message.channel != self._channel:
            return False
        # 检查消息来源
        if message.source and message.source != source:
            return False
        # 不是定向发送时，检查消息类型开关
        if not message.userid and message.mtype:
            conf = self.get_config(source)
            if conf:
                switchs = conf.switchs or []
                if message.mtype.value not in switchs:
                    return False
        return True


@runtime_checkable
class IDownloader(Protocol):
    """
    下载器（Downloader 域）行为接口契约。

    这是下载器领域的稳定行为接口（对照存储域的 StorageBase）：声明门面
    app.helper.downloader.DownloaderManager 统一对外暴露、并按方法名分发到各后端的
    下载器操作面。采用 **结构化类型（Protocol）** 而非 ABC——后端只要实现同名同义方法即满足
    契约，无需显式继承，避免与 _ModuleBase(ABCMeta)/ServiceBase(Generic) 的元类冲突，
    亦保证对既有 Qbittorrent/Transmission/Rtorrent 模块零改动即结构兼容。

    `@runtime_checkable` 使 isinstance(obj, IDownloader) 可在运行期校验"是否实现了这些方法名"
    （注意 Protocol 的 isinstance 只校验方法存在性，不校验签名）。

    约定（与 ChainBase 下载器包装方法签名一致）：
    - 多实例路由：downloader 参数为具体下载器配置名（config_name）；为 None 时由后端广播到其
      全部启用实例，门面再跨后端按"列表 extend / 非列表取首个非 None"合并。
    - torrent_files 统一返回 List[DownloaderFile]（rtorrent 当前仍返回 List[Dict]，属待归一化的
      P0.5 后端修复项，见 app/modules/rtorrent/__init__.py 的 TODO，本接口声明目标类型）。
    """

    def download(
            self,
            content: "Union[Path, str, bytes]",
            download_dir: Path,
            cookie: str,
            episodes: "Set[int]" = None,
            category: Optional[str] = None,
            label: Optional[str] = None,
            downloader: Optional[str] = None,
    ) -> "Optional[Tuple[Optional[str], Optional[str], Optional[str], str]]":
        """添加下载任务，返回 (下载器名, 种子Hash, 种子文件布局, 错误原因)。"""
        ...

    def list_torrents(
            self,
            status: "TorrentStatus" = None,
            hashs: "Union[list, str]" = None,
            downloader: Optional[str] = None,
            include_all_tags: bool = False,
    ) -> "Optional[List[DownloaderTorrent]]":
        """获取下载器种子列表。"""
        ...

    def remove_torrents(
            self,
            hashs: "Union[str, list]",
            delete_file: bool = True,
            downloader: Optional[str] = None,
    ) -> Optional[bool]:
        """删除下载器种子。"""
        ...

    def start_torrents(self, hashs: "Union[list, str]", downloader: Optional[str] = None) -> Optional[bool]:
        """开始下载。"""
        ...

    def stop_torrents(self, hashs: "Union[list, str]", downloader: Optional[str] = None) -> Optional[bool]:
        """停止下载。"""
        ...

    def set_torrents_tag(
            self, hashs: "Union[list, str]", tags: list, downloader: Optional[str] = None
    ) -> Optional[bool]:
        """设置种子标签。"""
        ...

    def update_torrent(
            self,
            hash_string: str,
            downloader: Optional[str] = None,
            download_limit: Optional[float] = None,
            upload_limit: Optional[float] = None,
            tracker_list: Optional[list] = None,
            save_path: Optional[str] = None,
            category: Optional[str] = None,
            ratio_limit: Optional[float] = None,
            seeding_time_limit: Optional[int] = None,
    ) -> "Optional[Dict[str, bool]]":
        """修改下载任务属性。"""
        ...

    def get_torrent_trackers(
            self, hash_string: str, downloader: Optional[str] = None
    ) -> "Optional[Dict[str, List[str]]]":
        """查询下载任务 Tracker 列表。"""
        ...

    def torrent_files(
            self, tid: str, downloader: Optional[str] = None
    ) -> "Optional[List[DownloaderFile]]":
        """获取种子文件列表。"""
        ...

    def downloader_info(self, downloader: Optional[str] = None) -> "Optional[List[DownloaderInfo]]":
        """获取下载器统计信息。"""
        ...

    def transfer_completed(self, hashs: str, downloader: Optional[str] = None) -> None:
        """下载器转移完成后的处理。"""
        ...


class _DownloaderBase(ServiceBase[TService, DownloaderConf]):
    """
    下载器基类
    """
    CONFIG_WATCH = {SystemConfigKey.Downloaders.value}

    def __init__(self):
        """
        初始化下载器基类
        """
        super().__init__()
        self._default_config_name: Optional[str] = None

    def init_service(self, service_name: str,
                     service_type: Optional[Union[Type[TService], Callable[..., TService]]] = None):
        """
        初始化服务，获取配置并实例化对应服务

        :param service_name: 服务名称，作为配置匹配的依据
        :param service_type: 服务的类型，可以是类类型（Type[TService]）、工厂函数（Callable）或 None 来跳过实例化
        """
        # 重置默认配置名称
        self.reset_default_config_name()
        # 初始化服务
        super().init_service(service_name, service_type)

    def get_default_config_name(self) -> Optional[str]:
        """
        获取默认服务配置的名称

        :return: 优先从所有下载器中查找配置了默认的下载器，如果没有配置，则获取第一个下载器名称
        """
        # 优先查找默认配置
        if self._default_config_name:
            return self._default_config_name

        configs = ServiceConfigHelper.get_downloader_configs()
        for conf in configs:
            if conf.default:
                self._default_config_name = conf.name
                return self._default_config_name
        # 如果没有默认配置，返回第一个配置的名称
        first_conf = next(iter(configs), None)
        self._default_config_name = first_conf.name if first_conf else None
        return self._default_config_name

    def get_configs(self) -> Dict[str, DownloaderConf]:
        """
        获取已启用的下载器的配置字典

        :return: 返回下载器配置字典
        """
        configs = ServiceConfigHelper.get_downloader_configs()
        if not self._service_name:
            return {}
        return {conf.name: conf for conf in configs if conf.type == self._service_name and conf.enabled}

    def reset_default_config_name(self):
        """
        重置默认配置名称
        """
        self._default_config_name = None

    @staticmethod
    def __replace_path_prefix(path: Union[Path, str], source: str, target: str) -> Optional[str]:
        """
        按完整路径段替换路径前缀，避免 /media 误匹配 /media2 这类相邻目录。
        """
        if not source or not source.strip() or not target or not target.strip():
            return None

        path_text = Path(path).as_posix()
        source_path = Path(source.strip()).as_posix()
        target_path = Path(target.strip()).as_posix()
        if path_text == source_path:
            return target_path

        source_prefix = f"{source_path.rstrip('/')}/"
        if path_text.startswith(source_prefix):
            suffix = path_text[len(source_prefix):]
            return (Path(target_path) / suffix).as_posix()
        return None

    @staticmethod
    def __strip_storage_prefix(path: str) -> str:
        """
        去掉存储协议前缀 if any，下载器无法识别本地存储协议。
        """
        for s in StorageSchema:
            prefix = f"{s.value}:"
            if path.startswith(prefix):
                return path[len(prefix):]
        return path

    def normalize_path(self, path: Path, downloader: Optional[str]) -> str:
        """
        根据下载器配置和路径映射，规范化下载路径

        :param path: 存储路径
        :param downloader: 下载器名称
        :return: 规范化后发送给下载器的路径
        """
        normalized_path = path.as_posix()
        conf = self.get_config(downloader)
        if conf and conf.path_mapping:
            for (storage_path, download_path) in conf.path_mapping:
                mapped_path = self.__replace_path_prefix(normalized_path, storage_path, download_path)
                if mapped_path:
                    normalized_path = mapped_path
                    break
        return self.__strip_storage_prefix(normalized_path)

    def normalize_return_path(self, path: Path, downloader: Optional[str]) -> str:
        """
        将下载器返回的路径反向映射为 MoviePilot 可访问的存储路径。

        :param path: 下载器返回的路径
        :param downloader: 下载器名称
        :return: MoviePilot 可访问的路径
        """
        normalized_path = path.as_posix()
        conf = self.get_config(downloader)
        if conf and conf.path_mapping:
            for (storage_path, download_path) in conf.path_mapping:
                mapped_path = self.__replace_path_prefix(normalized_path, download_path, storage_path)
                if mapped_path:
                    normalized_path = mapped_path
                    break
        return self.__strip_storage_prefix(normalized_path)


class _MediaServerBase(ServiceBase[TService, MediaServerConf]):
    """
    媒体服务器基类
    """
    CONFIG_WATCH = {SystemConfigKey.MediaServers.value}

    def get_configs(self) -> Dict[str, MediaServerConf]:
        """
        获取已启用的媒体服务器的配置字典

        :return: 返回媒体服务器配置字典
        """
        configs = ServiceConfigHelper.get_mediaserver_configs()
        if not self._service_name:
            return {}
        return {conf.name: conf for conf in configs if conf.type == self._service_name and conf.enabled}


@runtime_checkable
class IMediaServer(Protocol):
    """
    媒体服务器（MediaServer 域）行为接口契约。

    对照下载器域的 IDownloader / 存储域的 StorageBase：声明门面
    app.helper.mediaserver_manager.MediaServerManager 统一对外暴露、并按方法名分发到各后端的
    媒体服务器操作面。采用 **结构化类型（Protocol）** 而非 ABC——后端只要实现同名同义方法即满足
    契约，无需显式继承，避免与 _ModuleBase(ABCMeta)/ServiceBase(Generic) 的元类冲突，对既有
    Emby/Jellyfin/Plex/TrimeMedia/Ugreen/ZSpace 模块零改动即结构兼容。

    约定（与 ChainBase/MediaServerChain 媒服包装方法签名一致）：
    - 多实例路由：server 参数为具体媒体服务器配置名（config_name）；为 None 时由后端广播到其
      全部启用实例，门面再按"列表 extend / 非列表取首个非 None"跨后端合并。
    - 签名漂移收敛：各后端 server 必填性 / username 形参 / **kwargs 存在差异（见各模块），门面在此
      统一为最宽松 canonical 签名（server: Optional[str]）；后端要么声明该形参、要么有 **kwargs
      吸收（不致 TypeError），故按 kwarg 分发对全部后端兼容、与 run_module 行为完全一致。注意：以
      **kwargs 吸收某形参的后端（如 Plex/TrimeMedia/Ugreen 对 username）会静默忽略该值——此为既有
      run_module 行为，门面如实保留、不引入差异。
    - mediaserver_image_cookies 仅部分后端实现（TrimeMedia/Ugreen），按方法名分发自然只命中实现者
      （类比下载器域 rtorrent 早期缺方法），未实现者不参与。
    """

    def media_exists(self, mediainfo: "MediaInfo", itemid: Optional[str] = None,
                     server: Optional[str] = None) -> "Optional[ExistMediaInfo]": ...

    def media_statistic(self, server: Optional[str] = None) -> "Optional[List[Statistic]]": ...

    def mediaserver_librarys(self, server: Optional[str] = None, username: Optional[str] = None,
                             hidden: Optional[bool] = False) -> "Optional[List[MediaServerLibrary]]": ...

    def mediaserver_items(self, server: Optional[str] = None, library_id: Union[str, int] = None,
                          start_index: Optional[int] = 0, limit: Optional[int] = -1) -> Optional[Generator]: ...

    def mediaserver_iteminfo(self, server: Optional[str] = None,
                             item_id: Union[str, int] = None) -> "Optional[MediaServerItem]": ...

    def mediaserver_tv_episodes(self, server: Optional[str] = None,
                                item_id: Union[str, int] = None) -> "Optional[List[MediaServerSeasonInfo]]": ...

    def mediaserver_playing(self, server: Optional[str] = None, count: Optional[int] = 20,
                            username: Optional[str] = None) -> "List[MediaServerPlayItem]": ...

    def mediaserver_play_url(self, server: Optional[str] = None,
                             item_id: Union[str, int] = None) -> Optional[str]: ...

    def mediaserver_latest(self, server: Optional[str] = None, count: Optional[int] = 20,
                           username: Optional[str] = None) -> "List[MediaServerPlayItem]": ...

    def mediaserver_latest_images(self, server: Optional[str] = None, count: Optional[int] = 10,
                                  username: Optional[str] = None,
                                  remote: Optional[bool] = False) -> List[str]: ...

    def mediaserver_image_cookies(self, server: Optional[str] = None,
                                  image_url: Optional[str] = None) -> Optional[Union[str, dict]]: ...


@runtime_checkable
class INotification(Protocol):
    """
    消息通知（Notification 域）行为接口契约。

    对照下载器域的 IDownloader / 媒服域的 IMediaServer / 存储域的 StorageBase：声明门面
    app.helper.notification_manager.NotificationManager 统一对外暴露、并按方法名分发到各通知后端
    （内建 Telegram/WeChat/Slack/Discord/VoceChat/... 及插件经 provides_notifications() 注册的
    渠道）的消息操作面。采用 **结构化类型（Protocol）** 而非 ABC——后端只要实现同名同义方法即满足
    契约，无需显式继承，对既有通知模块零改动即结构兼容。

    派发语义（与 run_module 完全一致）：通知是**广播域**——post_* 类方法对所有启用渠道广播（返回
    None、不短路合并），各渠道方法内部经 check_message 自行按渠道/来源/类型过滤是否处理；
    delete_message/edit_message 返回非空值（bool/响应字典），按"取首个非空"语义短路。后端按需实现
    子集（如部分渠道不支持编辑/删除），按方法名分发自然只命中实现者。
    """

    def post_message(self, message: "Notification", **kwargs) -> None: ...

    def post_medias_message(self, message: "Notification", medias: "List[MediaInfo]") -> None: ...

    def post_torrents_message(self, message: "Notification", torrents: "List[Context]") -> None: ...

    def delete_message(self, channel: "MessageChannel", source: Optional[str] = None,
                       message_id: Union[str, int] = None,
                       chat_id: Optional[Union[str, int]] = None) -> Optional[bool]: ...

    def register_commands(self, commands: Dict[str, dict]) -> None: ...

    def edit_message(self, channel: "MessageChannel", source: Optional[str] = None,
                     message_id: Union[str, int] = None, chat_id: Union[str, int] = None,
                     text: Optional[str] = None, title: Optional[str] = None,
                     buttons: Optional[list] = None, metadata: Optional[dict] = None) -> bool: ...

    def send_direct_message(self, message: "Notification") -> "Optional[MessageResponse]": ...

    def finalize_message(self, response: "MessageResponse") -> Optional[bool]: ...


@runtime_checkable
class IMediaRecognize(Protocol):
    """
    媒体识别 / 数据源（MediaRecognize 域）行为接口契约。

    对照下载器 IDownloader / 媒服 IMediaServer / 通知 INotification / 存储 StorageBase：声明门面
    app.helper.mediarecognize_manager.MediaRecognizeManager 统一对外暴露、并按方法名分发到各数据源后端
    （内建 TheMovieDb/Douban/Bangumi/TheTvDb 及插件经 provides_data_sources() 注册的源）的识别操作面。
    采用 **结构化类型（Protocol）** 而非 ABC——后端只要实现同名同义方法即满足契约，无需显式继承。

    派发语义——**管道（pipeline）**：recognize_media 等方法的返回值在源之间流转、逐源精化；search_* 列表
    方法跨源 extend 合并；首个非空非列表结果短路。后端按需实现子集（如 Bangumi 缺 obtain_images、
    TheTvDb 仅实现 tvdb_info），按方法名分发自然只命中实现者——故下列方法均非强制实现。
    异步变体（async_*）与同步同义，门面经 async_dispatch 分发。
    """

    def recognize_media(self, meta: "MetaBase" = None, mtype: "MediaType" = None,
                        tmdbid: Optional[int] = None, doubanid: Optional[str] = None,
                        bangumiid: Optional[int] = None, **kwargs) -> "Optional[MediaInfo]": ...

    def search_medias(self, meta: "MetaBase") -> "Optional[List[MediaInfo]]": ...

    def search_persons(self, name: str) -> "Optional[List[MediaPerson]]": ...

    def search_collections(self, name: str) -> "Optional[List[MediaInfo]]": ...

    def obtain_images(self, mediainfo: "MediaInfo") -> "Optional[MediaInfo]": ...

    def obtain_specific_image(self, mediaid: Union[str, int], mtype: "MediaType",
                              **kwargs) -> Optional[str]: ...

    def metadata_nfo(self, meta: "MetaBase", mediainfo: "MediaInfo", **kwargs) -> Optional[str]: ...

    def media_category(self) -> Optional[Dict[str, list]]: ...
