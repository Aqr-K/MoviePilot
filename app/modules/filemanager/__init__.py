from pathlib import Path
from typing import Optional, List, Set, Tuple, Union, Dict, Callable

from app.chain.tmdb import TmdbChain
from app.core.config import settings
from app.core.context import MediaInfo
from app.core.meta import MetaBase
from app.core.metainfo import MetaInfo
from app.helper.directory import DirectoryHelper
from app.helper.message import MessageHelper
from app.core.module_loader import ModuleHelper
from app.log import logger
from app.modules import _ModuleBase
from app.modules.filemanager import storage_registry
from app.modules.filemanager.storages import StorageBase
from app.modules.filemanager.transhandler import TransHandler
from app.schemas import TransferInfo, ExistMediaInfo, TmdbEpisode, TransferDirectoryConf, FileItem, StorageUsage
from app.schemas.types import MediaType, ModuleType, OtherModulesType
from app.utils.system import SystemUtils


class FileManagerModule(_ModuleBase):
    """
    文件整理模块
    """

    def __init__(self):
        super().__init__()
        self.directoryhelper = DirectoryHelper()
        self.messagehelper = MessageHelper()

    def init_module(self) -> None:
        # 存储器统一收敛到单索引 storage_registry（内建 owner=None + 外部插件），
        # 此处仅确保内建已扫描入索引（幂等、仅一次）；外部注册随插件启停直接增删索引。
        storage_registry.ensure_builtins()

    @property
    def _storage_schemas(self) -> List[type]:
        """全部存储器类（内建+外部），直读单索引 storage_registry（保留属性名兼容既有读取方/测试）。"""
        return storage_registry.all_classes()

    @property
    def _support_storages(self) -> Set[str]:
        """当前支持的存储类型 schema.value 集合（内建+外部），直读单索引，供成员资格守卫 O(1) 判定。"""
        return storage_registry.supported_values()

    @staticmethod
    def verify_storage_contract(storage_class: type) -> Tuple[bool, List[str]]:
        """
        校验外部(插件)存储器类是否满足 StorageBase 契约，作为「验证注册」核心判定，
        对齐 ModuleManager.register_module 的严格注册（其余各域均有 verify_*_contract）。
        宽松内省策略（不抛异常），返回 (是否通过, 失败原因列表)：
          1) 须为类对象；
          2) 须继承 StorageBase（真存储器 vs 任意注入类的核心区分）；
          3) 抽象方法须全部落地（StorageBase 系 ABCMeta，未实现则不可实例化）；
          4) 须声明非空 schema 且 schema.value 非空（存储类型身份；__get_storage_oper
             按 schema.value 路由，缺失则无法被命中、init_module 亦会静默过滤掉）。
        """
        if not isinstance(storage_class, type):
            return False, ["不是类对象"]
        reasons: List[str] = []
        if not issubclass(storage_class, StorageBase):
            reasons.append("未继承 app.modules.filemanager.storages.StorageBase")
        abstracts = getattr(storage_class, "__abstractmethods__", frozenset())
        if abstracts:
            reasons.append(f"抽象方法未实现：{sorted(abstracts)}")
        schema = getattr(storage_class, "schema", None)
        if not schema:
            reasons.append("缺少存储类型标识 schema（须为非空 StorageSchema）")
        elif not getattr(schema, "value", None):
            reasons.append("schema.value 为空，无法按存储类型路由")
        return (not reasons), reasons

    @classmethod
    def register_storage(cls, storage_class: type, owner: str) -> bool:
        """
        注册一个外部(插件)存储器类（StorageBase 子类）：先经 StorageBase 契约严格校验，再交
        单索引 storage_registry 做 schema.value 碰撞检测后入索引（运行实例经只读属性即时可见，
        无需刷新）。存储器无需扩展 StorageSchema 封闭枚举：按 schema.value 字符串路由，插件存储类
        只要 .schema.value 为其字符串 id 即可被命中。
        """
        # 验证注册：不通过直接拒绝（对齐 register_module 严格注册，避免畸形类静默入索引后实例化炸裂）
        ok, reasons = cls.verify_storage_contract(storage_class)
        if not ok:
            logger.warning(
                f"存储器 {getattr(storage_class, '__name__', storage_class)}(owner={owner}) "
                f"未通过 StorageBase 契约校验，拒绝注册：{'；'.join(reasons)}")
            return False
        # schema.value 碰撞检测 = 单索引内一次查（与内建或【其它】owner 冲突即拒，同 owner 幂等放行）
        accepted, reason = storage_registry.register(storage_class, owner)
        if not accepted:
            logger.warning(
                f"存储器 {getattr(storage_class, '__name__', storage_class)}(owner={owner}) "
                f"注册被拒：{reason}")
            return False
        return True

    @classmethod
    def unregister_storages(cls, owner: str) -> None:
        """卸载某来源(owner)注册的外部存储器（从单索引移除；运行实例经只读属性即时反映）。"""
        storage_registry.unregister(owner)

    @staticmethod
    def get_name() -> str:
        return "文件整理"

    @staticmethod
    def get_type() -> ModuleType:
        """
        获取模块类型
        """
        return ModuleType.Other

    @staticmethod
    def get_subtype() -> OtherModulesType:
        """
        获取模块子类型
        """
        return OtherModulesType.FileManager

    @staticmethod
    def get_priority() -> int:
        """
        获取模块优先级，数字越小优先级越高，只有同一接口下优先级才生效
        """
        return 4

    def stop(self):
        pass

    def test(self) -> Tuple[bool, str]:
        """
        测试模块连接性
        """
        # 检查目录
        dirs = self.directoryhelper.get_dirs()
        if not dirs:
            return False, "未设置任何目录"
        for d in dirs:
            # 下载目录
            download_path = d.download_path
            if not download_path:
                return False, f"{d.name} 的下载目录未设置"
            if d.storage == "local" and not Path(download_path).exists():
                return False, f"{d.name} 的下载目录 {download_path} 不存在"
            # 仅在启用整理时检查媒体库目录
            library_path = d.library_path
            if d.transfer_type:
                if not library_path:
                    return False, f"{d.name} 的媒体库目录未设置"
                if d.library_storage == "local" and not Path(library_path).exists():
                    return False, f"{d.name} 的媒体库目录 {library_path} 不存在"
                # 硬链接
                if d.transfer_type == "link" \
                        and d.storage == "local" \
                        and d.library_storage == "local" \
                        and not SystemUtils.is_same_disk(Path(download_path), Path(library_path)):
                    return False, f"{d.name} 的下载目录 {download_path} 与媒体库目录 {library_path} 不在同一磁盘，无法硬链接"
            # 存储
            storage_oper = self.__get_storage_oper(d.storage)
            if storage_oper:
                if not storage_oper.check():
                    return False, f"{d.name} 的存储测试不通过"
                if d.transfer_type and d.transfer_type not in storage_oper.support_transtype():
                    return False, f"{d.name} 的存储不支持 {d.transfer_type} 整理方式"

        return True, ""

    def __get_storage_oper(self, _storage: str, _func: Optional[str] = None) -> Optional[StorageBase]:
        """
        获取存储操作对象：按 schema.value 从单索引 O(1) 取后端类并新建实例。
        _func 非空时门控——后端类须实现该可选方法（如 generate_qrcode/check_login）方返回。
        """
        storage_class = storage_registry.get_class(_storage)
        if not storage_class:
            return None
        if _func and not hasattr(storage_class, _func):
            return None
        return storage_class()

    def init_setting(self) -> Tuple[str, Union[str, bool]]:
        pass

    def support_transtype(self, storage: str) -> Optional[dict]:
        """
        支持的整理方式
        """
        if storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的整理方式获取")
            return None
        return storage_oper.support_transtype()

    @staticmethod
    def recommend_name(meta: MetaBase, mediainfo: MediaInfo) -> Optional[str]:
        """
        获取重命名后的名称
        :param meta: 元数据
        :param mediainfo: 媒体信息
        :return: 重命名后的名称（含目录）
        """
        handler = TransHandler()
        # 重命名格式
        rename_format = settings.RENAME_FORMAT(mediainfo.type)
        # 获取集信息
        episodes_info: Optional[List[TmdbEpisode]] = None
        if mediainfo.type == MediaType.TV:
            # 判断注意season为0的情况
            season_num = mediainfo.season
            if season_num is None and meta.season_seq:
                if meta.season_seq.isdigit():
                    season_num = int(meta.season_seq)
            # 默认值1
            if season_num is None:
                season_num = 1
            episodes_info = TmdbChain().tmdb_episodes(
                tmdbid=mediainfo.tmdb_id,
                season=season_num,
                episode_group=mediainfo.episode_group,
            )
        # 获取重命名后的名称
        path = handler.get_rename_path(
            template_string=rename_format,
            rename_dict=handler.get_naming_dict(meta=meta,
                                                mediainfo=mediainfo,
                                                episodes_info=episodes_info,
                                                file_ext=Path(meta.title).suffix)
        )
        return path.as_posix() if path else ""

    def save_config(self, storage: str, conf: Dict) -> None:
        """
        保存存储配置
        """
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的配置保存")
            return
        storage_oper.set_config(conf)

    def reset_config(self, storage: str) -> None:
        """
        重置存储配置
        """
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的重置存储配置")
            return
        storage_oper.reset_config()

    def generate_qrcode(self, storage: str) -> Optional[Tuple[dict, str]]:
        """
        生成二维码
        """
        storage_oper = self.__get_storage_oper(storage, "generate_qrcode")
        if not storage_oper:
            logger.error(f"不支持 {storage} 的二维码生成")
            return None
        return storage_oper.generate_qrcode()

    def generate_auth_url(self, storage: str) -> Optional[Tuple[dict, str]]:
        """
        生成 OAuth2 授权 URL
        """
        storage_oper = self.__get_storage_oper(storage, "generate_auth_url")
        if not storage_oper:
            logger.error(f"不支持 {storage} 的 OAuth2 授权")
            return {}, f"不支持 {storage} 的 OAuth2 授权"
        return storage_oper.generate_auth_url()

    def check_login(self, storage: str, **kwargs) -> Optional[Dict[str, str]]:
        """
        登录确认
        """
        storage_oper = self.__get_storage_oper(storage, "check_login")
        if not storage_oper:
            logger.error(f"不支持 {storage} 的登录确认")
            return None
        return storage_oper.check_login(**kwargs)

    def list_files(self, fileitem: FileItem, recursion: Optional[bool] = False) -> Optional[List[FileItem]]:
        """
        浏览文件
        :param fileitem: 源文件
        :param recursion: 是否递归，此时只浏览文件
        :return: 文件项列表
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的文件浏览")
            return None

        def __get_files(_item: FileItem, _r: Optional[bool] = False):
            """
            递归处理
            """
            _items = storage_oper.list(_item)
            if _items:
                if _r:
                    for t in _items:
                        if t.type == "dir":
                            __get_files(t, _r)
                        else:
                            result.append(t)
                else:
                    result.extend(_items)

        # 返回结果
        result = []
        __get_files(fileitem, recursion)

        return result

    def any_files(self, fileitem: FileItem, extensions: list = None) -> Optional[bool]:
        """
        查询当前目录下是否存在指定扩展名任意文件
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的文件浏览")
            return None

        def __any_file(_item: FileItem):
            """
            递归处理
            """
            _items = storage_oper.list(_item)
            if _items:
                if not extensions:
                    return True
                for t in _items:
                    if (t.type == "file"
                            and t.extension
                            and f".{t.extension.lower()}" in extensions):
                        return True
                    elif t.type == "dir":
                        if __any_file(t):
                            return True
            return False

        # 返回结果
        return __any_file(fileitem)

    def create_folder(self, fileitem: FileItem, name: str) -> Optional[FileItem]:
        """
        创建目录
        :param fileitem: 源文件
        :param name: 目录名
        :return: 创建的目录
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的目录创建")
            return None
        return storage_oper.create_folder(fileitem, name)

    def get_folder(self, storage: str, path: Path) -> Optional[FileItem]:
        """
        获取目录，如目录不存在则创建
        """
        if storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的目录获取")
            return None
        return storage_oper.get_folder(path)

    def delete_file(self, fileitem: FileItem) -> Optional[bool]:
        """
        删除文件或目录
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的删除处理")
            return False
        return storage_oper.delete(fileitem)

    def rename_file(self, fileitem: FileItem, name: str) -> Optional[bool]:
        """
        重命名文件或目录
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的重命名处理")
            return False
        return storage_oper.rename(fileitem, name)

    def download_file(self, fileitem: FileItem, path: Path = None) -> Optional[Path]:
        """
        下载文件
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的下载处理")
            return None
        return storage_oper.download(fileitem, path=path)

    def upload_file(self, fileitem: FileItem, path: Path, new_name: Optional[str] = None) -> Optional[FileItem]:
        """
        上传文件
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的上传处理")
            return None
        return storage_oper.upload(fileitem, path, new_name)

    def get_file_item(self, storage: str, path: Path) -> Optional[FileItem]:
        """
        根据路径获取文件项
        """
        if storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的文件获取")
            return None
        return storage_oper.get_item(path)

    def get_parent_item(self, fileitem: FileItem) -> Optional[FileItem]:
        """
        获取上级目录项
        """
        if fileitem.storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(fileitem.storage)
        if not storage_oper:
            logger.error(f"不支持 {fileitem.storage} 的文件获取")
            return None
        return storage_oper.get_parent(fileitem)

    def snapshot_storage(self, storage: str, path: Path,
                         last_snapshot_time: float = None, max_depth: int = 5) -> Optional[Dict[str, Dict]]:
        """
        快照存储
        :param storage: 存储类型
        :param path: 路径
        :param last_snapshot_time: 上次快照时间，用于增量快照
        :param max_depth: 最大递归深度，避免过深遍历
        """
        if storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的快照处理")
            return None
        return storage_oper.snapshot(path, last_snapshot_time=last_snapshot_time, max_depth=max_depth)

    def storage_usage(self, storage: str) -> Optional[StorageUsage]:
        """
        存储使用情况
        """
        if storage not in self._support_storages:
            return None
        storage_oper = self.__get_storage_oper(storage)
        if not storage_oper:
            logger.error(f"不支持 {storage} 的存储使用情况")
            return None
        return storage_oper.usage()

    def transfer(self, fileitem: FileItem, meta: MetaBase, mediainfo: MediaInfo,
                 target_directory: TransferDirectoryConf = None,
                 target_storage: Optional[str] = None, target_path: Path = None,
                 transfer_type: Optional[str] = None, scrape: Optional[bool] = None,
                 library_type_folder: Optional[bool] = None, library_category_folder: Optional[bool] = None,
                 episodes_info: List[TmdbEpisode] = None,
                 source_oper: Callable = None, target_oper: Callable = None,
                 preview: Optional[bool] = False) -> TransferInfo:
        """
        文件整理
        :param fileitem:  文件信息
        :param meta: 预识别的元数据
        :param mediainfo:  识别的媒体信息
        :param target_directory:  目标目录配置
        :param target_storage:  目标存储
        :param target_path:  目标路径
        :param transfer_type:  转移模式
        :param scrape: 是否刮削元数据
        :param library_type_folder: 是否按媒体类型创建目录
        :param library_category_folder: 是否按媒体类别创建目录
        :param episodes_info: 当前季的全部集信息
        :param source_oper: 源存储操作对象
        :param target_oper: 目标存储操作对象
        :return: {path, target_path, message}
        """
        handler = TransHandler()
        # 检查目录路径
        if fileitem.storage == "local" and not Path(fileitem.path).exists():
            return TransferInfo(success=False,
                                fileitem=fileitem,
                                message=f"{fileitem.path} 不存在")
        # 目标路径不能是文件
        if target_path and target_path.is_file():
            logger.error(f"整理目标路径 {target_path} 是一个文件")
            return TransferInfo(success=False,
                                fileitem=fileitem,
                                message=f"{target_path} 不是有效目录")
        # 获取目标路径
        if target_directory:
            # 目标媒体库目录未设置
            if not target_directory.library_path:
                logger.error(f"目标媒体库目录未设置，无法整理文件，源路径：{fileitem.path}")
                return TransferInfo(success=False,
                                    fileitem=fileitem,
                                    message="目标媒体库目录未设置")
            # 整理方式
            if not transfer_type:
                transfer_type = target_directory.transfer_type
            # 目标存储
            if not target_storage:
                target_storage = target_directory.library_storage
            # 是否需要重命名
            need_rename = target_directory.renaming
            # 是否需要通知
            need_notify = target_directory.notify
            # 覆盖模式
            overwrite_mode = target_directory.overwrite_mode
            # 是否需要刮削
            need_scrape = target_directory.scraping if scrape is None else scrape
            # 拼装媒体库一、二级子目录
            target_path = handler.get_dest_dir(mediainfo=mediainfo, target_dir=target_directory,
                                               need_type_folder=library_type_folder,
                                               need_category_folder=library_category_folder)
        elif target_path:
            need_scrape = scrape or False
            need_rename = True
            need_notify = False
            overwrite_mode = "never"
            # 手动整理的场景，有自定义目标路径
            target_path = handler.get_dest_path(mediainfo=mediainfo, target_path=target_path,
                                                need_type_folder=library_type_folder,
                                                need_category_folder=library_category_folder)
        else:
            # 未找到有效的媒体库目录
            logger.error(
                f"{mediainfo.type.value if mediainfo.type else '未知类型'} {mediainfo.title_year} 未找到有效的媒体库目录，无法整理文件，源路径：{fileitem.path}")
            return TransferInfo(success=False,
                                fileitem=fileitem,
                                message="未找到有效的媒体库目录")
        # 整理方式
        if not transfer_type:
            logger.error(f"{target_directory.name} 未设置整理方式")
            return TransferInfo(success=False,
                                fileitem=fileitem,
                                message=f"{target_directory.name} 未设置整理方式")

        # 源操作对象
        if not source_oper:
            source_oper = self.__get_storage_oper(fileitem.storage)
        if not source_oper:
            return TransferInfo(success=False,
                                message=f"不支持的存储类型：{fileitem.storage}",
                                fileitem=fileitem,
                                fail_list=[fileitem.path],
                                transfer_type=transfer_type,
                                need_notify=need_notify
                                )
        # 目的操作对象
        if not target_oper:
            if not target_storage:
                target_storage = fileitem.storage
            target_oper = self.__get_storage_oper(target_storage)
        if not target_oper:
            return TransferInfo(success=False,
                                message=f"不支持的存储类型：{target_storage}",
                                fileitem=fileitem,
                                fail_list=[fileitem.path],
                                transfer_type=transfer_type,
                                need_notify=need_notify)

        # 整理
        logger.info(f"获取整理目标路径：【{target_storage}】{target_path}")
        return handler.transfer_media(fileitem=fileitem,
                                      in_meta=meta,
                                      mediainfo=mediainfo,
                                      target_storage=target_storage,
                                      target_path=target_path,
                                      transfer_type=transfer_type,
                                      need_scrape=need_scrape,
                                      need_rename=need_rename,
                                      need_notify=need_notify,
                                      overwrite_mode=overwrite_mode,
                                      episodes_info=episodes_info,
                                      preview=preview,
                                      source_oper=source_oper,
                                      target_oper=target_oper)

    def media_files(self, mediainfo: MediaInfo) -> List[FileItem]:
        """
        获取对应媒体的媒体库文件列表
        :param mediainfo: 媒体信息
        """
        handler = TransHandler()
        ret_fileitems = []
        # 检查本地媒体库
        dest_dirs = DirectoryHelper().get_library_dirs()
        # 检查每一个媒体库目录
        for dest_dir in dest_dirs:
            # 存储
            storage_oper = self.__get_storage_oper(dest_dir.library_storage)
            if not storage_oper:
                continue
            # 媒体分类路径
            dir_path = handler.get_dest_dir(mediainfo=mediainfo, target_dir=dest_dir)
            # 重命名格式
            rename_format = settings.RENAME_FORMAT(mediainfo.type)
            # 元数据补上常用属性，尽可能确保重命名后的路径不出现空白
            meta = MetaInfo(mediainfo.title)
            if meta.type == MediaType.UNKNOWN and mediainfo.type is not None:
                meta.type = mediainfo.type
            if meta.year is None:
                meta.year = mediainfo.year
            if meta.begin_season is None:
                meta.begin_season = 1
            if meta.begin_episode is None:
                meta.begin_episode = 1
            # 获取路径（重命名路径）
            target_path = handler.get_rename_path(
                path=dir_path,
                template_string=rename_format,
                rename_dict=handler.get_naming_dict(meta=meta,
                                                    mediainfo=mediainfo)
            )
            # 获取重命名后的媒体文件根路径
            media_path = DirectoryHelper.get_media_root_path(
                rename_format, rename_path=target_path
            )
            if not media_path:
                # 忽略
                continue
            if dir_path != media_path and dir_path.is_relative_to(media_path):
                # 兜底检查，避免不必要的扫盘
                logger.warn(f"{media_path} 是媒体库目录 {dir_path} 的父目录，忽略获取媒体文件列表，请检查重命名格式！")
                continue
            # 检索媒体文件
            fileitem = storage_oper.get_item(media_path)
            if not fileitem:
                continue
            try:
                media_files = self.list_files(fileitem, True)
            except Exception as e:
                logger.debug(f"获取媒体文件列表失败：{str(e)}")
                continue
            if media_files:
                for media_file in media_files:
                    if f".{media_file.extension.lower()}" in settings.RMT_MEDIAEXT:
                        if media_file not in ret_fileitems:
                            ret_fileitems.append(media_file)
        return ret_fileitems

    def media_exists(self, mediainfo: MediaInfo, **kwargs) -> Optional[ExistMediaInfo]:
        """
        判断媒体文件是否存在于文件系统（网盘或本地文件），只支持标准媒体库结构
        :param mediainfo:  识别的媒体信息
        :param server:  指定媒体服务器名称时跳过本地文件系统检查
        :return: 如不存在返回None，存在时返回信息，包括每季已存在所有集{type: movie/tv, seasons: {season: [episodes]}}
        """
        if kwargs.get("server"):
            return None

        if not settings.LOCAL_EXISTS_SEARCH:
            return None

        logger.debug(f"正在本地媒体库中查找 {mediainfo.title_year}...")

        # 检查媒体库
        fileitems = self.media_files(mediainfo)
        if not fileitems:
            logger.debug(f"{mediainfo.title_year} 不在本地媒体库中")
            return None

        if mediainfo.type == MediaType.MOVIE:
            # 电影存在任何文件为存在
            logger.info(f"{mediainfo.title_year} 在本地文件系统中找到了")
            return ExistMediaInfo(type=MediaType.MOVIE)
        else:
            # 电视剧检索集数
            seasons: Dict[int, list] = {}
            for fileitem in fileitems:
                file_meta = MetaInfo(fileitem.basename)
                season_index = file_meta.begin_season if file_meta.begin_season is not None else 1
                episode_index = file_meta.begin_episode
                if not episode_index:
                    continue
                if season_index not in seasons:
                    seasons[season_index] = []
                if episode_index not in seasons[season_index]:
                    seasons[season_index].append(episode_index)
            # 返回剧集情况
            logger.info(f"{mediainfo.title_year} 在本地文件系统中找到了这些季集：{seasons}")
            return ExistMediaInfo(type=MediaType.TV, seasons=seasons)
