import threading
import traceback
from enum import Enum
from typing import Generator, Optional, Tuple, Any, Union, List, Dict

from app.core.config import settings
from app.core.event import eventmanager
from app.core.module.contract import (
    verify_module_contract as _verify_module_contract,
    verify_data_source_contract as _verify_data_source_contract,
    verify_downloader_contract as _verify_downloader_contract,
    verify_notification_contract as _verify_notification_contract,
    verify_mediaserver_contract as _verify_mediaserver_contract,
    _verify_typed_contract as _verify_typed_contract,
)
from app.core.module.loader import ModuleHelper
from app.log import logger
from app.schemas.types import EventType, ModuleType, DownloaderType, MediaServerType, MessageChannel, StorageSchema, \
    OtherModulesType
from app.utils.object import ObjectUtils
from app.utils.singleton import Singleton


class ModuleManager(metaclass=Singleton):
    """
    模块管理器
    """

    # 子模块类型集合（兼容传入纯字符串子类型标识）
    SubType = Union[DownloaderType, MediaServerType, MessageChannel, StorageSchema, OtherModulesType, str]

    def __init__(self):
        # 模块列表
        self._modules: dict = {}
        # 运行态模块列表
        self._running_modules: dict = {}
        # 外部(插件)注册的模块类，按 owner 记账：{owner: [module_cls, ...]}
        # 作为与静态扫描并列的二级源，存类对象以便 reload 全量重扫后重放，挺过重扫不丢失。
        self._external_classes: Dict[str, List[type]] = {}
        # 保护 _modules/_running_modules/_external_classes 运行期并发读写的可重入锁
        self._lock = threading.RLock()
        self.load_modules()

    def load_modules(self):
        """
        加载所有模块
        """
        with self._lock:
            # 扫描模块目录
            modules = ModuleHelper.load(
                "app.modules",
                filter_func=lambda _, obj: hasattr(obj, 'init_module') and hasattr(obj, 'init_setting')
            )
            self._running_modules = {}
            self._modules = {}
            for module in modules:
                module_id = module.__name__
                self._modules[module_id] = module
                try:
                    # 生成实例
                    _module = module()
                    # 初始化模块
                    if self.check_setting(_module.init_setting()):
                        # 通过模板开关控制加载
                        _module.init_module()
                        self._running_modules[module_id] = _module
                        logger.debug(f"Moudle Loaded：{module_id}")
                except Exception as err:
                    logger.error(f"Load Moudle Error：{module_id}，{str(err)} - {traceback.format_exc()}", exc_info=True)
            # 重放外部(插件)注册的模块，使其挺过 reload 的全量重扫
            self._replay_external_modules()

    def stop(self):
        """
        停止所有模块
        """
        logger.info("正在停止所有模块...")
        for module_id, module in list(self._running_modules.items()):
            try:
                module.stop()
                logger.debug(f"Moudle Stoped：{module_id}")
            except Exception as err:
                logger.error(f"Stop Moudle Error：{module_id}，{str(err)} - {traceback.format_exc()}", exc_info=True)
        logger.info("所有模块停止完成")

    def reload(self):
        """
        重新加载所有模块
        """
        self.stop()
        self.load_modules()
        eventmanager.send_event(etype=EventType.ModuleReload, data={})

    def test(self, modleid: str) -> Tuple[bool, str]:
        """
        测试模块
        """
        if modleid not in self._running_modules:
            return False, ""
        module = self._running_modules[modleid]
        if hasattr(module, "test") \
                and ObjectUtils.check_method(getattr(module, "test")):
            result = module.test()
            if not result:
                return False, ""
            return result
        return True, "模块不支持测试"

    @staticmethod
    def check_setting(setting: Optional[tuple]) -> bool:
        """
        检查开关是否己打开，开关使用,分隔多个值，符合其中即代表开启
        """
        if not setting:
            return True
        switch, value = setting
        option = getattr(settings, switch)
        if not option:
            return False
        if option and value is True:
            return True
        if value in option:
            return True
        return False

    def get_running_module(self, module_id: str) -> Any:
        """
        根据模块id获取模块运行实例
        """
        if not module_id:
            return None
        if not self._running_modules:
            return None
        return self._running_modules.get(module_id)

    def get_running_modules(self, method: str) -> Generator:
        """
        获取实现了同一方法的模块列表
        """
        if not self._running_modules:
            return
        for _, module in list(self._running_modules.items()):
            if hasattr(module, method) \
                    and ObjectUtils.check_method(getattr(module, method)):
                yield module

    def get_running_type_modules(self, module_type: ModuleType) -> Generator:
        """
        获取指定类型的模块列表
        """
        if not self._running_modules:
            return
        for _, module in list(self._running_modules.items()):
            if hasattr(module, 'get_type') \
                    and module.get_type() == module_type:
                yield module

    @staticmethod
    def _coerce_subtype(value) -> Optional[str]:
        """
        将子类型（Enum 或字符串）归一化为字符串标识，None 原样返回 None。
        使内建 Enum 子类型与插件纯字符串子类型可统一比较。
        """
        if value is None:
            return None
        if isinstance(value, Enum):
            return str(value.value)
        return str(value)

    def get_running_subtype_module(self, module_subtype: SubType) -> Generator:
        """
        获取指定子类型的模块。按字符串标识相等匹配，同时兼容 Enum 与纯字符串子类型：
        查询参数与模块的 get_subtype_id() 均归一化为字符串后比较，使插件无需扩展封闭枚举
        即可新增子类型。
        """
        if not self._running_modules:
            return
        target = self._coerce_subtype(module_subtype)
        if target is None:
            return
        for _, module in list(self._running_modules.items()):
            getter = getattr(module, 'get_subtype_id', None)
            if getter is not None:
                value = self._coerce_subtype(getter())
            else:
                legacy = getattr(module, 'get_subtype', None)
                value = self._coerce_subtype(legacy()) if legacy else None
            if value is not None and value == target:
                yield module

    def get_module(self, module_id: str) -> Any:
        """
        根据模块id获取模块
        """
        if not module_id:
            return None
        if not self._modules:
            return None
        return self._modules.get(module_id)

    def get_modules(self) -> dict:
        """
        获取模块列表
        """
        return self._modules

    def get_module_ids(self) -> List[str]:
        """
        获取模块id列表
        """
        return list(self._modules.keys())

    # ---------------------------------------------------------------------
    # 外部(插件)模块二级注册：与静态扫描并列的来源。外部模块经 register 进入
    # _running_modules 后，被 chain 分发层(仅按 method 名 + get_priority 取模块)
    # 无差别接管，无需改动分发链。运行期线程安全，支持热插拔。
    # ---------------------------------------------------------------------

    # 契约校验家族已抽至 app.core.module.contract（独立、轻量、可被 plugin_manager 直接 import）。
    # 此处以静态方法别名再导出，保持 ModuleManager.verify_*_contract 与 register_module 内部
    # self.verify_module_contract 调用零改动；plugin_manager.py 仍按 ModuleManager.verify_*_contract 取引用。
    verify_module_contract = staticmethod(_verify_module_contract)
    verify_data_source_contract = staticmethod(_verify_data_source_contract)
    verify_downloader_contract = staticmethod(_verify_downloader_contract)
    verify_notification_contract = staticmethod(_verify_notification_contract)
    verify_mediaserver_contract = staticmethod(_verify_mediaserver_contract)
    _verify_typed_contract = staticmethod(_verify_typed_contract)

    def register_module(self, module_cls: type, owner: str) -> bool:
        """
        注册一个外部(插件)模块类。复用内建加载流程(check_setting/init_setting/init_module)，
        成功后进入 _running_modules 即可被分发。owner 用于按来源精确回收(unregister)。

        :param module_cls: 模块类，需实现 _ModuleBase 契约(init_module/init_setting/stop/test 等)
        :param owner: 注册来源标识(通常为 plugin_id)，用于精确卸载
        :return: 是否被接受进注册表(命名冲突或非法入参返回 False；
                 被接受但因开关关闭/初始化异常未上线仍返回 True，运行态另由分发查询体现)
        """
        if not owner or not isinstance(module_cls, type):
            return False
        module_id = module_cls.__name__
        # 验证注册：校验 _ModuleBase 基类契约，不通过直接拒绝（严格注册）。
        # register_module 系 v3-python 新增且未发布，无外部插件依赖宽松行为，故不保留注入兼容路径。
        _ok, _reasons = self.verify_module_contract(module_cls)
        if not _ok:
            logger.warning(
                f"模块 {module_id}(owner={owner}) 未通过 _ModuleBase 契约校验，拒绝注册："
                f"{'；'.join(_reasons)}。请使其继承 app.modules._ModuleBase 并实现完整契约。")
            return False
        with self._lock:
            # 命名冲突：已存在且不归属本 owner(内建或他插件) → 拒绝，避免遮蔽
            existing_owner = self._find_owner(module_id)
            if module_id in self._modules and existing_owner != owner:
                logger.warning(
                    f"模块注册冲突：{module_id} 已存在(owner={existing_owner or 'builtin'})，"
                    f"拒绝来自 {owner} 的注册")
                return False
            # 记账(幂等：同 owner 重复注册不产生重复记录)
            owner_classes = self._external_classes.setdefault(owner, [])
            if module_cls not in owner_classes:
                owner_classes.append(module_cls)
            # 激活(进入 _modules/_running_modules)
            self._activate_module(module_cls, owner)
            return True

    def unregister_modules(self, owner: str) -> List[str]:
        """
        卸载某来源(owner)注册的全部外部模块，停止其运行实例并从注册表移除，无僵尸残留。

        :param owner: 注册来源标识
        :return: 被移除的 module_id 列表
        """
        if not owner:
            return []
        removed: List[str] = []
        with self._lock:
            classes = self._external_classes.pop(owner, [])
            for module_cls in classes:
                module_id = module_cls.__name__
                running = self._running_modules.pop(module_id, None)
                if running is not None and hasattr(running, "stop"):
                    try:
                        running.stop()
                    except Exception as err:
                        logger.error(f"Stop Module Error：{module_id}，{str(err)} - {traceback.format_exc()}",
                                     exc_info=True)
                self._modules.pop(module_id, None)
                removed.append(module_id)
        return removed

    def get_external_module_ids(self, owner: Optional[str] = None) -> List[str]:
        """
        获取外部(插件)注册的模块id列表。owner 为空时返回全部来源。
        """
        with self._lock:
            if owner is not None:
                return [cls.__name__ for cls in self._external_classes.get(owner, [])]
            return [cls.__name__
                    for classes in self._external_classes.values()
                    for cls in classes]

    def _activate_module(self, module_cls: type, owner: Optional[str] = None) -> bool:
        """
        实例化并初始化一个模块类，写入 _modules，开关通过则写入 _running_modules。
        异常被捕获并隔离，不影响其它模块。调用方需持有 self._lock。

        :return: 是否成功进入运行态
        """
        module_id = module_cls.__name__
        self._modules[module_id] = module_cls
        try:
            _module = module_cls()
            if self.check_setting(_module.init_setting()):
                _module.init_module()
                self._running_modules[module_id] = _module
                logger.debug(f"Module Loaded：{module_id}" + (f"（owner={owner}）" if owner else ""))
                return True
            return False
        except Exception as err:
            logger.error(f"Load Module Error：{module_id}，{str(err)} - {traceback.format_exc()}", exc_info=True)
            return False

    def _replay_external_modules(self):
        """
        重放外部注册的模块类(reload 全量重扫后调用)。调用方需持有 self._lock。
        """
        for owner, classes in list(self._external_classes.items()):
            for module_cls in classes:
                self._activate_module(module_cls, owner)

    def _find_owner(self, module_id: str) -> Optional[str]:
        """
        查找某 module_id 归属的外部 owner，未注册或为内建模块返回 None。调用方需持有 self._lock。
        """
        for owner, classes in self._external_classes.items():
            if any(cls.__name__ == module_id for cls in classes):
                return owner
        return None
