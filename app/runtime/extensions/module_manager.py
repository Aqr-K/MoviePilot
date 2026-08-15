import threading
import traceback
from typing import Callable, Dict, Generator, Optional, Tuple, Any, Union, List

from app.runtime.config import settings
from app.runtime.events import EventHandlerBinding, eventmanager
from app.foundation.reflection import ModuleHelper
from app.runtime.extensions.contract import verify_module_contract
from app.runtime.log import logger
from app.schemas.types import EventType, ModuleType, DownloaderType, MediaServerType, MessageChannel, StorageSchema, \
    OtherModulesType, MediaRecognizeType
from app.foundation.reflection import ObjectUtils
from app.foundation.singleton import Singleton


class ProvidedModule:
    """
    外部来源声明的一个系统模块

    :param module_cls: 模块类，契约校验针对该类进行
    :param module_id: 模块标识，缺省取类名
    :param factory: 实例构造器，缺省直接调用模块类
    """

    def __init__(self, module_cls: type, module_id: Optional[str] = None,
                 factory: Optional[Callable[[], Any]] = None):
        """记录模块声明的类、标识与构造方式"""
        self.module_cls = module_cls
        self.module_id = module_id or getattr(module_cls, "__name__", "")
        self.factory = factory

    def instantiate(self) -> Any:
        """
        按声明构造模块实例

        :return: 模块实例
        """
        return self.factory() if self.factory else self.module_cls()

    def __repr__(self) -> str:
        """以模块标识标识声明本身"""
        return f"ProvidedModule({self.module_id})"


class ModuleManager(metaclass=Singleton):
    """
    模块管理器
    """

    # 子模块类型集合
    SubType = Union[
        DownloaderType,
        MediaServerType,
        MessageChannel,
        StorageSchema,
        OtherModulesType,
        MediaRecognizeType,
    ]

    def __init__(self):
        """初始化模块注册表并装载当前启用的运行模块。"""
        # 模块列表
        self._modules: dict = {}
        # 运行态模块列表
        self._running_modules: dict = {}
        # 外部来源声明的模块，按 owner 记账：{owner: [ProvidedModule, ...]}
        # 存声明而非实例，使外部模块可在全量重扫后重新上线
        self._external_classes: Dict[str, List[ProvidedModule]] = {}
        # 保护三张注册表的运行期并发读写
        self._lock = threading.RLock()
        # 事件总线通过该解析器绑定已启用的模块实例。
        eventmanager.register_handler_instance_resolver(
            "modules",
            self.resolve_event_handler_instance,
        )
        self.load_modules()

    def resolve_event_handler_instance(
            self,
            owner_class: type,
    ) -> Optional[EventHandlerBinding]:
        """为模块声明的事件方法解析当前运行实例。"""
        module_id = owner_class.__name__
        with self._lock:
            if module_id not in self._modules:
                return None
            module = self._running_modules.get(module_id)
        owner_name = module_id
        if module and callable(getattr(module, "get_name", None)):
            owner_name = module.get_name()
        return EventHandlerBinding(
            instance=module,
            owner_name=owner_name,
        )

    def load_modules(self):
        """
        加载所有模块
        """
        # 扫描模块目录
        modules = ModuleHelper.load(
            "app.modules",
            filter_func=lambda _, obj: hasattr(obj, 'init_module') and hasattr(obj, 'init_setting')
        )
        with self._lock:
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
                    logger.error(f"Load Moudle Error：{module_id}，{str(err)} - {traceback.format_exc()}",
                                 exc_info=True)
            # 全量重扫会清空注册表，外部模块需按声明重新上线
            self._replay_external_modules()

    def stop(self):
        """
        停止所有模块
        """
        logger.info("正在停止所有模块...")
        with self._lock:
            running_modules = list(self._running_modules.items())
        for module_id, module in running_modules:
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
        module = self.get_running_module(modleid)
        if module is None:
            return False, ""
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

    def _running_snapshot(self) -> List[Any]:
        """
        取运行态模块实例的快照，使遍历不受运行期注册和卸载影响

        :return: 运行态模块实例列表
        """
        with self._lock:
            return list(self._running_modules.values())

    def get_running_module(self, module_id: str) -> Any:
        """
        根据模块id获取模块运行实例
        """
        if not module_id:
            return None
        with self._lock:
            return self._running_modules.get(module_id)

    def get_running_modules(self, method: str) -> Generator:
        """
        获取实现了同一方法的模块列表
        """
        for module in self._running_snapshot():
            if hasattr(module, method) \
                    and ObjectUtils.check_method(getattr(module, method)):
                yield module

    def get_running_type_modules(self, module_type: ModuleType) -> Generator:
        """
        获取指定类型的模块列表
        """
        for module in self._running_snapshot():
            if hasattr(module, 'get_type') \
                    and module.get_type() == module_type:
                yield module

    def get_running_subtype_module(self, module_subtype: SubType) -> Generator:
        """
        获取指定子类型的模块
        """
        for module in self._running_snapshot():
            if hasattr(module, 'get_subtype') \
                    and module.get_subtype() == module_subtype:
                yield module

    def get_module(self, module_id: str) -> Any:
        """
        根据模块id获取模块
        """
        if not module_id:
            return None
        with self._lock:
            return self._modules.get(module_id)

    def get_modules(self) -> dict:
        """
        获取模块列表
        """
        with self._lock:
            return dict(self._modules)

    def get_module_ids(self) -> List[str]:
        """
        获取模块id列表
        """
        with self._lock:
            return list(self._modules.keys())

    def register_module(self, module: Union[type, ProvidedModule], owner: str) -> bool:
        """
        注册一个外部来源声明的模块，通过契约校验后按内建流程实例化并上线

        模块标识与已有模块重名且归属不同来源时拒绝注册，先到者胜；同一来源重复注册为幂等更新。

        :param module: 模块类或 ProvidedModule 声明
        :param owner: 注册来源标识，用于按来源精确卸载
        :return: 是否被接受进注册表，开关关闭或初始化失败不影响接受结果
        """
        if not owner:
            return False
        declaration = module if isinstance(module, ProvidedModule) else ProvidedModule(module)
        if not isinstance(declaration.module_cls, type):
            return False
        module_id = declaration.module_id
        passed, reasons = verify_module_contract(declaration.module_cls)
        if not passed:
            logger.warning(f"模块 {module_id}（owner={owner}）未通过契约校验，拒绝注册：{'；'.join(reasons)}")
            return False
        with self._lock:
            existing_owner = self._find_owner(module_id)
            if module_id in self._modules and existing_owner != owner:
                logger.warning(
                    f"模块注册冲突：{module_id} 已存在（owner={existing_owner or 'builtin'}），"
                    f"拒绝来自 {owner} 的注册")
                return False
            declared = self._external_classes.get(owner, [])
            self._external_classes[owner] = [
                item for item in declared if item.module_id != module_id
            ] + [declaration]
            self._activate_module(declaration, owner)
            return True

    def unregister_modules(self, owner: str) -> List[str]:
        """
        卸载某来源注册的全部模块，停止运行实例并从注册表移除

        :param owner: 注册来源标识
        :return: 被移除的模块id列表
        """
        if not owner:
            return []
        removed: List[str] = []
        with self._lock:
            for declaration in self._external_classes.pop(owner, []):
                module_id = declaration.module_id
                running = self._running_modules.pop(module_id, None)
                self._modules.pop(module_id, None)
                removed.append(module_id)
                if running is None or not hasattr(running, "stop"):
                    continue
                try:
                    running.stop()
                except Exception as err:
                    logger.error(f"Stop Module Error：{module_id}，{str(err)} - {traceback.format_exc()}",
                                 exc_info=True)
        return removed

    def get_external_module_ids(self, owner: Optional[str] = None) -> List[str]:
        """
        获取外部来源注册的模块id列表

        :param owner: 注册来源标识，为空时返回全部来源
        :return: 模块id列表
        """
        with self._lock:
            if owner is not None:
                return [item.module_id for item in self._external_classes.get(owner, [])]
            return [item.module_id
                    for declared in self._external_classes.values()
                    for item in declared]

    def _activate_module(self, declaration: ProvidedModule, owner: Optional[str] = None) -> bool:
        """
        实例化并初始化一个模块声明，开关通过则进入运行态，异常逐模块隔离

        调用方需持有 self._lock。

        :param declaration: 模块声明
        :param owner: 注册来源标识
        :return: 是否进入运行态
        """
        module_id = declaration.module_id
        self._modules[module_id] = declaration.module_cls
        try:
            instance = declaration.instantiate()
            if not self.check_setting(instance.init_setting()):
                return False
            instance.init_module()
            self._running_modules[module_id] = instance
            logger.debug(f"Module Loaded：{module_id}" + (f"（owner={owner}）" if owner else ""))
            return True
        except Exception as err:
            logger.error(f"Load Module Error：{module_id}，{str(err)} - {traceback.format_exc()}", exc_info=True)
            return False

    def _replay_external_modules(self) -> None:
        """按已记账的声明重新上线全部外部模块，调用方需持有 self._lock。"""
        for owner, declared in list(self._external_classes.items()):
            for declaration in declared:
                self._activate_module(declaration, owner)

    def _find_owner(self, module_id: str) -> Optional[str]:
        """
        查找模块id归属的外部来源，调用方需持有 self._lock

        :param module_id: 模块id
        :return: 来源标识，内建模块或未注册返回 None
        """
        for owner, declared in self._external_classes.items():
            if any(item.module_id == module_id for item in declared):
                return owner
        return None
