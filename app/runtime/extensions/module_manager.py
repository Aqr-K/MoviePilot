import inspect
import threading
import traceback
from enum import Enum
from typing import Callable, Dict, Generator, Optional, Tuple, Any, Union, List

from app.runtime.config import settings
from app.runtime.events import EventHandlerBinding, eventmanager
from app.foundation.reflection import ModuleHelper
from app.runtime.extensions.contract import verify_module_contract, verify_module_type
from app.runtime.extensions.plugin_instance import plugin_id_of, qualify_module_id
from app.runtime.log import logger
from app.schemas.types import EventType, ModuleType, DownloaderType, MediaServerType, MessageChannel, StorageSchema, \
    OtherModulesType, MediaRecognizeType
from app.foundation.reflection import ObjectUtils
from app.foundation.singleton import Singleton


def subtype_value(subtype: Any) -> Optional[str]:
    """
    取子类型用于比较的字符串取值

    :param subtype: 子类型，枚举成员或字符串
    :return: 非空取值字符串，无法归一或为空时返回 None
    """
    value = subtype.value if isinstance(subtype, Enum) else subtype
    return value if isinstance(value, str) and value else None


def subtype_matches(declared: Any, expected: Any) -> bool:
    """
    判断模块声明的子类型是否与期望一致

    两侧都是枚举时按成员身份判定，避免不同枚举的同名取值互相误配；
    一侧为字符串时按取值判定，使外部来源可用字符串声明子类型。

    :param declared: 模块声明的子类型
    :param expected: 期望的子类型
    :return: 是否一致
    """
    if isinstance(declared, Enum) and isinstance(expected, Enum):
        return declared is expected
    declared_value = subtype_value(declared)
    return bool(declared_value) and declared_value == subtype_value(expected)


class ProvidedModule:
    """
    外部来源声明的一个系统模块

    :param module_cls: 模块类，契约校验针对该类进行
    :param module_id: 模块标识，缺省取类名
    :param factory: 实例构造器，缺省直接调用模块类
    :param expected_type: 期望的模块类型，非空时在契约校验之外追加类型校验
    """

    def __init__(self, module_cls: type, module_id: Optional[str] = None,
                 factory: Optional[Callable[[], Any]] = None,
                 expected_type: Optional[ModuleType] = None):
        """记录模块声明的类、标识、构造方式与期望类型"""
        self.module_cls = module_cls
        self.module_id = module_id or getattr(module_cls, "__name__", "")
        self.factory = factory
        self.expected_type = expected_type

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
            self.resolve_event_handler_instances,
        )
        self.load_modules()

    def resolve_event_handler_instances(
            self,
            owner_class: type,
    ) -> Optional[List[EventHandlerBinding]]:
        """
        为模块声明的事件方法解析当前全部运行实例

        同一个模块类可被多个来源以不同模块id注册，事件需要投递给其中每一个。

        :param owner_class: 声明事件方法的模块类
        :return: 事件绑定列表，该类未登记时返回 None
        """
        with self._lock:
            module_ids = list(dict.fromkeys(
                module_id for module_id, module_cls in self._modules.items()
                if module_id == owner_class.__name__ or module_cls is owner_class
            ))
            if not module_ids:
                return None
            modules = [(module_id, self._running_modules.get(module_id)) for module_id in module_ids]
        bindings = []
        for module_id, module in modules:
            owner_name = module_id
            if module and callable(getattr(module, "get_name", None)):
                owner_name = module.get_name()
            bindings.append(EventHandlerBinding(
                instance=module,
                owner_name=owner_name,
                instance_key=module_id,
            ))
        return bindings

    def load_modules(self):
        """
        加载所有模块
        """
        # 扫描模块目录
        modules = ModuleHelper.load(
            "app.modules",
            # 抽象基类满足契约方法却无法实例化，被包入口导出时会当成模块反复报错
            filter_func=lambda _, obj: hasattr(obj, 'init_module') and hasattr(obj, 'init_setting')
            and not inspect.isabstract(obj)
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

    def get_running_subtypes(self, module_type: ModuleType) -> List[str]:
        """
        取指定类型下全部运行模块的子类型取值

        :param module_type: 模块类型
        :return: 子类型取值列表，去重且保持运行态顺序
        """
        values: List[str] = []
        for module in self._running_snapshot():
            try:
                if module.get_type() != module_type:
                    continue
                value = subtype_value(module.get_subtype())
            except Exception as err:
                logger.debug(f"获取模块 {module.__class__.__name__} 类型信息出错：{str(err)}")
                continue
            if value and value not in values:
                values.append(value)
        return values

    def get_running_subtype_module(self, module_subtype: Union[SubType, str]) -> Generator:
        """
        获取指定子类型的模块

        子类型允许以枚举成员或字符串声明，两种形式互认。

        :param module_subtype: 期望的子类型
        :return: 命中的模块
        """
        for module in self._running_snapshot():
            probe = getattr(module, "get_subtype", None)
            if not callable(probe):
                continue
            try:
                declared = probe()
            except Exception as err:
                logger.debug(f"获取模块 {module.__class__.__name__} 子类型出错：{str(err)}")
                continue
            if subtype_matches(declared, module_subtype):
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

    def _subtype_holder(self, module_cls: type, module_id: str) -> Optional[str]:
        """
        查出已占用该模块子类型的其它运行模块

        按子类型精确分发时同一子类型只能有一个模块，否则外部来源可以静默顶替内建后端。
        子类型无法在类上取值或为空时不作判定。调用方需持锁。

        :param module_cls: 待注册的模块类
        :param module_id: 待注册的模块标识
        :return: 已占用该子类型的模块标识，未被占用时为 None
        """
        try:
            declared = subtype_value(module_cls.get_subtype())
        except Exception:
            return None
        if not declared:
            return None
        for running_id, running in self._running_modules.items():
            if running_id == module_id:
                continue
            try:
                if subtype_value(running.get_subtype()) == declared:
                    return running_id
            except Exception:
                continue
        return None

    def register_module(self, module: Union[type, ProvidedModule], owner: str) -> bool:
        """
        注册一个外部来源声明的模块，通过契约校验后按内建流程实例化并上线

        模块标识与已有模块重名且归属不同来源时拒绝注册，先到者胜；同一来源重复注册为幂等更新。
        非默认实例的声明按实例键限定模块标识，使同一插件的多个实例注册同一模块类时互不覆盖；
        限定只在同一插件内部消歧，声明自身的模块标识仍要与内建模块和其它插件的模块不重名，
        因此同一份声明在默认实例与分身实例上得到相同的接受或拒绝结果。

        :param module: 模块类或 ProvidedModule 声明
        :param owner: 注册来源的实例键，用于按来源精确卸载
        :return: 是否被接受进注册表，开关关闭或初始化失败不影响接受结果
        """
        if not owner:
            return False
        declaration = module if isinstance(module, ProvidedModule) else ProvidedModule(module)
        if not isinstance(declaration.module_cls, type):
            return False
        declared_id = declaration.module_id
        declaration = ProvidedModule(
            module_cls=declaration.module_cls,
            module_id=qualify_module_id(declared_id, owner),
            factory=declaration.factory,
            expected_type=declaration.expected_type,
        )
        module_id = declaration.module_id
        if declaration.expected_type is not None:
            passed, reasons = verify_module_type(declaration.module_cls, declaration.expected_type)
        else:
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
            if self._is_taken_by_others(declared_id, owner):
                logger.warning(
                    f"模块注册冲突：{declared_id} 已存在"
                    f"（owner={self._find_owner(declared_id) or 'builtin'}），"
                    f"拒绝来自 {owner} 的注册")
                return False
            holder = self._subtype_holder(declaration.module_cls, module_id)
            if holder:
                logger.warning(
                    f"模块注册冲突：子类型已被 {holder} 占用，拒绝来自 {owner} 的注册 {module_id}")
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

        :param owner: 注册来源的实例键
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

    def _is_taken_by_others(self, module_id: str, owner: str) -> bool:
        """
        判断未限定的模块标识是否已被内建模块或其它插件占用，调用方需持有 self._lock

        同一插件的不同实例共用一份声明，不算占用。

        :param module_id: 声明自身的模块标识
        :param owner: 注册来源的实例键
        :return: 是否被他人占用
        """
        if module_id not in self._modules:
            return False
        holder = self._find_owner(module_id)
        if holder is None:
            return True
        return plugin_id_of(holder) != plugin_id_of(owner)

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
