from __future__ import annotations

import sys
import threading
from enum import Enum
from typing import Any, Generator, List, Optional, Tuple, Union

from app.foundation.reflection import ObjectUtils
from app.foundation.singleton import Singleton
from app.runtime.capabilities.model import (
    CapabilityLifecycleState,
    CapabilityObservation,
    CapabilitySpec,
)
from app.runtime.capabilities.runtime import CapabilityRuntime
from app.runtime.config import settings
from app.runtime.events import Event, EventHandlerBinding, eventmanager
from app.runtime.extensions.capability import (
    BUILTIN_ONLY_CAPABILITIES,
    provided_capabilities,
)
from app.runtime.extensions.contract import (
    verify_module_contract,
    verify_module_type,
)
from app.runtime.extensions.plugin_instance import plugin_id_of, qualify_module_id
from app.runtime.extensions.plugin_module_adapter import (
    PLUGIN_MODULE_KIND,
    PluginModuleAdapter,
    ProvidedModule,
    build_plugin_module_spec,
)
from app.runtime.extensions.host_module_adapter import (
    HOST_MODULE_KIND,
    HostModuleAdapter,
    build_host_module_registry,
    capture_host_module_config,
    should_run_host_module,
)
from app.runtime.log import logger
from app.schemas.types import (
    DownloaderType,
    EventType,
    MediaRecognizeType,
    MediaServerType,
    NotificationChannel,
    ModuleType,
    OtherModulesType,
    StorageSchema,
)


def _subtype_value(target: Any) -> Optional[str]:
    """
    取模块声明的子类型取值

    :param target: 模块类或模块实例
    :return: 非空取值字符串，无法取值或为空时返回 None
    """
    try:
        declared = target.get_subtype()
    except Exception:
        return None
    value = declared.value if isinstance(declared, Enum) else declared
    return value if isinstance(value, str) and value else None


class ModuleManager(metaclass=Singleton):
    """以 Capability Runtime 管理宿主模块与外部来源注册的模块。"""

    SubType = Union[
        DownloaderType,
        MediaServerType,
        NotificationChannel,
        StorageSchema,
        OtherModulesType,
        MediaRecognizeType,
    ]

    def __init__(self) -> None:
        """发现 data-only manifest，并按当前配置激活所需宿主模块。"""
        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._modules: dict[str, type] = {}
        self._running_modules: dict[str, Any] = {}
        # 多播与单播的查表结果：{(族类, 能力): (提供者, ...)}，运行态变化时整体丢弃
        self._dispatch_index: dict[tuple, tuple] = {}
        # 外部来源声明的模块按 owner 记账：{owner: [module_id, ...]}
        self._external_modules: dict[str, list[str]] = {}
        self._plugin_adapter = PluginModuleAdapter()
        registry = build_host_module_registry()
        registry.allow_kind(PLUGIN_MODULE_KIND)
        self._runtime = CapabilityRuntime(
            registry,
            adapters={
                HOST_MODULE_KIND: HostModuleAdapter(),
                PLUGIN_MODULE_KIND: self._plugin_adapter,
            },
            observer=self._observe_transition,
        )
        # pkgutil 的既有发现顺序按一级包名稳定排列，兼容视图继续保持该顺序。
        self._specs = tuple(
            sorted(self._runtime.list_specs(), key=lambda item: item.source.parent.name)
        )
        eventmanager.register_handler_instance_resolver(
            "modules",
            self.resolve_event_handler_instance,
        )
        eventmanager.add_event_listener(
            EventType.ConfigChanged,
            self.handle_config_changed,
        )
        self.load_modules()

    @staticmethod
    def _observe_transition(observation: CapabilityObservation) -> None:
        """把 Runtime 的稳定转换结果接入现有日志面。"""
        if observation.outcome == "failed":
            logger.error(
                "Host Module %s %s 失败：%s",
                observation.capability_id,
                observation.operation,
                observation.error,
            )
        elif observation.outcome == "succeeded":
            logger.debug(
                "Host Module %s %s 完成，generation=%s，耗时=%.2fms",
                observation.capability_id,
                observation.operation,
                observation.generation,
                observation.duration_ms,
            )

    @staticmethod
    def _event_changed_keys(event: Optional[Event]) -> set[str]:
        """兼容对象和 dict 两种配置事件载荷。"""
        if not event:
            return set()
        event_data = event.event_data
        if isinstance(event_data, dict):
            keys = event_data.get("key", set())
        else:
            keys = getattr(event_data, "key", set())
        if isinstance(keys, str):
            return {keys}
        return {str(key) for key in (keys or set())}

    def _remember_materialized(self, module_id: str, implementation: type) -> type:
        """更新旧 `_modules` 视图，但不改变能力资源生命周期。"""
        with self._lock:
            self._modules[module_id] = implementation
        return implementation

    def _consumer_materialized_class(self, spec: CapabilitySpec) -> Optional[type]:
        """识别插件显式旧导入产生的真实类，不触发新的 Python import。"""
        module_name, symbol_name = spec.entrypoint.split(":", maxsplit=1)
        module = sys.modules.get(module_name)
        namespace = getattr(module, "__dict__", None) if module is not None else None
        if not isinstance(namespace, dict):
            return None
        implementation = namespace.get(symbol_name)
        return implementation if isinstance(implementation, type) else None

    def _all_specs(self) -> tuple[CapabilitySpec, ...]:
        """取宿主与外部来源的全部声明；外部声明可在运行期增删，故每次向 Runtime 取。"""
        return self._runtime.list_specs()

    def _refresh_running_projection(self) -> None:
        """从 Runtime 已发布实例重建插件可见的运行模块字典。"""
        running = {
            spec.id: instance
            for spec in self._all_specs()
            if (instance := self._runtime.get_running(spec.id)) is not None
        }
        with self._lock:
            self._running_modules = running
            self._dispatch_index = {}

    def invalidate_dispatch_index(self) -> None:
        """
        丢弃分发注册表

        运行态模块集合变化后调用，使下次查询重新求值。
        """
        with self._lock:
            self._dispatch_index = {}

    def providers_for(self, module_type: ModuleType, method: str) -> tuple:
        """
        取某族类下提供指定能力的模块，按优先级排序

        多播与单播都是查询而非通知：它们只关心「这一类里谁能回答」，不需要触达全体。
        结果按 (族类, 能力) 记入注册表，命中后为 O(1)，只在运行态集合变化时重建。
        广播不走这里——它要触达全体，遍历本身就是它的语义。

        :param module_type: 模块族类
        :param method: 能力方法名
        :return: 按优先级升序排列的提供者
        """
        key = (module_type, method)
        with self._lock:
            cached = self._dispatch_index.get(key)
        if cached is not None:
            return cached
        providers = tuple(sorted(
            (
                module for module in self._running_snapshot()
                if self._provides(module, module_type, method)
            ),
            key=lambda module: module.get_priority(),
        ))
        with self._lock:
            self._dispatch_index[key] = providers
        return providers

    @staticmethod
    def _provides(module: Any, module_type: ModuleType, method: str) -> bool:
        """
        判断模块是否属于该族类并已实现该能力

        :param module: 运行态模块实例
        :param module_type: 期望的族类
        :param method: 能力方法名
        :return: 是否为该能力的提供者
        """
        try:
            if module.get_type() != module_type:
                return False
        except Exception as err:
            logger.debug(f"获取模块 {module.__class__.__name__} 族类出错：{str(err)}")
            return False
        candidate = getattr(module, method, None)
        return callable(candidate) and ObjectUtils.check_method(candidate)

    def resolve_event_handler_instance(
        self,
        owner_class: type,
    ) -> Optional[EventHandlerBinding]:
        """按 canonical class identity 绑定当前 generation，停止态阻断 fallback 构造。"""
        for spec in self._all_specs():
            with self._lock:
                implementation = self._modules.get(spec.id)
            if implementation is None:
                implementation = self._consumer_materialized_class(spec)
                if implementation is not None:
                    self._remember_materialized(spec.id, implementation)
                    # 同步 Runtime 的物化观测，但不创建或启动实例。
                    self._runtime.snapshot(spec.id)
            if implementation is not owner_class:
                continue
            return EventHandlerBinding(
                instance=self._runtime.get_running(spec.id),
                owner_name=str(spec.metadata.get("name", spec.id)),
            )
        return None

    def _reconcile(
        self,
        *,
        reason: str,
        changed_keys: Optional[set[str]] = None,
        reload_running: bool = False,
    ) -> None:
        """以一次配置快照串行协调需要启动、重载或停止的能力。"""
        with self._lifecycle_lock:
            selected = tuple(
                spec
                for spec in self._specs
                if changed_keys is None or changed_keys.intersection(spec.watch)
            )
            snapshot = capture_host_module_config(selected)
            for spec in selected:
                desired = should_run_host_module(spec, snapshot)
                running = self._runtime.get_running(spec.id)
                try:
                    if desired and running is None:
                        instance = self._runtime.activate(
                            spec.id,
                            reason=reason,
                            retry=True,
                        )
                        self._remember_materialized(spec.id, type(instance))
                    elif desired and running is not None and reload_running:
                        instance = self._runtime.reload(spec.id, reason=reason)
                        self._remember_materialized(spec.id, type(instance))
                    elif not desired and running is not None:
                        self._runtime.stop(spec.id, reason=reason)
                except Exception:
                    # 单能力失败由 Runtime 完整记录；其它无依赖能力继续 reconcile。
                    continue
            self._refresh_running_projection()

    def load_modules(self) -> None:
        """按当前配置启动未运行模块；已运行模块保持当前 generation。"""
        self._reconcile(reason="module_manager_load")
        self._reactivate_external_modules()

    def handle_config_changed(self, event: Event) -> None:
        """配置变更时仅协调 watch 命中的能力，并保证单一生命周期 writer。"""
        changed_keys = self._event_changed_keys(event)
        if not changed_keys:
            return
        self._reconcile(
            reason="config_changed",
            changed_keys=changed_keys,
            reload_running=True,
        )

    def stop(self) -> None:
        """停止全部运行模块但保留 Runtime，使旧插件可随后再次 load。"""
        logger.info("正在停止所有模块...")
        with self._lifecycle_lock:
            for spec in reversed(self._all_specs()):
                snapshot = self._runtime.snapshot(spec.id)
                if (
                    self._runtime.get_running(spec.id) is None
                    and snapshot.lifecycle is not CapabilityLifecycleState.FAILED
                ):
                    continue
                try:
                    self._runtime.stop(spec.id, reason="module_manager_stop")
                except Exception:
                    continue
            self._refresh_running_projection()
        logger.info("所有模块停止完成")

    def shutdown(self) -> None:
        """进程关闭时不可逆停止 Runtime，阻止并发能力重新发布。"""
        logger.info("正在关闭模块运行时...")
        with self._lifecycle_lock:
            self._runtime.shutdown(reason="application_shutdown")
            self._refresh_running_projection()
        logger.info("模块运行时关闭完成")

    def reload(self) -> None:
        """保留旧插件可观察的 stop、load、ModuleReload 同步顺序。"""
        with self._lifecycle_lock:
            self.stop()
            self.load_modules()
            eventmanager.send_event(etype=EventType.ModuleReload, data={})

    def test(self, modleid: str) -> Tuple[bool, str]:
        """测试已运行模块；未启用模块保持旧合同返回 `(False, "")`。"""
        module = self.get_running_module(modleid)
        if module is None:
            return False, ""
        if hasattr(module, "test") and ObjectUtils.check_method(module.test):
            result = module.test()
            return result if result else (False, "")
        return True, "模块不支持测试"

    @staticmethod
    def check_setting(setting: Optional[tuple]) -> bool:
        """保留旧模块开关的 truthy 与 membership 判定语义。"""
        if not setting:
            return True
        switch, value = setting
        option = getattr(settings, switch)
        if not option:
            return False
        if value is True:
            return True
        return value in option

    def get_running_module(self, module_id: str) -> Any:
        """根据模块 ID 返回已发布的运行实例，不触发物化。"""
        if not module_id or self._runtime.get_spec(module_id) is None:
            return None
        return self._runtime.get_running(module_id)

    def _running_snapshot(self) -> tuple[Any, ...]:
        """直接读取 Runtime 发布视图，转换期间不暴露旧或候选实例。"""
        return tuple(
            instance
            for spec in self._all_specs()
            if (instance := self._runtime.get_running(spec.id)) is not None
        )

    def get_running_modules(self, method: str) -> Generator:
        """返回实现了指定方法的运行模块快照。"""
        for module in self._running_snapshot():
            candidate = getattr(module, method, None)
            if callable(candidate) and ObjectUtils.check_method(candidate):
                yield module

    def get_running_type_modules(self, module_type: ModuleType) -> Generator:
        """返回指定类型的运行模块快照。"""
        for module in self._running_snapshot():
            if module.get_type() == module_type:
                yield module

    def get_running_subtype_module(self, module_subtype: SubType) -> Generator:
        """返回指定子类型的运行模块快照。"""
        for module in self._running_snapshot():
            if module.get_subtype() == module_subtype:
                yield module

    def get_module(self, module_id: str) -> Any:
        """显式物化并返回 canonical 模块类；失败保持旧合同返回 None。"""
        if not module_id or self._runtime.get_spec(module_id) is None:
            return None
        with self._lock:
            implementation = self._modules.get(module_id)
        if implementation is not None:
            return implementation
        try:
            implementation = self._runtime.materialize(
                module_id,
                reason="compat_get_module",
                retry=True,
            )
        except Exception:
            return None
        return self._remember_materialized(module_id, implementation)

    def get_modules(self) -> dict[str, type]:
        """兼容性显式物化全部真实类；单个失败不阻断其它模块。"""
        for spec in self._all_specs():
            self.get_module(spec.id)
        with self._lock:
            return dict(self._modules)

    def get_module_ids(self) -> List[str]:
        """从 manifest 返回全部模块 ID，不物化实现。"""
        return [spec.id for spec in self._all_specs()]

    def list_specs(self) -> tuple[CapabilitySpec, ...]:
        """返回全部轻量模块声明，包含物化或启动失败的能力。"""
        return self._all_specs()

    def get_specs(self) -> tuple[CapabilitySpec, ...]:
        """兼容内部调用命名，返回与 `list_specs` 相同的声明快照。"""
        return self.list_specs()

    def _find_owner(self, module_id: str) -> Optional[str]:
        """
        查找模块归属的外部来源，调用方需持有 self._lock

        :param module_id: 模块标识
        :return: 来源标识，内建模块或未注册返回 None
        """
        for owner, module_ids in self._external_modules.items():
            if module_id in module_ids:
                return owner
        return None

    def _is_taken_by_others(self, module_id: str, owner: str) -> bool:
        """
        判断未限定的模块标识是否已被内建模块或其它插件占用，调用方需持有 self._lock

        同一插件的不同实例共用一份声明，不算占用。

        :param module_id: 声明自身的模块标识
        :param owner: 注册来源的实例键
        :return: 是否被他人占用
        """
        if self._runtime.get_spec(module_id) is None:
            return False
        holder = self._find_owner(module_id)
        if holder is None:
            return True
        return plugin_id_of(holder) != plugin_id_of(owner)

    def _subtype_holder(self, module_cls: type, module_id: str) -> Optional[str]:
        """
        查出已占用该模块子类型的其它运行模块

        按子类型精确分发时同一子类型只能有一个模块，否则外部来源可以静默顶替内建后端。
        子类型无法在类上取值或为空时不作判定。

        :param module_cls: 待注册的模块类
        :param module_id: 待注册的模块标识
        :return: 已占用该子类型的模块标识，未被占用时为 None
        """
        declared = _subtype_value(module_cls)
        if not declared:
            return None
        with self._lock:
            running = dict(self._running_modules)
        for running_id, running_module in running.items():
            if running_id == module_id:
                continue
            if _subtype_value(running_module) == declared:
                return running_id
        return None

    def _prepare_module(self, declaration: ProvidedModule) -> Tuple[Any, bool]:
        """
        构造模块实例并判定其开关

        开关在实例上读取，因此必须先构造；构造出的实例交给 adapter 复用，同一模块不会
        为了读开关而构造两次。

        :param declaration: 模块声明
        :return: (实例, 开关是否打开)，构造失败时为 (None, False)
        """
        try:
            instance = declaration.instantiate()
        except Exception as err:
            logger.error(f"Load Module Error：{declaration.module_id}，{str(err)}", exc_info=True)
            return None, False
        try:
            return instance, self.check_setting(instance.init_setting())
        except Exception as err:
            logger.debug(f"读取模块 {declaration.module_id} 开关出错，按开启处理：{str(err)}")
            return instance, True

    def _detach_module(self, module_id: str) -> None:
        """
        停止并摘除一个外部模块声明

        :param module_id: 模块标识
        """
        try:
            self._runtime.unregister_capability(module_id, reason="plugin_unregister")
        except Exception as err:
            logger.debug(f"摘除模块 {module_id} 声明出错：{str(err)}")
        self._plugin_adapter.forget(module_id)
        with self._lock:
            self._modules.pop(module_id, None)
            self._running_modules.pop(module_id, None)

    def _activate_external(self, module_id: str, reason: str) -> None:
        """
        激活一个已登记的外部模块，失败由 Runtime 记录且不影响其它模块

        :param module_id: 模块标识
        :param reason: 记入观测的操作原因
        """
        try:
            instance = self._runtime.activate(module_id, reason=reason, retry=True)
        except Exception:
            return
        self._remember_materialized(module_id, type(instance))

    def register_module(self, module: Union[type, ProvidedModule], owner: str) -> bool:
        """
        注册一个外部来源声明的模块，通过契约校验后按内建流程实例化并上线

        模块标识与已有模块重名且归属不同来源时拒绝注册，先到者胜；同一来源重复注册为幂等更新。
        非默认实例的声明按实例键限定模块标识，使同一插件的多个实例注册同一模块类时互不覆盖；
        限定只在同一插件内部消歧，声明自身的模块标识仍要与内建模块和其它插件的模块不重名。

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
        module_id = qualify_module_id(declared_id, owner)
        declaration = ProvidedModule(
            module_cls=declaration.module_cls,
            module_id=module_id,
            factory=declaration.factory,
            expected_type=declaration.expected_type,
        )
        if declaration.expected_type is not None:
            passed, reasons = verify_module_type(declaration.module_cls, declaration.expected_type)
        else:
            passed, reasons = verify_module_contract(declaration.module_cls)
        if not passed:
            logger.warning(f"模块 {module_id}（owner={owner}）未通过契约校验，拒绝注册：{'；'.join(reasons)}")
            return False
        reserved = sorted(provided_capabilities(declaration.module_cls) & BUILTIN_ONLY_CAPABILITIES)
        if reserved:
            logger.warning(
                f"模块 {module_id}（owner={owner}）声明了内建独占能力，拒绝注册：{'、'.join(reserved)}")
            return False
        with self._lifecycle_lock:
            with self._lock:
                existing_owner = self._find_owner(module_id)
                if self._runtime.get_spec(module_id) is not None and existing_owner != owner:
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
            # 同一来源重复注册为幂等更新，先摘旧声明再登记新的
            self._detach_module(module_id)
            prepared, enabled = self._prepare_module(declaration)
            self._plugin_adapter.declare(module_id, declaration, prepared if enabled else None)
            try:
                self._runtime.register_capability(build_plugin_module_spec(module_id, declaration.module_cls))
            except Exception as err:
                logger.warning(f"模块 {module_id}（owner={owner}）登记声明失败：{str(err)}")
                self._plugin_adapter.forget(module_id)
                return False
            with self._lock:
                registered = self._external_modules.setdefault(owner, [])
                if module_id not in registered:
                    registered.append(module_id)
            if enabled:
                self._activate_external(module_id, reason="plugin_register")
            self._refresh_running_projection()
            return True

    def unregister_modules(self, owner: str) -> List[str]:
        """
        卸载某来源注册的全部模块，停止运行实例并从注册表移除

        :param owner: 注册来源的实例键
        :return: 被移除的模块id列表
        """
        if not owner:
            return []
        with self._lock:
            module_ids = list(self._external_modules.pop(owner, []))
        if not module_ids:
            return []
        with self._lifecycle_lock:
            for module_id in module_ids:
                self._detach_module(module_id)
            self._refresh_running_projection()
        return module_ids

    def get_external_module_ids(self, owner: Optional[str] = None) -> List[str]:
        """
        获取外部来源注册的模块id列表

        :param owner: 注册来源标识，为空时返回全部来源
        :return: 模块id列表
        """
        with self._lock:
            if owner is not None:
                return list(self._external_modules.get(owner, []))
            return [module_id
                    for module_ids in self._external_modules.values()
                    for module_id in module_ids]

    def _reactivate_external_modules(self) -> None:
        """整体重载后让已登记的外部模块重新上线，其声明不随重载丢失。"""
        with self._lock:
            module_ids = [module_id
                          for module_ids in self._external_modules.values()
                          for module_id in module_ids]
        if not module_ids:
            return
        with self._lifecycle_lock:
            for module_id in module_ids:
                if self._runtime.get_running(module_id) is not None:
                    continue
                declaration = self._plugin_adapter.get_declaration(module_id)
                if declaration is None:
                    continue
                prepared, enabled = self._prepare_module(declaration)
                if not enabled:
                    continue
                self._plugin_adapter.declare(module_id, declaration, prepared)
                self._activate_external(module_id, reason="module_manager_load")
            self._refresh_running_projection()
