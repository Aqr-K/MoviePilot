"""插件模块的能力适配。

插件在运行期交出模块类，它没有 manifest、也不落在一级模块包里，因此以独立 kind 接入
Capability Runtime：实现对象由声明直接携带而不按 entrypoint 导入，canonical 同一性
校验对它不成立。资源生命周期沿用宿主模块的 ``init_module``/``stop`` 合同。
"""
from __future__ import annotations

import threading
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Optional

from app.runtime.capabilities.model import (
    ActivationPolicy,
    AdapterExecutionMode,
    CapabilitySpec,
)
from app.schemas.types import ModuleType

PLUGIN_MODULE_KIND = "plugin_module"

# 插件模块的声明不来自文件，以该虚拟路径充当来源标识
PLUGIN_MANIFEST_SOURCE = Path("<plugin>")


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


def build_plugin_module_spec(module_id: str, module_cls: type) -> CapabilitySpec:
    """
    为一个插件模块声明构造能力声明

    插件模块不经配置 selector 判定启停，其启停由注册来源的生命周期决定，因此一律声明为
    bootstrap；模块自身的开关仍由 ``init_setting`` 在激活前判定。

    :param module_id: 模块标识，同时作为 capability id
    :param module_cls: 模块类，其模块路径与类名构成 entrypoint 标识
    :return: 能力声明
    """
    module_path = getattr(module_cls, "__module__", "__main__")
    symbol = getattr(module_cls, "__name__", module_id)
    return CapabilitySpec(
        schema_version=1,
        id=module_id,
        kind=PLUGIN_MODULE_KIND,
        entrypoint=f"{module_path}:{symbol}",
        activation=ActivationPolicy.BOOTSTRAP,
        metadata=MappingProxyType({}),
        selector=None,
        watch=(),
        depends_on=(),
        source=PLUGIN_MANIFEST_SOURCE,
    )


class PluginModuleAdapter:
    """把插件交出的模块类接入 Capability Runtime，实现对象随声明携带。"""

    execution_mode = AdapterExecutionMode.SYNC
    # 实现对象由插件声明直接携带，没有可比对的 canonical 模块符号
    requires_canonical_implementation = False

    def __init__(self) -> None:
        """初始化声明表与待用实例表"""
        self._declarations: Dict[str, ProvidedModule] = {}
        # 注册前已构造用于探测开关的实例，激活时直接取用，避免同一模块构造两次
        self._prepared: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def declare(self, capability_id: str, declaration: ProvidedModule,
                prepared: Optional[Any] = None) -> None:
        """
        登记一个模块声明及其待用实例

        :param capability_id: 能力标识
        :param declaration: 模块声明
        :param prepared: 已构造的实例，激活时直接取用
        """
        with self._lock:
            self._declarations[capability_id] = declaration
            if prepared is not None:
                self._prepared[capability_id] = prepared

    def forget(self, capability_id: str) -> None:
        """
        丢弃一个模块声明及其待用实例

        :param capability_id: 能力标识
        """
        with self._lock:
            self._declarations.pop(capability_id, None)
            self._prepared.pop(capability_id, None)

    def get_declaration(self, capability_id: str) -> Optional[ProvidedModule]:
        """
        取一个已登记的模块声明

        :param capability_id: 能力标识
        :return: 模块声明，未登记时为 None
        """
        with self._lock:
            return self._declarations.get(capability_id)

    def materialize(self, spec: CapabilitySpec) -> type:
        """
        取声明携带的模块类

        :param spec: 能力声明
        :return: 模块类
        """
        declaration = self.get_declaration(spec.id)
        if declaration is None:
            raise LookupError(f"插件模块 {spec.id} 没有登记声明")
        return declaration.module_cls

    def create(self, spec: CapabilitySpec, implementation: type,
               generation: int, previous: Any = None) -> Any:
        """
        取用待用实例或按声明构造实例；配置重载沿用原实例以保留模块语义

        :param spec: 能力声明
        :param implementation: 模块类
        :param generation: 代际
        :param previous: 上一代实例
        :return: 模块实例
        """
        del generation
        if previous is not None:
            return previous
        with self._lock:
            prepared = self._prepared.pop(spec.id, None)
        if prepared is not None:
            return prepared
        declaration = self.get_declaration(spec.id)
        return declaration.instantiate() if declaration else implementation()

    @staticmethod
    def start(spec: CapabilitySpec, candidate: Any, generation: int) -> None:
        """
        初始化实例持有的连接、线程或客户端资源

        :param spec: 能力声明
        :param candidate: 候选实例
        :param generation: 代际
        """
        del spec, generation
        candidate.init_module()

    @staticmethod
    def stop(spec: CapabilitySpec, instance: Any, generation: int) -> None:
        """
        停止实例持有的资源

        :param spec: 能力声明
        :param instance: 运行实例
        :param generation: 代际
        """
        del spec, generation
        instance.stop()

    @staticmethod
    def cleanup(spec: CapabilitySpec, candidate: Any, generation: int,
                error: BaseException) -> None:
        """
        回收启动失败的候选实例

        :param spec: 能力声明
        :param candidate: 候选实例
        :param generation: 代际
        :param error: 启动失败的异常
        """
        del spec, generation, error
        candidate.stop()
