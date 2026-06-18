"""组合根服务注册表（composition-root registry）。

S6 DI：让组合根（app/startup/modules_initializer.py 的 init_modules / stop_modules）
**显式拥有**其构造的生命周期服务实例，替掉「stop 时重新 `X()` 取全局单例」的隐式反模式
（依赖 Singleton 元类在 init/stop 两处返回同一实例）。

本注册表**只在组合根内部使用**，不作为随处可取的服务定位器——那正是 S6 要消除的访问
模式。它是组合根对其所拥有服务的显式清单与生命周期句柄，也是后续逐步去单例（让这些服务
不再全局可取、改由注册表唯一持有）的落点。

无任何外部依赖（仅 typing），是叶子模块。
"""
from typing import Any, Dict, Optional


class ServiceRegistry:
    """组合根持有的服务实例注册表（按名登记 / 取用 / 清空）。"""

    def __init__(self):
        self._services: Dict[str, Any] = {}

    def register(self, name: str, instance: Any) -> Any:
        """登记一个服务实例并原样返回（便于 register(name, X()).start() 链式调用）。"""
        self._services[name] = instance
        return instance

    def get(self, name: str) -> Optional[Any]:
        """取登记的服务实例；未登记返回 None。"""
        return self._services.get(name)

    def clear(self) -> None:
        """清空注册表（测试隔离用）。"""
        self._services.clear()


# 组合根的全局注册表实例（仅组合根使用）
service_registry = ServiceRegistry()
