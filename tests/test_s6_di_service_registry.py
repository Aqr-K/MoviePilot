"""S6 DI #5：组合根服务注册表（composition-root registry）。

ServiceRegistry 让组合根（modules_initializer.init_modules / stop_modules）显式拥有其构造的
生命周期服务，替掉「stop 时重新 X() 取全局单例」的隐式反模式。

本测试覆盖：(1) ServiceRegistry 单元行为（register 返回实例便于链式、get、clear、未登记返回
None）；(2) **源码层**断言 init_modules 经 service_registry.register 登记服务、stop_modules 经
service_registry.get 取回。

注：不 import modules_initializer——它顶层 import agent_initializer → app.agent → jieba_next，
本 venv 缺包（预存环境限制）；改为直接读取其源码文件做结构断言，亦不触发真实启动/关闭
（会起线程 / 连 redis/db）。service_registry 本身是零依赖叶子，可正常 import。
"""
import unittest
from pathlib import Path

from app.startup.service_registry import ServiceRegistry, service_registry

_MODULES_INIT_SRC = (
    Path(__file__).resolve().parent.parent
    / "app" / "startup" / "modules_initializer.py"
).read_text(encoding="utf-8")


class ServiceRegistryUnitTest(unittest.TestCase):
    def setUp(self):
        self.reg = ServiceRegistry()

    def test_register_returns_instance_for_chaining(self):
        """register 原样返回实例（支持 register(name, X()).start() 链式）。"""
        sentinel = object()
        self.assertIs(sentinel, self.reg.register("svc", sentinel))

    def test_get_returns_registered_instance(self):
        sentinel = object()
        self.reg.register("svc", sentinel)
        self.assertIs(sentinel, self.reg.get("svc"))

    def test_get_unregistered_returns_none(self):
        self.assertIsNone(self.reg.get("missing"))

    def test_clear_empties_registry(self):
        self.reg.register("svc", object())
        self.reg.clear()
        self.assertIsNone(self.reg.get("svc"))

    def test_module_level_singleton_instance_is_a_registry(self):
        self.assertIsInstance(service_registry, ServiceRegistry)


class CompositionRootWiringTest(unittest.TestCase):
    """源码层验证组合根经注册表持有/取回生命周期服务（不执行真实 init/stop）。"""

    def test_init_modules_registers_only_lifecycle_services_with_stop(self):
        # 仅登记有 stop()、且 stop_modules 会取回的 3 个生命周期服务
        for name in ("display", "module_manager", "event_manager"):
            self.assertIn(
                f'service_registry.register("{name}"',
                _MODULES_INIT_SRC,
                f"init_modules 未经注册表登记 {name}",
            )
        # doh/sites/resource 无 stop()，不应登记进注册表（避免无用引用与语义误导）
        for name in ("doh", "sites", "resource"):
            self.assertNotIn(
                f'service_registry.register("{name}"',
                _MODULES_INIT_SRC,
                f"无 stop() 的 {name} 不应登记进注册表",
            )

    def test_init_modules_clears_registry_first(self):
        """init_modules 开头清空注册表（文档化单进程单次 init 假设 + 防御二次 init 残留）。"""
        self.assertIn("service_registry.clear()", _MODULES_INIT_SRC)

    def test_stop_modules_retrieves_from_registry_not_resingleton(self):
        for name in ("module_manager", "event_manager", "display"):
            self.assertIn(
                f'service_registry.get("{name}")',
                _MODULES_INIT_SRC,
                f"stop_modules 未从注册表取回 {name}",
            )
        # 不再重新 X() 取单例来 stop（反模式已替换）
        self.assertNotIn("ModuleManager().stop()", _MODULES_INIT_SRC)
        self.assertNotIn("EventManager().stop()", _MODULES_INIT_SRC)
        self.assertNotIn("DisplayHelper().stop()", _MODULES_INIT_SRC)


if __name__ == "__main__":
    unittest.main()
