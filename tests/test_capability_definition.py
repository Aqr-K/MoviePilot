"""能力的单一定义。

「什么算能力」全库只能有一处定义，否则每加一个分发消费方都要先问「这个方法在哪套
定义下算能力」。定义落在 capability.provided_capabilities，分发注册表直接引用它。

判定按方法而非按类连坐：领域模块基类（媒体服务器、下载器、通知渠道的 *ModuleBase）
既提供管道也提供真业务能力——所有媒体服务器共享同一套认证实现，写在基类上是合理
设计，不是「管道」。把整个基类拉黑会把它上面的真能力一并判死。

真正只提供管道的是服务基类（ServiceBase 及其三个特化），它们给的是配置与实例管理：
init_service、get_instances、get_configs 之类，这些继续不计入能力。
"""
import threading
import unittest

from app.runtime.extensions.capability import (
    INFRASTRUCTURE_BASES,
    provided_capabilities,
)
from app.runtime.extensions.module_manager import ModuleManager


def _build_registry(module):
    """
    构造只认给定模块的注册表

    :param module: 运行态模块实例
    :return: 模块管理器
    """
    manager = object.__new__(ModuleManager)
    manager._lock = threading.RLock()
    manager._dispatch_index = {}
    manager._running_modules = {type(module).__name__: module}
    manager._running_snapshot = lambda: (module,)
    return manager


class CapabilityDefinitionTest(unittest.TestCase):
    """能力推导的归属判定"""

    def test_authentication_on_the_mediaserver_base_is_a_capability(self):
        """认证实现在媒体服务器基类上，仍是真能力而非管道。"""
        from app.modules.plex import PlexModule

        self.assertIn("user_authenticate", provided_capabilities(PlexModule))

    def test_media_existence_on_the_mediaserver_base_is_a_capability(self):
        """媒体存在性查询同样定义在基类上，同样是能力。"""
        from app.modules.plex import PlexModule

        self.assertIn("media_exists", provided_capabilities(PlexModule))

    def test_command_registration_on_the_channel_base_is_a_capability(self):
        """命令注册定义在通知渠道基类上，是能力。"""
        from app.modules.telegram import TelegramModule

        self.assertIn("register_commands", provided_capabilities(TelegramModule))

    def test_service_plumbing_is_not_a_capability(self):
        """服务基类给的是配置与实例管理管道，不计入能力。"""
        from app.modules.plex import PlexModule

        capabilities = provided_capabilities(PlexModule)
        for plumbing in ("get_instances", "get_instance", "get_configs", "init_service"):
            self.assertNotIn(plumbing, capabilities)

    def test_lifecycle_methods_are_not_capabilities(self):
        """生命周期与横切钩子不是能力。"""
        from app.modules.plex import PlexModule

        capabilities = provided_capabilities(PlexModule)
        for hook in ("init_module", "stop", "test", "scheduler_job", "clear_cache"):
            self.assertNotIn(hook, capabilities)

    def test_domain_module_bases_are_not_blacklisted(self):
        """领域模块基类不在基础设施黑名单里——它们提供领域能力。"""
        for domain_base in ("_MediaServerModuleBase", "_DownloaderModuleBase",
                            "_MessageChannelModuleBase"):
            self.assertNotIn(domain_base, INFRASTRUCTURE_BASES)

    def test_service_bases_stay_blacklisted(self):
        """服务基类仍在黑名单里——它们只提供管道。"""
        for service_base in ("ServiceBase", "_MediaServerBase", "_MessageBase",
                             "_DownloaderBase", "_ModuleBase", "ConfigReloadMixin"):
            self.assertIn(service_base, INFRASTRUCTURE_BASES)


class DispatchUsesTheSameDefinitionTest(unittest.TestCase):
    """分发注册表与能力定义必须是同一处"""

    def test_the_registry_accepts_a_capability_declared_on_a_base_class(self):
        """注册表按同一定义判定，基类上的能力照样能查到提供者。"""
        from app.modules.plex import PlexModule

        module = object.__new__(PlexModule)
        manager = _build_registry(module)

        self.assertEqual((module,), manager.providers_for("user_authenticate"))

    def test_the_registry_rejects_service_plumbing(self):
        """管道方法不构成能力，注册表不把它当提供者。"""
        from app.modules.plex import PlexModule

        module = object.__new__(PlexModule)
        manager = _build_registry(module)

        self.assertEqual((), manager.providers_for("get_instances"))


if __name__ == "__main__":
    unittest.main()
