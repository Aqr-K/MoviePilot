"""插件认证等级校验。

插件以 auth_level 声明自己的可见门槛，当前站点的认证等级由启动组合根注入，未装配时按
未认证处理。等级 99 的插件额外要求公私钥配对，私钥只从进程环境变量读取，因此该校验的
结论仅在当前进程内成立。
"""
import os
from typing import Any, Callable, Optional, Type, Union

from app import schemas
from app.foundation.crypto import RSAUtils
from app.runtime.log import logger

SiteAuthLevelProvider = Callable[[], int]


def _unavailable_site_auth_level() -> int:
    """站点能力尚未装配时返回未认证等级。"""
    return 0


_site_auth_level_provider: SiteAuthLevelProvider = _unavailable_site_auth_level


def configure_site_auth_level_provider(provider: SiteAuthLevelProvider) -> None:
    """由启动组合根注入站点认证等级，避免扩展运行时依赖应用服务。"""
    global _site_auth_level_provider
    _site_auth_level_provider = provider


def set_and_check_auth_level(plugin: Union[schemas.Plugin, Type[Any]],
                             source: Optional[Union[dict, Type[Any]]] = None) -> bool:
    """
    设置并检查插件的认证级别
    :param plugin: 插件对象或包含 auth_level 属性的对象
    :param source: 可选的字典对象或类对象，可能包含 "level" 或 "auth_level" 键
    :return: 如果插件的认证级别有效且当前环境的认证级别满足要求，返回 True，否则返回 False
    """
    # 检查并赋值 source 中的 level 或 auth_level
    if source:
        if isinstance(source, dict) and "level" in source:
            plugin.auth_level = source.get("level")
        elif hasattr(source, "auth_level"):
            plugin.auth_level = source.auth_level
    # 如果 source 为空且 plugin 本身没有 auth_level，直接返回 True
    elif not hasattr(plugin, "auth_level"):
        return True

    # auth_level 级别说明
    # 1 - 所有用户可见
    # 2 - 站点认证用户可见
    # 3 - 站点&密钥认证可见
    # 99 - 站点&特殊密钥认证可见
    # 如果当前站点认证级别大于 1 且插件级别为 99，并存在插件公钥，说明为特殊密钥认证，通过密钥匹配进行认证
    auth_level = _site_auth_level_provider()
    if auth_level > 1 and plugin.auth_level == 99 and hasattr(plugin, "plugin_public_key"):
        plugin_id = plugin.id if isinstance(plugin, schemas.Plugin) else plugin.__name__
        public_key = plugin.plugin_public_key
        if public_key:
            private_key = _get_plugin_private_key(plugin_id)
            verify = RSAUtils.verify_rsa_keys(public_key=public_key, private_key=private_key)
            return verify
    # 如果当前站点认证级别小于插件级别，则返回 False
    if auth_level < plugin.auth_level:
        return False
    return True


def _get_plugin_private_key(plugin_id: str) -> Optional[str]:
    """
    根据插件标识获取对应的私钥
    :param plugin_id: 插件标识
    :return: 对应的插件私钥，如果未找到则返回 None
    """
    try:
        # 将插件标识转换为大写并构建环境变量名称
        env_var_name = f"PLUGIN_{plugin_id.upper()}_PRIVATE_KEY"
        private_key = os.environ.get(env_var_name)
        return private_key
    except Exception as e:
        logger.debug(f"获取插件 {plugin_id} 的私钥时发生错误：{e}")
        return None
