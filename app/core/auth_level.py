# -*- coding: utf-8 -*-
"""
站点认证等级注入式 seam：解耦 core -> helper.sites。

SitesHelper 是资源包拉取的编译模块（app/helper/sites.*.so），属于 helper 层。
core 层（security / auth_bridge）原先直接 import SitesHelper 仅为读取 `auth_level`，
形成 core -> helper 的反向依赖。此 seam 把"读取站点认证等级"抽象为可注入的 provider：

  - 由组合根（app/startup/lifecycle.py）注入 `lambda: SitesHelper().auth_level`；
  - 未注册时返回未认证默认等级（least privilege），与全新 SitesHelper().auth_level 一致；
  - 本模块零外部依赖（仅 typing），不反向依赖 helper。

与 app/core/meta/config_source.py（S1）同属注入式 seam 技术。
"""
from typing import Callable, Optional

# 未注册 provider 时的默认认证等级：与全新 SitesHelper().auth_level 的初值一致（未认证 / 最小权限）
DEFAULT_AUTH_LEVEL = 1

_provider: Optional[Callable[[], int]] = None


def set_auth_level_provider(provider: Callable[[], int]) -> None:
    """
    注册站点认证等级提供者（由组合根调用）。
    """
    global _provider
    _provider = provider


def get_auth_level() -> int:
    """
    获取当前站点认证等级；未注册 provider 时返回未认证默认等级。
    """
    if _provider is None:
        return DEFAULT_AUTH_LEVEL
    return _provider()
