# -*- coding: utf-8 -*-
"""
插件安装上报注入式 seam：解耦 core/plugin -> helper.server。

core/plugin 在插件安装成功后上报安装统计,原先直接调用
MoviePilotServerHelper.install_plugin_reg（helper 层,依赖 db / http / 外部 MP 统计服务器）,
形成 core -> helper 的反向依赖。此 seam 把"上报插件安装"抽象为可注入 reporter：

  - 由组合根（app/startup/lifecycle.py）注入 MoviePilotServerHelper.install_plugin_reg;
  - 未注册时为 no-op（与 settings.PLUGIN_STATISTIC_SHARE=False 时跳过上报的语义一致,
    且上报本就是 fire-and-forget,调用方忽略返回值）;
  - 本模块零外部依赖（仅 typing），不反向依赖 helper。

与 app/core/auth_level.py（S1b）、app/core/meta/config_source.py（S1）同属注入式 seam。
"""
from typing import Any, Callable, Optional

_install_reporter: Optional[Callable[..., Any]] = None


def set_plugin_install_reporter(reporter: Callable[..., Any]) -> None:
    """
    注册插件安装上报器（由组合根调用）。
    """
    global _install_reporter
    _install_reporter = reporter


def report_plugin_install(plugin_id: str, repo_url: Optional[str] = None) -> Any:
    """
    上报单个插件安装统计；未注册 reporter 时为 no-op，返回 None。
    """
    if _install_reporter is None:
        return None
    return _install_reporter(plugin_id=plugin_id, repo_url=repo_url)
