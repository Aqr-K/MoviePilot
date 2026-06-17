# -*- coding: utf-8 -*-
"""
插件来源(plugin source)注入式 seam：解耦 core/plugin -> helper.plugin。

PluginHelper（app/helper/plugin.py，2488 行：插件市场拉取 / 安装 / 依赖管理 / 本地仓库发现）
是 helper 层重类。core/plugin 原先在模块顶层 `from app.helper.plugin import PluginHelper`
并在 9 处直接调用,构成 core -> helper 的**顶层** import 反向依赖（import 期层级耦合）。

此 seam 把"获取插件来源对象"抽象为可注入函数：
  - 默认懒加载返回真实 PluginHelper 单例 —— 行为与原先字节一致,但把对 helper 的引用从
    模块顶层 import **降级为函数内惰性 import**,从而消除顶层反向边(与 event.py 中惰性
    导入 helper.message 同属"惰性即无 import 期环"的处理);
  - 可经 set_plugin_source_provider 注入替代实现,为未来 Rust / 进程外插件宿主预留接入点
    （strangler-fig 的插件来源边界）。

注:这是 S5 的收尾刀(S5a 已先剥离无状态 URL 工具至 app.utils.plugin_repo)。
本 seam 故意不在组合根注册 provider —— 默认值本身即生产行为,YAGNI:待第二实现(Rust 宿主)
出现时再注册替代 provider。
"""
from typing import Any, Callable, Optional

_provider: Optional[Callable[[], Any]] = None


def set_plugin_source_provider(provider: Callable[[], Any]) -> None:
    """
    注入插件来源提供者（为未来替代实现预留；生产默认无需调用）。
    """
    global _provider
    _provider = provider


def get_plugin_source() -> Any:
    """
    获取插件来源对象。已注入 provider 时用之；否则懒加载返回真实 PluginHelper 单例。
    """
    if _provider is not None:
        return _provider()
    # 默认:懒加载真实 PluginHelper（WeakSingleton），避免在 core 顶层 import helper
    from app.helper.plugin import PluginHelper
    return PluginHelper()
