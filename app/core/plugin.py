"""兼容垫片：`PluginManager` 现位于 `app.helper.plugin_manager`。

保留 `from app.core.plugin import PluginManager` 的旧写法（仓内已无引用，仅作防御性兼容）。
采用 PEP 562 模块级 `__getattr__` 惰性解析，使「导入 app.core.plugin」本身不在 import 期拉起 helper，
避免 core 顶层产生对 helper 的依赖。
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 仅类型检查期可见，运行期不产生 core→helper 顶层边
    from app.helper.plugin_manager import PluginManager


def __getattr__(name: str):
    if name == "PluginManager":
        from app.helper.plugin_manager import PluginManager

        return PluginManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
