"""兼容垫片（S9）：`PluginManager` 已迁出 core，落户 `app.helper.plugin_manager`。

迁移动机（审计 P1）：原 `app/core/plugin.py` 是一个 2026 行的 god-object，既不该
留在 core（core 应是下层，不应内含插件市场/安装/热重载这类高层编排），又通过
`PluginDataOper`/`SystemConfigOper` 顶层反向依赖 db（core→db 反向边）。迁至 helper 层后，
helper→{core,db,utils} 均为合法层序，core 的 god-object 气味与最后 2 条 core→db 边一并消除。

本垫片仅为**防御性向后兼容**：保留历史上可能存在的 `from app.core.plugin import PluginManager`
写法（仓内市场插件 0 引用，全部内部导入方已改指新路径）。采用 PEP 562 模块级
`__getattr__` **惰性**解析，使「导入 app.core.plugin」本身不在 import-time 拉起 helper —
守护 core↔helper 解环里程碑（core 顶层零 helper 反向依赖）。
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 仅类型检查期可见，运行期不产生 core→helper 顶层边
    from app.helper.plugin_manager import PluginManager


def __getattr__(name: str):
    if name == "PluginManager":
        from app.helper.plugin_manager import PluginManager

        return PluginManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
