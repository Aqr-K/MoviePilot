"""
门面层（Managers / 派发门面）包。

把 chain 与 modules 之间的「派发门面」从 app/helper（叶子工具层）抽出为**独立一层**，
与三层目标架构对齐：

- 契约接口（Protocol / 抽象基类）在 app/modules：INotification / IDownloader / IMediaServer /
  IMediaRecognize、StorageBase；
- 注册工厂在 app/core/module + 各域 provides_* 钩子 / verify_*_contract；
- **门面管理器集中在本包**：忠实复刻 ChainBase.run_module 的派发语义（插件劫持面 + 系统面），
  被 ChainBase 直接调用，取代「ChainBase.run_module(字符串) → 模块」的字符串 ABI 双层派发。

分层（迁移目的）：

    chain → managers → { core, helper, modules, schemas, utils }

helper / modules / core 均不回指 managers。由此消除两类问题：
1. **概念环**：门面原先落在 helper，形成「helper(门面) → modules(后端) → helper(工具)」的概念环；
   抽出后变为 `managers → modules → helper` 的干净 DAG；
2. **反向引用**：被编排的 app/modules/* 后端 docstring 原先反指 `app.helper.<x>_manager`（被编排者
   点名编排者），迁移后改指 `app.managers.<x>_manager`，方向恢复自上而下。

懒再导出（PEP 562 __getattr__）：沿用 app/core/module 的范式——`from app.managers import X` 才触发
对应子模块加载；`from app.managers.<mod> import X` 直接 import 子模块时不会急加载其余门面，
保持与迁移前一致的 import 足迹，避免引入新的 import 边。
"""
from typing import TYPE_CHECKING

# 公共门面名 -> (子模块全名, 属性名)。仅在按属性访问（from app.managers import X）时懒加载。
# 用二元组而非裸模块名：与 app/core/module 范式对齐，解除「导出名必须等于类名」的隐式耦合。
_LAZY_EXPORTS = {
    "DownloaderManager": ("app.managers.downloader_manager", "DownloaderManager"),
    "MediaServerManager": ("app.managers.mediaserver_manager", "MediaServerManager"),
    "NotificationManager": ("app.managers.notification_manager", "NotificationManager"),
    "MediaRecognizeManager": ("app.managers.mediarecognize_manager", "MediaRecognizeManager"),
    "StorageManager": ("app.managers.storage_manager", "StorageManager"),
}

if TYPE_CHECKING:  # 仅供静态检查/IDE，运行期不执行，不引入急加载
    from app.managers.downloader_manager import DownloaderManager
    from app.managers.mediaserver_manager import MediaServerManager
    from app.managers.notification_manager import NotificationManager
    from app.managers.mediarecognize_manager import MediaRecognizeManager
    from app.managers.storage_manager import StorageManager

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str):
    """PEP 562 懒再导出：按需 import 子模块并取出属性，避免包初始化期急加载全部门面。"""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(target[0]), target[1])


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
