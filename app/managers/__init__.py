"""
门面层（Managers / 派发门面）包。

chain 与 modules 之间的「派发门面」独立为一层，与三层架构对齐：

- 契约接口（Protocol / 抽象基类）在 app/modules：INotification / IDownloader / IMediaServer /
  IMediaRecognize、StorageBase；
- 注册工厂在 app/core/module + 各域 provides_* 钩子 / verify_*_contract；
- **门面管理器集中在本包**：按方法名把领域操作分发到各后端模块（插件钩子面 + 系统后端面），
  被 ChainBase 直接调用，取代散落在 ChainBase 中按字符串分发到模块的写法。

分层：

    chain → managers → { core, helper, modules, schemas, utils }

helper / modules / core 均不回指 managers，保持 `managers → modules → helper` 的干净 DAG（无概念环）；
app/modules/* 后端 docstring 也只向上指向 `app.managers.<x>`。

懒再导出（PEP 562 __getattr__）：沿用 app/core/module 的范式——`from app.managers import X` 才触发
对应子模块加载；`from app.managers.<mod> import X` 直接 import 子模块时不会急加载其余门面，
不引入额外的 import 边。
"""
from typing import TYPE_CHECKING

# 公共门面名 -> (子模块全名, 属性名)。仅在按属性访问（from app.managers import X）时懒加载。
# 用二元组而非裸模块名：与 app/core/module 范式对齐，解除「导出名必须等于类名」的隐式耦合。
_LAZY_EXPORTS = {
    "DownloaderManager": ("app.managers.downloader", "DownloaderManager"),
    "MediaServerManager": ("app.managers.mediaserver", "MediaServerManager"),
    "NotificationManager": ("app.managers.notification", "NotificationManager"),
    "MediaRecognizeManager": ("app.managers.mediarecognize", "MediaRecognizeManager"),
    "StorageManager": ("app.managers.storage", "StorageManager"),
}

if TYPE_CHECKING:  # 仅供静态检查/IDE，运行期不执行，不引入急加载
    from app.managers.downloader import DownloaderManager
    from app.managers.mediaserver import MediaServerManager
    from app.managers.notification import NotificationManager
    from app.managers.mediarecognize import MediaRecognizeManager
    from app.managers.storage import StorageManager

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
