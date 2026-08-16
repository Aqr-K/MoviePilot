# 存储分发层拆除方案

把 7 个存储驱动从 `FileManagerModule` 底下的二级实现，提升为与 `emby`/`plex`/`qbittorrent` 同级的一级模块。

> 状态：第 1–5 步已落地（`e76ccde35`、`2c7b363fb`、`4d640a9d4`）。第 6 步「整理编排的归属」按计划押后，见 §四。
> 落地过程中相对本方案有三处修正，见 §六。

## 一、问题

`FileManagerModule`（`app/modules/filemanager/__init__.py`，795 行）是两样东西粘在一起：

```
FileManagerModule
├─ 存储分发表（冗余）
│   list_files / any_files / create_folder / get_folder / get_file_item / get_parent_item
│   delete_file / rename_file / download_file / upload_file / snapshot_storage / storage_usage
│   save_config / reset_config / generate_qrcode / generate_auth_url / check_login / support_transtype
│   一律形如：storage_oper = self.__get_storage_oper(x); return storage_oper.<短名>(...)
│
└─ 整理编排（真业务）
    transfer / media_files / media_exists / recommend_name / _build_library_lookup_meta
    _music_recording_exists / _music_album_is_complete / _music_file_identity
```

分发表存在的唯一原因：`ChainBase.run_module()` 只有「按方法名广播 + 短路」一种模式，**没有「按 subtype 精确选一个」**。存储必须精确选一个（一次 `delete_file` 不能打到所有存储上），于是 `FileManagerModule` 自建了 `__get_storage_oper`（`:135`）这张查找表。

结果是层级错位：

| | 层级 | 实质 |
|---|---|---|
| `EmbyModule` / `PlexModule` / `JellyfinModule` | 一级模块 | 一个模块管 N 个同类后端 |
| `FileManagerModule` | 一级模块 | **分发器**，底下挂 7 个后端 |
| `LocalStorage` / `AlipanStorage` / … | 二级实现 | 与 emby 同性质，却低一级 |

`ModuleManager.SubType` 里 `StorageSchema` 早已与 `MediaServerType` 并列（`module_manager.py:55`）——契约上存储本来就该是一级的，只是分发路径缺失。

## 二、目标形态

```
app/modules/storages/__init__.py     re-export 7 个存储模块类
app/modules/storages/local.py        LocalStorage      get_subtype() -> StorageSchema.Local
app/modules/storages/alipan.py       AlipanStorage     -> StorageSchema.Alipan
app/modules/storages/u115.py         U115Storage       -> StorageSchema.U115
app/modules/storages/rclone.py       RcloneStorage     -> StorageSchema.Rclone
app/modules/storages/alist.py        AlistStorage      -> StorageSchema.Alist
app/modules/storages/alistgo.py      AlistGoStorage    -> StorageSchema.AlistGo
app/modules/storages/smb.py          SmbStorage        -> StorageSchema.SMB
```

`ModuleHelper.load` 用 `pkgutil.iter_modules`（`app/foundation/reflection.py:42`）只扫一层，但它遍历的是 `module.__dict__`，因此 `storages/__init__.py` 的 re-export 会让 7 个类各自独立注册。**目录分组不引入运行期间接层。**

## 三、三刀

### 刀 1 — chain 补精确分发路径（纯增量）

`ModuleManager.get_running_subtype_module()`（`module_manager.py:235`）已存在，chain 从未使用。在 `ChainBase` 增加：

```python
def run_module_for(self, subtype, method: str, *args, **kwargs) -> Any:
    """按子类型精确选中一个模块执行，不广播"""
```

**前置缺陷**：现有匹配是 `module.get_subtype() == module_subtype` 的裸比较。内建存储的 subtype 是 `StorageSchema.Local` 枚举，而 `fileitem.storage` 是字符串 `"local"`；插件声明的存储 schema 压根不在枚举内，只能是字符串。匹配必须先归一到 schema 字符串值，否则插件存储永远选不中——与 `FileURI.from_uri` 的闭合枚举缺陷同源。

`run_module()` 的广播语义**保留不动**。它对「依次试」（tmdb→douban→bangumi）和「全都要」（通知广播）是正确的。两条路并列，不是替换。

### 刀 2 — `StorageBase` 直接长成模块基类

不要再包 `XxxStorageModule` 外壳——那只是把分发层换成包装层。

```python
class StorageBase(metaclass=ABCMeta):
    def init_module(self): ...
    def init_setting(self): ...
    @staticmethod
    def get_type() -> ModuleType: return ModuleType.Storage   # 新增枚举成员
    @abstractmethod
    def get_subtype(self): ...
```

一个类既是驱动又是模块，与 `EmbyModule` 完全同构。

连带清理：

- `app/adapters/storage/registry.py` 整个删除——模块注册表就是存储注册表。`_support_storages()` 变成 `get_running_type_modules(ModuleType.Storage)` 收集 subtype，这是广播的正当用法。
- `provides_storages` 降级为类型校验糖，插件存储走 `provides_modules` 同一条注册路径。
- `app/adapters/storage/config.py`（StorageHelper）按上游归位 `app/application/storage.py`。
- `proxy.py` / `worker.py` → `app/runtime/`。

### 刀 3 — 方法名与复合能力归位

唯一有真实工作量的部分。

**a) 名字对不齐。** chain 调 `list_files/delete_file/rename_file/download_file`，驱动实现 `list/delete/rename/download`——`FileManagerModule` 一直在做这层映射。统一到 chain 的长名，短名废弃。`provides_storages` 是新增的、无存量插件；`StorageBase` 虽是上游的，但上游没有存储插件机制，破坏面可控。

**b) 复合能力不属于驱动。** 以下不是转发：

| 方法 | 实质 | 归属 |
|---|---|---|
| `list_files(recursion=True)` | 递归遍历，驱动只有单层 `list` | 调用方循环 |
| `any_files(extensions)` | 递归遍历 + 后缀过滤 | 调用方 |
| `snapshot_storage` | 遍历打快照 | 调用方 |
| `transfer` | **跨存储**：源存储读 → 目标存储写 | 编排层 |

驱动契约收窄为「单层、单存储、无编排」，7 个实现都不必处理递归。

`transfer` 尤其要点名：它天然横跨两个存储，**永远无法用 subtype 分发**。这本身就证明它不属于存储模块，而属于整理编排。

## 四、落地顺序

| # | 步骤 | 提交 | 状态 |
|---|---|---|---|
| 1 | `run_module_for` + subtype 归一匹配 | `e76ccde35` | 已落地 |
| 2 | 新增 `ModuleType.Storage` | `e76ccde35` | 已落地 |
| 3 | 驱动迁入 `app/modules/storages/`（纯搬位置） | `2c7b363fb` | 已落地 |
| 4 | `StorageBase` 长成模块基类，7 个驱动上线 | `4d640a9d4` | 已落地 |
| 5 | 删 `registry.py`；`provides_storages` 并入模块注册通道 | `4d640a9d4` | 已落地 |
| 6 | 整理编排的归属 | — | 押后 |

第 3、4 步没有按原计划「先迁 local 再批量」：给 `StorageBase` 加模块契约后，7 个驱动
自动同时具备模块身份，逐个上线反而要额外造开关。改为「搬位置」与「上模块」两刀切分，
每刀各自可独立验证——第 3 步扫描到的模块数与迁移前一致，第 4 步从 35 增到 42。

`FileManagerModule` 现在只剩整理编排（`transfer`/`media_files`/`media_exists`/
`recommend_name`）。**第 6 步是「它该留在 module 还是上移 `app/application/transfer/`」**，
刻意押后：那是 chain-vs-application 双内核那笔债的一部分，不该与存储分发这笔债捆绑。

第 6 步之后才回到「编排该留在 module 还是上移 `app/application/transfer/`」。**刻意留到最后**：那是 chain-vs-application 双内核那笔债的一部分，不该与存储分发这笔债捆绑。前 5 步无论那个问题怎么答都成立。

## 五、注意事项

- **广播误伤**：迁移期间 7 个驱动都实现 `delete_file` 而 chain 仍走 `run_module`，会导致一次删除打到所有存储。第 3 步必须先切到 `run_module_for` 再让驱动上线，不能反序。
- **插件存储**：subtype 匹配的字符串归一是插件存储可用的前提，属于刀 1 的必做项而非优化项。
- **`app/adapters/storage/` 是本 fork 自创**（提交 `22b4f0ed9`），不是上游结构。上游驱动在 `app/modules/filemanager/storages/`，`StorageHelper` 在 `app/application/storage.py`。本方案的归位方向与上游一致。
- **架构门禁**：`tests/test_architecture_dependencies.py` 把父包计为依赖边，`storages/__init__.py` 的 re-export 需确认不触发环判定。

## 六、落地过程中对本方案的修正

### 1. 文件搬迁不是可选项，是硬约束

原以为「驱动放哪是文件组织，不是架构」。实际有两条硬约束把它钉死在 `app/modules/` 下：

- 模块扫描用 `pkgutil.iter_modules`，只遍历 `app.modules` 的一级条目；
- 外部注册走的 `verify_module_contract` 要求模块类继承 `_ModuleBase`，而 `app.adapters` 反向依赖 `app.modules` 会经 `app/modules/__init__.py` 拿到 `app.runtime.extensions`，正是分层禁止的方向。

### 2. 驱动无需改名，长名转发整个消失

原方案「统一到 chain 的长名，短名废弃」是多余的。精确分发把方法名的作用域收敛到单个模块后，`list`/`delete`/`rename` 这类泛名不再有冲突风险。核对结果：7 个与 `FileManagerModule` 同名的方法（`create_folder`/`get_folder`/`reset_config`/`support_transtype`/`generate_qrcode`/`generate_auth_url`/`check_login`）**仅** `app/chain/storage.py` 一处广播调用，切换后无残留广播调用方。7 个驱动因此一个方法都没改。

### 3. 删注册表会连带删掉一条安全属性

旧存储注册表有「schema 重名先到者胜」的保护。删表后若不补，插件可静默顶替内建 `local`。补在 `ModuleManager.register_module`：注册前查子类型是否已被运行中的模块占用。这是 `(type, subtype)` 唯一性这一通用不变量的显式化，不只对存储成立。

同理，`register_plugin_modules` 原先没有逐条隔离（存储注册表有），并入后补上。
