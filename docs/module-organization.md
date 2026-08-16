# 模块归位与功能族

`app/modules/` 的目录组织、功能族与具体模块的映射、以及拆分判据。

存储分发层的拆除单独记在 [storage-module-flattening-plan.md](storage-module-flattening-plan.md)。

## 一、两层结构

**目录表达主归属，功能族表达契约归属，两者不是一回事。**

目录只能给一个模块一个位置，但契约归属是交叉的：`themoviedb` 同时属于媒体识别、图片元数据、NFO 与媒体搜索、人物搜索四个族，外加 21 个独占方法。因此目录归位只能表达「这几个后端可以互相顶替」这一层，完整的分类由功能族表承载，锁在 `tests/test_module_contract_families.py`。

### 目录

```
app/modules/
├── downloaders/     3   qbittorrent transmission rtorrent
├── mediaservers/    7   emby jellyfin plex navidrome trimemedia ugreen zspace
├── notifications/  10   telegram slack wechat wechatclawbot discord feishu
│                        qqbot synologychat vocechat webpush
├── recognizers/     8   themoviedb douban doubanmusic bangumi anilist
│                        thetvdb musicbrainz theaudiodb
├── storages/        7   local alipan u115 rclone alist alistgo smb
├── acoustid/  fanart/  filemanager/  filter/  indexer/
├── listenbrainz/  lrclib/  postgresql/  redis/  subtitle/
└── __init__.py
```

族包按 `ModuleType` 划分。模块扫描用 `pkgutil.iter_modules`（`app/foundation/reflection.py:42`）只遍历一级条目，**具体模块类必须在族包的 `__init__.py` 导出才会进入注册表**。

顶层剩余 10 个是各自唯一的单例能力，方法名两两不重叠，不构成可互换族。**不按主题再分组**——分组的信息量来自「这几个能互相顶替」，主题相同契约不同的东西聚在一起只是把乱换个地方。

## 二、功能族 → 具体模块

完整表锁在 `tests/test_module_contract_families.py::CONTRACT_FAMILIES`，共 22 个族。主要的：

| 功能族 | 契约方法 | 具体模块 |
|---|---|---|
| 消息投递 | `post_message` | 10 个渠道 |
| 消息解析与富文本 | `message_parser` `post_medias_message` `post_torrents_message` | 9 个渠道（webpush 除外） |
| 消息交互 | `edit_message` `send_direct_message` `mark_message_processing_*` | discord feishu slack telegram |
| 媒体库查询 | `mediaserver_*` `media_statistic` `user_authenticate` 等 11 个 | 7 个媒体库 |
| 媒体存在判定 | `media_exists` | 7 个媒体库 + filemanager |
| 下载器 | `download` `list_torrents` `remove_torrents` 等 10 个 | qbittorrent transmission rtorrent |
| 媒体识别 | `recognize_media` | anilist bangumi douban doubanmusic musicbrainz theaudiodb themoviedb |
| 音乐元数据 | `recognize_music` `music_album` `search_music` `get_music_source` | doubanmusic musicbrainz theaudiodb |
| 图片元数据 | `metadata_img` | **fanart** anilist bangumi douban themoviedb |
| 图片获取 | `obtain_images` | **fanart** douban themoviedb |
| NFO 与媒体搜索 | `metadata_nfo` `search_medias` | anilist bangumi douban themoviedb |

存储族的契约在 `StorageBase` 上而不在各驱动的 `__init__.py` 里，因此不进上表，由 `tests/test_builtin_storage_modules.py` 单独锁定。

## 三、拆分判据

一个模块实现多个族的方法**不构成拆分理由**。三条同时满足才拆：

1. **领域实体不同**——音乐 vs 影视，而不是同一实体的不同切面
2. **有独立的来源或类型标识**——如 `MediaSource.DoubanMusic`
3. **模块内部已出现自建分发器**——如 `recognize_media` 里按来源分流

`DoubanModule` 是唯一三条全中的：它在 `recognize_media` 里写着

```python
if media_source == self._music_source:
    return self._recognize_music_media(...)
```

混合模块在自己肚子里又造了一个分发器，与 `FileManagerModule.__get_storage_oper` 同病。已拆为 `DoubanModule`（影视）+ `DoubanMusicModule`（音乐），各自只认自己的来源。

反例：识别源的图片、NFO、搜索三个面**不拆**。`metadata_nfo` 只是 3 行委托给已经独立出来的 `scraper` 类——切面已在类粒度分离，再拆模块只会造出空壳。

## 四、搬迁清单

每族六步，缺一不可：

1. `git mv` 到族包下，包内结构原样保留
2. 改包内 dotted 路径
3. **写族包 `__init__.py` 导出模块类**——不导出就不进注册表
4. **补兼容别名**（`app/runtime/compat/manifest.py`）：包本身 `is_package=True` + **每个子模块单独一条**
5. 改测试——**dotted 路径和文件系统路径两种都要**
6. HEAD 对照跑全量，比 FAILED 集合而非绝对数字

### 三个已踩过的坑

- **别名包的子模块必须逐条登记。** `LegacyImportFinder.find_spec` 只按精确 `fullname` 查表；父包命中后 `LegacyAliasLoader` 把 canonical 的 `__path__` 恢复到旧名下，未登记的子模块会退回 `PathFinder` **二次执行源码**，生成 id 不同的模块对象——插件与主程序各持一份同名却不同一的类，`isinstance`/`issubclass` 静默失败。已由 `tests/test_legacy_alias_submodule_coverage.py` 兜住。
- **前缀覆盖。** `app.modules.wechat` 是 `app.modules.wechatclawbot` 的严格前缀，裸 `sed` 会把后者改成乱码。改写时长名优先、并加 `\b`。
- **文件系统路径漏改。** 部分测试用 `repo_root / "app" / "modules" / X / "y.py"` 装载源码，并自建 `sys.modules` 桩字典。dotted 路径的 grep 扫不到，漏改会在 pytest **collection 阶段**炸掉整轮。另外 `tests/manual/` 下的手工脚本不被 pytest 采集，漏改也不会变红，要按整个 `tests/` 搜而不是只搜 `test_*.py`。

## 五、已知遗留

- **`fanart` 的目录归属与契约归属不一致。** 它独占方法为 0，全部方法都与 4 个识别源共享，契约上是图片族正式成员，但声明 `ModuleType.Other` 蹲在顶层。移进 `recognizers/` 会让目录名失准（它不识别）。当前由功能族表记录其真实归属，目录不动。
- **`thetvdb` 声明 `ModuleType.MediaRecognize` 却不实现任何识别族方法**，只有 `tvdb_info`/`tvdb_slug`/`search_tvdb` 三个独占查询。它是能力不全的族成员，不是错分。族内可选能力目前只在消息渠道那里被显式化（`ChannelCapabilities`），其余族靠隐式 `hasattr` 探测。
- **`postgresql`/`redis` 对外方法为 0**，不参与任何分发，只有 `test()` 有内容。它们不是伪模块：模块系统在此兼作健康探针注册表，`/system/modulelist` 与 `/system/moduletest/{moduleid}` 是其 API，前端依赖之。摘除会造成用户可见的功能回退，不做。
- **`filemanager` 只剩整理编排**，其归属押后到 chain 与 application 双内核那笔债一起解，见存储方案第 6 步。
