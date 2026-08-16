# 发现能力契约化方案

把 15 个各自为政的发现方法归一到 2 个契约，让「发现」成为真正的能力族。

模块归位的总体规则见 [module-organization.md](module-organization.md)。

## 一、问题

`chain/recommend.py` 硬编码 11 个专有方法名去点调各数据源：

```python
run_module("async_tmdb_trending", ...)
run_module("async_movie_hot", ...)
run_module("async_bangumi_calendar", ...)
```

后果：

- 新增一个发现源要改 chain，而不是只实现一个契约
- 前端的发现页与后端方法名硬绑定
- 「发现」在能力索引里表现为 15 个互不相干的独占能力，看不出它是一类东西
- `MediaRecognizeType` 同时承担「识别源」与「发现源」两个概念，`douban` 的能力面里 8 个发现对 2 个识别，主体反而被归在识别下

## 二、量化依据

15 个发现方法的签名按形状自然分成两组，返回类型全是 `List[MediaInfo]`：

| 组 | 签名形状 | 成员 |
|---|---|---|
| **榜单** | `(page, count)` | douban 7 个（`movie_showing` `tv_weekly_chinese` `tv_weekly_global` `tv_animation` `movie_hot` `tv_hot` `movie_top250`）、anilist 2 个（`anilist_trending` `anilist_popular_this_season`）、`tmdb_trending(page)`、`bangumi_calendar()` |
| **条件筛选** | `(mtype, **criteria)` | `tmdb_discover` `douban_discover` `bangumi_discover` `anilist_discover` |

`bangumi_discover` 与 `anilist_discover` 已经是 `**kwargs`，条件筛选这一组本就接近统一。`tmdb_trending` 缺 `count`、`bangumi_calendar` 无参，是榜单契约的退化情形，可用默认值吸收。

**归一可行，不是主观判断。**

## 三、契约

```python
def discover_boards(self) -> List[DiscoverBoard]:
    """本源提供的榜单清单，供前端枚举"""

def discover_board(self, source, board: str,
                   page: int = 1, count: int = 30) -> Optional[List[MediaInfo]]:
    """取指定榜单的一页，source 不是本源时返回 None"""

def discover(self, source, mtype: MediaType = None,
             **criteria) -> Optional[List[MediaInfo]]:
    """按条件筛选，source 不是本源时返回 None"""
```

`DiscoverBoard` 至少含：`source`、`board`（标识）、`name`（显示名）、`media_type`。

### 分发方式

沿用 `recognize_media` 的既有模式，**不引入新机制**：`run_module` 广播 + 模块按 `source` 自检，不匹配返回 `None`。只有一个源匹配，所以不存在结果被 `extend` 累加的问题。

`discover_boards` 相反，**广播累加正是它要的语义**——各源的榜单并集就是前端要展示的全部。

### 为什么不用 `run_module_for`

精确分发按 `get_subtype()` 匹配，而一个模块只有一个子类型。`douban` 的子类型是 `MediaRecognizeType.Douban`，若发现按 `MediaSource` 分发就需要第二个子类型，模块给不出。广播加自检没有这个约束，且与识别侧写法一致。

## 四、不建立 `discovery/` 目录

**这是本方案与直觉相反的一点，理由要写清楚。**

`douban`/`themoviedb`/`bangumi`/`anilist` 同时提供识别与发现，契约上属于两个族。目录只能给一个模块一个位置，跨族归属由能力索引承载——这条规则在 [module-organization.md](module-organization.md) 已确立，`fanart` 就是同样的情形。

拆包也不成立。用既有的三条拆分判据检验「豆瓣发现」：

| 判据 | 豆瓣音乐（已拆） | 豆瓣发现 |
|---|---|---|
| 领域实体不同 | 音乐 vs 影视 | 都是影视 |
| 有独立来源标识 | `MediaSource.DoubanMusic` | 无 |
| 内部已有自建分发器 | `recognize_media` 里按来源分流 | 无 |

三条全不中。硬拆出来的会是两个共享同一 `DoubanApi`、同一 `MediaSource.Douban`、只有方法名前缀不同的包。

**同理不建 `common/`。** 跨包共享 API 客户端 Python 的导入已经解决——`doubanmusic` 直接用 `recognizers/douban/apiv2.py` 的 `DoubanApi` 就是现成例子。`common/` 没有准入判据，半年后必然变成第二个 `Other` 桶。

**实质收益全部来自契约，没有一项来自目录。**

## 五、分期

| # | 步骤 | 可独立验证 |
|---|---|---|
| 1 | 定义 `DiscoverBoard` 与三个契约方法签名 | 是 |
| 2 | 一个源端到端跑通（建议 `anilist`，只有 3 个方法且两个已是 `**kwargs`） | 是 |
| 3 | 其余三源实现契约，旧方法保留 | 是 |
| 4 | `recommend.py` 改为按契约调用，前端从 `discover_boards` 枚举 | 是 |
| 5 | 摘除 15 个旧方法与其分发调用点 | 是 |
| 6 | `MediaRecognizeType` 拆出发现源枚举（若届时确有必要） | 是 |

第 3 步保留旧方法，使第 4 步前后可对照同一份数据验证归一无损；第 5 步之前任何一步出问题都能停在可用状态。

## 六、风险

- **前端联动**：发现页现在按后端方法名组织，第 4 步必须与前端仓库同步，否则发现页空白。这是本方案唯一的跨仓协调点。
- **榜单语义不可通约**：`bangumi_calendar` 是「本周放送表」，`movie_top250` 是「固定榜单」，`tmdb_trending` 是「趋势」。归到同一个 `discover_board(board=...)` 之后，分页语义未必一致（`calendar` 无分页）。契约需允许源声明该榜单是否支持分页，否则前端翻页会出错。
- **`douban` 的 7 个榜单方法各有独立缓存与限流**（`rate_limit_exponential`），归一时要确认装饰器仍按榜单粒度生效，不能退化成整个 `discover_board` 一个限流桶。

## 七、不做的

- 不动 `thetvdb`——它没有发现能力，本方案与它无关。
- 不动 `listenbrainz` 的 `music_chart`/`music_fresh_releases`。它们返回音乐实体不是 `MediaInfo`，与影视榜单不可通约；音乐发现要归一是另一件事。
