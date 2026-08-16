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
| 3b | 四个源补 `async_discover_board` / `async_discover` | 是 |
| 4 | `RecommendChain` 内部改为按契约调用，16 个端点与方法签名不动 | 是 |
| 5 | 摘除 15 个旧方法与其分发调用点 | 是 |
| 6 | `MediaRecognizeType` 拆出发现源枚举（若届时确有必要） | 是 |

第 3 步保留旧方法，使第 4 步前后可对照同一份数据验证归一无损；第 5 步之前任何一步出问题都能停在可用状态。

## 六、前端契约：比预想的松

前端不消费方法名，消费的是 **16 个 REST 端点**（`app/api/endpoints/recommend.py`），每个榜单一个：

```
端点 /recommend/douban_movie_top250
  → RecommendChain.async_movie_top250(page, count)
    → run_module("async_movie_top250", ...)
      → DoubanModule.async_movie_top250
```

**契约化只改最后一跳。** 端点与 `RecommendChain` 的方法全部原样保留，只把它们内部的
`run_module("async_<board>")` 换成 `run_module("async_discover_board", source=..., board=...)`。
第 4 步因此**没有跨仓协调点**，前端零改动。

插件贡献的发现源走另一条完全独立的路：`ChainEventType.RecommendSource` 事件返回
`RecommendMediaSource(name, api_path, type)`，即**给前端一个 URL 让它自己去调**。与模块
分发正交，本方案不影响它。

把 `discover_boards()` 暴露给前端（让内建榜单也能被枚举，而不是硬编码 16 个）是**另一件
独立的事**，属于第 6 步之后。做时要注意：前端很可能已经硬编码了这 16 个，直接并进
`/recommend/source` 会在界面上重复出现。

## 七、风险

- **榜单语义不可通约**：`bangumi_calendar` 是「本周放送表」，`movie_top250` 是「固定榜单」，`tmdb_trending` 是「趋势」。归到同一个 `discover_board(board=...)` 之后，分页语义未必一致（`calendar` 无分页）。契约需允许源声明该榜单是否支持分页，否则前端翻页会出错。
- **`discover_board` 必须委托给现有榜单方法，不能重新实现**。落地时核实过豆瓣的实际情况：`rate_limit_exponential` 只挂在 `douban_info` 与 `match_doubaninfo` 上，7 个榜单方法**没有**独立限流，缓存是 `DoubanApi.__invoke` 上按 URL 与参数的 `@cached`，粒度本就是榜单加页码。所以今天不存在会被压平的限流桶——但委托这条仍要守，否则将来给某个榜单加限流时接缝已经错位。

- **各源支持的筛选条件不一致，契约无处声明**。Bangumi 按条目类型（动画/书籍/音乐/游戏）筛选，**没有影视这个轴**，`discover(mtype=...)` 只能忽略 `mtype`——若前端将来做跨源的影视切换，Bangumi 会静默返回全部。TMDB 侧则是不认识的条件键被丢弃而非报错，同样无信号。`DiscoverBoard` 目前没有字段承载「本源支持哪些条件」，等真有跨源筛选界面时再加，现在加是没有消费方的猜测。

- **`async_` 变体缺失，是第 4 步的前置**。`RecommendChain` 的方法是异步的，走 `async_run_module("async_<board>")`；而四个源目前都只实现了同步的三个契约方法。第 4 步要落地，必须先给四个源补 `async_discover_board` 与 `async_discover`。这一条在第 1、2 步定契约时漏了，记在此处。

## 八、不做的

- 不动 `thetvdb`——它没有发现能力，本方案与它无关。
- 不动 `listenbrainz` 的 `music_chart`/`music_fresh_releases`。它们返回音乐实体不是 `MediaInfo`，与影视榜单不可通约；音乐发现要归一是另一件事。
