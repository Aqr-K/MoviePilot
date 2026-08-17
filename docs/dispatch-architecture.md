# 分发架构

模块能力如何被 chain 找到并调用。三级分发语义、能力注册表、以及数据源契约的归一判据。

## 一、三级语义

三者不是并列的三选一，而是同一条选择流水线上的三级过滤：

```
全体运行模块
  → [能力过滤] ───── 有该方法且已实现的提供者
      → [仲裁] ───── 单播的唯一答案
```

| 语义 | 原语 | 代价 | 用途 |
|---|---|---|---|
| 广播 | `broadcast` / `async_broadcast` | O(n) 遍历全体 | 通知，不求答案 |
| 多播 | `multicast` / `async_multicast` | 查表 O(1) + 调用 O(k) | 收集全部答案 |
| 单播 | `unicast` / `async_unicast` | 同上 + 优先级仲裁与短路 | 只要一个答案 |

**广播刻意不做索引化。** 触达全体就是它的语义；一旦按订阅关系建表，它就变成了多播——
那是另一种语义，不是同一个东西的优化。测试 `test_it_walks_every_module_and_never_consults_the_index`
锁定这一点：广播必须扫全体，且查表次数必须为 0。

**单播是多播的下游，不是另一套选择逻辑。** 两者候选集完全一致（同一张注册表、同一个优先级顺序），
单播只多一层短路：谁先给出非空答案就用谁的。测试
`test_unicast_answer_is_the_first_of_the_multicast_answers` 锁定这一点。

### 定级判据

拿不准时按这个顺序问：

1. **要答案吗？** 不要（方法声明返回 `None`）→ 广播
2. **要几个答案？** 全部 → 多播；一个 → 单播
3. **多播的返回值是「每个提供者的答案」**，若原先 `run_module` 对 list 结果做扁平合并，
   调用处需要展平（见 `MediaServerChain.media_count`）

一条经验：**返回值的形状不决定分发级别，「是否归属唯一提供者」才决定**。
`torrent_files` 返回列表，但内容是"某个种子的文件"而非"多个下载器的答案"，所以是单播。

### 三级之外还有第四种：累积管道

三级语义覆盖不了所有情况。`run_module` 里有一条分支：

```python
elif ObjectUtils.check_signature(func, result):
    result = func(result)      # 上一个提供者的返回值成为下一个的入参
```

当某个能力的**返回类型与入参类型相同**时，这条分支会把提供者串成一条流水线：每个提供者在前
一个的结果上继续加工。`obtain_images` 就是实例——fanart、themoviedb、douban 依次在同一个
`MediaInfo` 对象上回填各自能补的图片字段，原地 mutate 并返回同一对象。

**这类能力不要硬塞进三级。** 它既不是"通知全体"、也不是"收集 N 份独立答案"、更不是"择一"——
套用任何一个原语都会丢掉链式累积的顺序，而代码库里也没有"合并 N 个 `MediaInfo` 答案"的既有写法。
识别特征：

- 方法的返回类型 == 某个入参的类型
- 各提供者的实现是"补齐缺失字段"而非"给出完整答案"
- 提供者之间有隐含的先后关系（谁先补、谁兜底）

遇到这种就**保持 `run_module` 不动**。它是这条分支唯一的正当用途，不是遗留债。

顺带一提：同一条 `check_signature` 分支在别处是**缺陷**——它让调用形态随上游返回值突变，
同一个方法第一个提供者收到 `(*args, **kwargs)`、第二个可能收到 `(result)`。区别在于
累积管道是**有意**利用它，而其余场景只是碰巧撞上。判断依据就是上面三个特征。

## 二、能力注册表

`ModuleManager.providers_for(method)` 把**能力方法名**映射到按优先级排好序的提供者元组，
命中后 O(1)，只在运行态模块集合变化时整体丢弃（失效挂在 `_refresh_running_projection`，
它是 `_running_modules` 的唯一写入点）。

### 索引键是能力，不是身份

`get_type()` 只有一个取值，它回答「你是什么」；能力回答「你能做什么」。一个模块只有一个身份，
却可以提供多种能力——媒体服务器同时兼任认证登录（`user_authenticate`），而认证根本不是一个
`ModuleType`。按身份圈定会把这类跨族能力漏在外面。

因此 `ModuleType` 已退化为**元数据**：manifest 校验、UI 分类、以及未映射族的兜底发现。
分发不看它；服务发现也改为按能力查表（见 `service_registry.py` 的 `_FAMILY_CAPABILITIES`）。

**推论：身份不必复合，能力天然可叠加。** 一个模块若同时实现视频与音乐能力，会自动出现在
两个族的发现结果里，不需要声明第二个身份。

### 什么算能力

定义只有一处：`capability.provided_capabilities()`。判定从运行期实例推导而非按标签声明——
标签会撒谎，静态扫描有盲点（方法可继承自基类）。

- `LIFECYCLE_METHODS`：生命周期与横切钩子不算能力
- `INFRASTRUCTURE_BASES`：**只登记真基础设施**（配置读取、服务实例管理、生命周期骨架）。
  领域模块基类不在此列——它们既给管道也给真业务能力，把整个基类拉黑会连坐判死
  `user_authenticate`、`media_exists`、`register_commands`

### 排查分发问题时的两个入口

```python
ModuleManager.get_module_capabilities(module_id) -> List[str]   # 这个模块提供什么
ModuleManager.get_capability_index() -> Dict[str, List[str]]    # 能力 → 提供者的倒排
```

只读、不触发任何初始化。`providers_for` 只能「按名问人」，答不了「系统里到底有哪些能力」——
而后者才是分发出问题时最先要问的（某个能力为什么查不到提供者？某个模块到底被识别出了什么？）。

两者都建立在 `provided_capabilities()` 之上，不另写判据。单个模块推导出错只记 debug 日志并跳过，
不中断整张表——诊断接口本就是故障时用的，若因某个模块状态异常而整体失效，恰好在最需要它的
时候罢工。

### 已知盲区

能力推导止步于 **Module 类**，看不到 Module 持有的 service 实例类。`get_music` 定义在
`jellyfin/jellyfin.py` 的客户端类上，`JellyfinModule` 自身没有——所以 `providers_for("get_music")`
查不到提供者。这个缺口与身份标记无关，改 `ModuleType` 怎么都够不着。

## 三、数据源契约的归一判据

**数据源应该是参数，不是方法名的一部分。**

反模式是同一能力按源拆成 N 个方法名，形成笛卡尔积：

```
tmdb_person_detail  douban_person_detail  bangumi_person_detail  anilist_person_detail
```

归一后源是参数，新增源只需实现已有契约，不必再往 chain 和模块两侧各加一组方法：

| 契约 | 取代的方法名数 |
|---|---|
| `person_detail(source, person_id)` | 8 |
| `person_credits(source, person_id, page, count)` | 8 |
| `media_detail(source, media_id, mtype, season, raise_exception)` | 9 |
| `media_credits(source, media_id, mtype, page, count)` | 14 |
| `media_recommend(source, media_id, mtype, page, count)` | 12 |
| `discover(source, **criteria)` | 8 |
| `discover_boards()` + `discover_board(source, board, page, count)` | 22 |

### 四条规矩

1. **契约委托原方法，不重写。** 缓存与限流都挂在原方法上，重新实现会让接缝错位。原方法保留，
   只降级为实现层。
2. **非本源返回 `None`（让出），不抛异常。** ID 类型转换失败同样返回 `None`——分发链上一个源的
   输入格式不该变成整条链的异常。
3. **各源只把自己认得的参数往下传。** 某源方法没有 `count` 就不能传，传了是 `TypeError`。
   签名差异由各源的契约实现吸收，不能甩给调用方。
4. **语义要固定而非照搬。** 例：`raise_exception` 取 chain 门面的缺省 `False`，而非模块方法自己的
   `True`——照搬会把「限流即抛错」变成默认行为，那是行为变更不是归一。

### 什么时候不该归一

- **单源专有方法**（`tmdb_seasons`、`tvdb_slug`、`tmdb_cache_*`）不构成重复，归一无收益
- **方法名本就统一、靠参数路由的族**（存储的 `storage=`、下载器的 `downloader=`、通知的 `channel=`）
  没有笛卡尔积可拆，它们缺的是分发级别而非契约
- **语义不可通约的能力组**不要硬塞进一个方法。榜单就是例子：本周放送表、固定 Top250、实时趋势
  彼此不同，分页能力也不同（豆瓣有 `(page, count)`、TMDB 只有 `page`、Bangumi 完全没有）。
  硬塞成 `discover(board=...)` 会把差异藏进字符串参数，调用方仍旧要靠猜——所以用双契约，
  先枚举再取，并由 `DiscoverBoard.paginated` 声明分页能力。

## 四、迁移时的三个坑

**测试打桩会落空。** 大量测试把 mock 打在 `run_module` 上——那是分发实现，不是契约边界。
分发一换，mock 就落空，调用穿透到真实模块（曾触发真实 TMDB 出站请求）。迁移前先确认目标方法的
mock 在哪个边界；打在 `run_module` 上的要先上移到领域钩子（如 `_run_native_media_recognize`，
它的契约「接收 module_kwargs」不随底层走广播还是查表而变）。

改打桩点时**只改打桩目标与数据形状，不得弱化断言值**。

**用 falsy 值表达「未认领」是陷阱。** `finalize_message` 在飞书实现里非匹配渠道返回 `False` 而非
`None`，而 `False` 会被当成"已认领"从而短路，真正该处理的渠道被吞掉。目前该方法只有一个
provider 所以未爆发，第二个 provider 出现时会暴露。约定是：**未认领一律返回 `None`**。

**留在 `run_module` 上的多播语义方法会被它的短路吞掉。** `run_module` 遇到非空且非 list 的返回值
就停止后续提供者——这对「只要一个答案」是对的，对「每个提供者都要执行」是错的。`post_message`
曾经就挂在上面：十个渠道实现恰好全部 `-> None`，短路条件从不成立，于是错误被掩盖；一旦某个插件
渠道返回非空值，它后面的渠道就静默收不到消息。判断依据不是「现在有没有出错」，而是
**「这个方法的语义要不要求全部执行」**——是，就必须迁到 `multicast`，不能因为暂时没爆而留着。
