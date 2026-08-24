# MoviePilot 进程隔离与并发模型设计

> 状态：设计草案（2026-08-24） · 分支 `perf/process-isolation`
> 关联：[`docs/architecture-overview.md`](architecture-overview.md) §四 启动与生命周期

---

## 零、结论先行

原始命题是「FastAPI 无状态 + 状态塔 + worker 池，实现真正的多进程以释放单核压力」。

经六路测绘与选型调研，结论分三条：

1. **「无状态 / 有状态分离」的方向正确，且代码里已经实现了大半**——`LifecycleMode`
   已把 16 个生命周期组件分成数据面 8 个、控制面 8 个，`MOVIEPILOT_SAFE_MODE`
   就是「只跑数据面」，`topology.py` 已明确允许该模式下开多 worker。
2. **「worker 池 = HTTP worker 池」这个边界画错了。** 对本项目而言，HTTP 并发不是瓶颈，
   而真正的痛点（插件失控）恰恰**不会**被 HTTP 分片解决——它会被复制到每个 worker 里。
3. **「释放单核压力」这个前提本身需要先确诊。** 最吃 CPU 的解析热点已经由 PyO3
   Rust 加速器接管并释放了 GIL；而当前单进程下最可能的饱和点是一个**从未被调整过的
   anyio 40 线程槽**，不是核数。

因此本文给出的不是单一方案，而是**三条独立推进、优先级明确的轨道**：
先确诊与止血（Track A），再把进程边界画在真正需要它的地方——插件周围（Track B），
HTTP 多 worker 拓扑降级为可选项（Track C）。

---

## 一、两条必须分开的论证线

「多进程」被同时用来指两件事，它们的成立条件完全不同：

| | 性能线 | 架构线 |
|---|---|---|
| 目标 | 释放多核算力、提高吞吐 | 故障隔离、多版本插件分身 |
| 本文判定 | **不成立**（见 §2.4、§4.6） | **成立**，且是本 fork 既定战略 |
| 正确的进程边界 | ——（无需进程边界） | **插件周围**，非 HTTP 层 |

架构线的依据不在本文，而在既有结论：本 fork 的 13 项架构资产中 12 项在上游分层模型下
都能实现，**唯一拿不到的就是跨进程扩展**；而多版本插件分身（同一插件多版本共存）会把
跨进程从投机变成必要条件——每版本一进程，共享全局单例的问题从根上消失。

**这条线成立，但它要的是「插件出进程」，不是「HTTP 出进程」。** 这是本文最核心的修正。

---

## 二、现状：地基已铺好三分之二

改造前需纠正一个常见误解——本项目不是「从未考虑过多进程」的单体。

### 2.1 多进程通路已通，被一道显式闸门挡着

`app/main.py:97-119` 已有两条路径：单进程 `Server.run()`（`:118`）与
**多进程 supervisor** `uvicorn.run(APP_FACTORY, factory=True, workers=settings.API_WORKERS)`（`:108`）。

闸门在 `app/runtime/topology.py:20-27`，实测行为：

| 配置 | `process_topology_issue()` |
|---|---|
| `workers=4, safe_mode=True` | `None`（允许） |
| `workers=4, safe_mode=False` | 拒绝 |

闸门的错误文案就是需求清单：「每个 worker 都会重复启动**插件、调度器、监控器和工作流**」。
双重校验：启动前 `main.py:183-186`，lifespan 内再校验 `lifecycle/__init__.py:313-316`。
契约已被 `tests/test_uvicorn_entrypoint.py:68-94` 锁定。

**单进程不是疏忽，是主动设的闸。**

### 2.2 数据面 / 控制面的切分已经存在

`app/startup/lifecycle/components.py:11-14` 的 `LifecycleMode`：

| `ALWAYS`（8 个，数据面） | `NORMAL_ONLY`（8 个，控制面） |
|---|---|
| 数据库准备 / HTTP 基础能力 / 领域依赖装配 | 插件备份恢复 / 插件 / 定时器 |
| 数据库引擎预热 / 数据库连接预算 | 监控器 / 待处理整理回放 |
| 数据端口装配 / 路由 / 模块服务 | 命令服务 / 工作流 / 插件备份 |

### 2.3 进程外 worker 有生产先例

`app/adapters/system/fsproxy.py`（428 行）已把文件操作甩进子进程规避网络挂载卡死：
`subprocess.Popen` + stdin/stdout **JSON 行协议**（`:384`）、请求超时 + 停滞心跳、
`_ensure_worker()` 惰性拉起与崩溃自愈（`:377`）、`_direct()` **fail-open 回退**（`:278`）。

**这是 Track B 的直接蓝本，不需另起炉灶。**

### 2.4 CPU 热点已被 Rust 接管

`app/adapters/system/rust.py` 显示 `moviepilot-rust` 已覆盖：`parse_metainfo_fast` /
`parse_metainfo_path_fast` / `find_metainfo_fast`（标题识别，正则密集）、`filter_torrents_fast`
（种子批量过滤）、`parse_filter_rule_fast`、`parse_indexer_torrents_fast` /
`parse_indexer_subtitles_fast`、`parse_rss_items_fast`。

PyO3 扩展执行期间释放 GIL。**最该并行的计算已经不占 GIL，剩余负载以 I/O 为主**——
这实质削弱了「多进程释放单核压力」的性能论证。

### 2.5 其它已就绪的地基

| 地基 | 位置 |
|---|---|
| 连接额度已按 worker 数换算 | `app/db/engine.py:296-309`，超限告警 `:344-349` |
| 缓存后端可插拔（内存/文件/Redis） | `app/runtime/cache.py:58,248`，装配 `app/adapters/cache/backends.py:330-341` |
| Redis 已是一等依赖但默认关闭 | `pyproject.toml:78` `redis~=8.0.0`；`CACHE_BACKEND_TYPE="cachetools"` |
| nginx 已为 SSE 单独分流 | `docker/nginx.common.conf` 独立 location，`proxy_read_timeout 3600s` |
| nginx upstream 预留扩容 | `docker/nginx.template.conf:45-49`，注释原文「可以添加更多后端服务器作为负载均衡」 |
| 声明式生命周期清单可导出 | `app/startup/lifecycle/components.py` |

---

## 三、当前并发模型

**单进程 + 单事件循环 + 11 个各自为政的线程池。** 一切跨组件通信靠进程内单例
（`Singleton` 元类约 38 个类）、内存队列与线程→循环桥（`run_coroutine_threadsafe` 约 25 处）。

### 3.1 线程池分布

`ThreadPoolExecutor` 共 **11 个独立池**：全局 `ThreadHelper`（`app/runtime/thread.py:13`，
`CONF.threadpool`=50/100）、APScheduler（`app/scheduler/composition.py:101`，`CONF.scheduler`=50/100）、
工作流（`app/workflow/service.py:170`）、日志（`app/runtime/log.py:358`）、agent 工具、
浏览器、DoH、插件安装、插件目录、搜索（2 处）。

`ProcessPoolExecutor`：**0 处**。`multiprocessing` 仅 2 处，且 `run_in_process`
（`app/runtime/scheduler.py:438,442`）**是死代码**——全仓无调用方，且实现为 `p.start(); p.join()`
仍阻塞调度线程。**这条路从未走通。**

### 3.2 被低估的饱和点

全仓 `current_default_thread_limiter` **零命中**——133 个同步路由与所有 `run_in_threadpool`
offload 共享 anyio **默认 40 线程槽**，而自建池是 50/100。

**这是当前单进程下最可能的饱和点，且与核数无关。** 调它是一行配置。

### 3.3 事件循环阻塞泄漏（4 处）

整体做得不错（重活刻意用同步 `def` 让 FastAPI 自动 offload；AST 扫描确认无 `async def`
路由直接注入同步 `Session`），但仍有真实泄漏：

| # | 位置 | 性质 |
|---|---|---|
| 1 | `app/adapters/media/image.py:48-51` `async def proxy_img` 内 PIL 解码 + `verify()` | CPU |
| 2 | `app/api/endpoints/site.py:572,579` `async def` 内同步 `query.list_sync()`；同型见 `app/api/servarr.py` 9 处 | DB |
| 3 | `app/runtime/extensions/plugin_manager.py:3258-3261` `async_run_plugin_method` 对非协程插件方法**不 offload，直接在协程里调用** | 契约 |
| 4 | `app/api/endpoints/message.py:179`、`app/api/endpoints/system.py:762` | 次要 |

第 3 条尤其值得记账：模块分发器有正确写法可对照
（`app/runtime/extensions/projection/dispatcher.py:469-471` 自动 offload）。

---

## 四、阻碍多进程的结构性原因

### 4.1 事件总线：进程内队列 + 活 callable + 同步 RPC 语义

`app/runtime/events.py:72` `EventManager(metaclass=Singleton)`，`PriorityQueue`（`:84`）、
订阅表 `Dict[EventType, Dict[str, Callable]]`（`:86,88`）。

**最深的一条**：广播侧尚可外置，但 **Chain 事件根本不进队列**——在调用方栈帧内同步执行
并回传被 handler 修改的 `event_data`（`app/runtime/events.py:296-302`、
`app/runtime/event/dispatch.py:66-68`）。其语义是**同步 RPC 而非发布订阅**。
订阅者按 `module.qualname` 索引活对象（`app/runtime/event/registry.py:42-47,107`），不可序列化。

### 4.2 调度器与监控器：MemoryJobStore + 每进程单例 + 无 leader election

`app/scheduler/composition.py:99-101` `BackgroundScheduler` **未指定 `jobstores=`**
（全仓 `SQLAlchemyJobStore` 零命中）→ 默认 MemoryJobStore。
**监控器里还藏着第二个 `BackgroundScheduler`**（`app/monitor/monitor.py:176`），
executor/jobstore/defaults 全未配置。

全仓无文件锁 / PID 锁 / leader 选举（`leader|is_primary|WORKER_ID|flock|filelock` 零命中）。
注：**换 SQLAlchemyJobStore 也不解决**——APScheduler 3.11 本身不提供 leader election。

### 4.3 内存态 SSE / 进度 / 消息队列被 API 直接读回

| 状态 | 位置 | 多进程后果 | 难度 |
|---|---|---|---|
| 进度条 | `app/runtime/progress.py:19,134` → TTLCache region | 开 Redis 后端即跨进程可见 | **易** |
| Passkey 两段式挑战 | `app/application/security/passkey.py:52-100` | 已有 Redis 开关 | 中 |
| Agent 附件注册表 | `app/api/endpoints/agent.py:83` 裸 dict | 上传/引用两段式失效 | 中 |
| **系统消息队列** | `app/application/messaging/message.py:1050` 裸 `queue.Queue()`，`get()` **破坏性弹出**（`:1106-1113`） | 消息**丢失而非重复** | **难** |
| Agent 编辑队列 | `app/application/messaging/agent.py:275-296` | 事件丢失 | 难 |
| 一次性登录票据 | `app/application/security/auth.py:29` `AuthTicketStore` | A 签发 B 消费不到 → 登录失败 | 难 |
| 5 个「等待用户确认」交互管理器 | `app/application/messaging/{agent,media,skill,interaction,plugin}.py` | 创建与回调须同进程 | 难 |

**有利事实**：全库**无 WebSocket**（`@router.websocket` 零命中）。所有实时推送都是 SSE
`StreamingResponse`，实现方式是**轮询本进程状态 + generator yield**，不是主动推送。
故只要被轮询的状态跨进程可见，SSE 即自动可用——无需 sticky session 或连接迁移。

### 4.4 `global_vars` 类属性级全局态，含非幂等语义

`app/runtime/config.py:1345-1361`：`STOP_EVENT`、`SUBSCRIPTIONS`（webpush 订阅表，无持久化）、
`EMERGENCY_STOP_WORKFLOWS`、`EMERGENCY_STOP_TRANSFER`、`CURRENT_EVENT_LOOP`。

最坏的是 `is_transfer_stopped` **读时 pop**（`:1449`）——非幂等，只有持有该标志的进程能观测到。
打到 worker B 的「停止工作流 / 取消整理」永远到不了 worker A 的执行线程。

### 4.5 配置失效通知不跨进程（系统性）

- `app/db/oper/systemconfig.py:16-25` `SystemConfigOper` 是 `Singleton`，构造时整表载入内存字典，
  读路径**不回源 DB**，**无任何跨进程通知**。
- 大量单例继承 `ConfigReloadMixin`（`app/runtime/reload.py:8`），靠**进程内** `EventManager`
  广播配置变更刷新自身。受影响：`DohHelper`、`RedisHelper`、`ScrapingChain`、`TransferChain`、
  `PluginManager`、`Monitor`。多进程下表现为「改了配置只有一个 worker 生效」。

### 4.6 数据库层

| 问题 | 位置 | 性质 |
|---|---|---|
| SQLite 无锁重试/退避 | `app/db/engine.py:57-59`，靠 `DB_TIMEOUT=60` 兜底 | 切 PostgreSQL 可绕开；坚持 SQLite 须加重试 |
| 订阅 check-then-insert 无唯一约束 | `app/db/oper/subscribe.py:171-215` + `models/subscribe.py:119` 非唯一索引 | **必须改代码** |
| 下载历史无去重兜底 | `app/db/oper/downloadhistory.py:57-60` | 同上 |
| 转移记录**相对安全** | `models/transferhistory.py:93` 有唯一索引 | 并发重复写被 DB 拒绝 |

### 4.7 端点耦合量化

38 个模块 / 369 路由（238 `async def` + 131 `def`）。**仅 11 个模块（29%）引用控制面单例**：
`auth` `plugin` `recommend` `site` `discover` `dashboard` `subscribe` `system` `agent` `service` `workflow`。
其余 27 个模块天然无状态。且这 11 个里相当比例只是**读**控制面状态
（如 `dashboard.py:165` 的 `Scheduler().list()`）。

---

## 五、方案空间对比

| 方案 | 隔离强度 | 部署复杂度 | 代码改动量 | 需中间件 | 2026 成熟度 |
|---|---|---|---|---|---|
| 现状：单进程 + 线程池 | 无 | — | — | 否 | 生产可用 |
| **阻塞检测 + 任务看门狗**（HA 模式） | 无隔离但可归因/熔断 | 无 | 小 | 否 | **生产可用** |
| **PyO3 `allow_threads` 热点下沉** | 无 | 无 | 小（已有加速器） | 否 | **生产可用** |
| granian 替换 uvicorn | 无 | 极低 | 极小 | 否 | 生产可用（2.8.2 Stable） |
| huey + SqliteHuey 独立 worker | 进程级 | 中 | 中 | 否 | 可试验（写并发有争议） |
| procrastinate 独立 worker | 进程级 | 中 | 中 | 否，但**强制 Postgres** | 可试验（维护者告急） |
| celery / dramatiq / taskiq | 进程级 | 高 | 中-大 | **是（Redis/MQ）** | 生产可用，违反「不强迫装 Redis」 |
| **HTTP 多 worker 拓扑** | 进程级 | 中 | **大**（§4 四笔账） | 否 | 技术可用，**收益错配** |
| **插件出进程 + RPC**（go-plugin 模式） | **最强** | 高 | 极大 | 否 | 模式生产可用，Python 需自建 |
| free-threading（3.14t） | 无隔离 | 中（换解释器） | 小-中 | 否 | **可试验，本项目不可用** |
| Subinterpreters（3.14） | 中（无内存保护） | 中 | 大（pickle 边界） | 否 | 做插件隔离**不可用** |
| WASM 插件（Extism / componentize-py） | 最强 | 高 | 极大 + 生态断裂 | 否 | **不可用**（pure-Python only） |

### 5.1 被排除方案的具体理由

**free-threading（PEP 703/779）**——3.14 已转 officially supported（单线程开销降至 5-10%），
但对本项目有四条硬阻塞：需从 3.12 跳到 3.14t；**greenlet 3.14t 退出时可能崩溃**而
SQLAlchemy async 依赖它；**psycopg 无 FT wheel**，Postgres 用户直接出局；
插件可 `pip install` 任意包，任何一个未声明 `Py_mod_gil` 会**静默把整进程 GIL 打回来**。
另有实测风险：asyncio 下 `_PyEval_StopTheWorld` 会卡住进程内全部事件循环（CPython #144337）。
重估时点：3.15 正式版 + abi3t（2026-10）且 greenlet/psycopg 落地后。
**零成本期权**：把 `moviepilot-rust` 升到 PyO3 0.28+ 并做 `Sync` 审计。

**Subinterpreters（PEP 734）**——做插件隔离不可用：无内存保护（插件里 C 扩展 segfault
照样带走进程）；第三方扩展需 PEP 489 multi-phase init，而插件依赖 lxml/requests 等大多未做；
跨解释器传对象成本 = pickle，改动量等同上多进程而收益更小。

**WASM 插件**——Extism python-pdk 原文：「only works with pure Python dependencies」；
componentize-py 另有「only import dependencies during **build time**」硬限制，
直接否掉 MoviePilot 的 importlib 动态加载模型。

### 5.2 同类自托管应用对照

| 应用 | 进程模型 | 驱动因素 |
|---|---|---|
| **Home Assistant** | **单进程 + 单 asyncio loop** | 见下，最直接的对照 |
| Sonarr / Radarr | 单 .NET 进程 + 内部 command queue | 无长耗时批处理 |
| Jellyfin | **单进程、单节点，刻意为之** | SQLite 不支持多进程并发写；跑两实例会**损坏数据库** |
| Paperless-ngx | 多进程：webserver / consumer / scheduler / task queue | OCR 是**分钟级 CPU-bound** |
| Immich | server + job worker + 独立 ML 容器 | 缩略图/ML 推理；ML 独立因硬件需求不同 |

**Home Assistant 与本项目同构**——Python、单进程 asyncio、海量第三方集成在进程内跑且
享有同等权限。**它在几千集成、百万用户规模下至今没有为此上多进程**，而是三层对策：

1. **检测 + 点名**：`homeassistant.util.loop` 自 2024.7.0 起包装常见阻塞 stdlib 调用，
   检查调用栈，日志里直接给出**是哪个集成、哪一行、真正阻塞的库函数**。
2. **承认检测有盲区**：能抓 `open`，抓不到后续 blocking read/write。
3. **真要隔离就用容器**：Add-ons 每个跑在独立 Docker 容器；HACS 自定义集成则留在进程内。

**归纳**：媒体服务器类（Jellyfin、Sonarr/Radarr）= 单进程；文档/照片摄入类
（Paperless、Immich）拆进程是因为工作单元是**分钟级 CPU 批处理**。
MoviePilot 的负载形状属于前者（订阅/搜索/整理是 I/O-bound 秒级），
**但插件问题属于 HA**。

---

## 六、推荐：三轨推进

### Track A —— 确诊与止血（立即，零新依赖，无部署变更）

**A0. 先确诊，别赌。** 现有「插件拖垮应用」的归因存在两种可能且解药不同：

- 定时任务与插件跑在 **APScheduler 线程池**（`composition.py:99-102`），
  纯 Python busy loop 是通过 **GIL 争抢 / 线程饥饿**饿死 asyncio loop 线程；
- 而 §3.3 的 4 处泄漏是真正的**事件循环阻塞**。

先加事件循环延迟探针（`loop.slow_callback_duration` 或期望-实际时差）+ 线程栈 dump，
把两者区分开。**不确诊就选型等于赌。**

| 项 | 内容 |
|---|---|
| A1 | 调 anyio 线程槽（§3.2）——当前 40 槽是最可能的饱和点，一行配置 |
| A2 | 修 §3.3 的 4 处事件循环阻塞泄漏，尤其 `plugin_manager.py:3258-3261` 的插件同步方法未 offload |
| A3 | HA 模式阻塞检测器：日志中**点名是哪个插件** |
| A4 | 插件独立有界线程池：把「一个插件吃光全局线程池」降级为「吃光自己的配额」 |
| A5 | APScheduler job 墙钟看门狗 + 插件连续超时自动禁用（circuit breaker） |
| A6 | PyO3 `allow_threads` 继续下沉热点——今天、在 3.12 上、零部署变更即拿到真并行 |

**Track A 直击已报症状，且把责任推给插件作者是可持续的**，而架构隔离是一次性的。

### Track B —— 把进程边界画在插件周围（战略）

这是唯一能同时满足**故障隔离**与**多版本插件分身**的边界，也是本 fork 架构溢价的兑现处。

- 形态：go-plugin 模式（子进程 + RPC），Python 侧需自建 harness。
- **蓝本已在仓库内**：`fsproxy.py` 的 Popen + 行协议 + 心跳 + 崩溃自愈 + fail-open 回退。
- 契约要求：插件不持有宿主对象引用，交互走序列化协议——这与「跨进程要求插件不持有宿主对象」
  的既有结论一致，也正是「多版本分身」需要的前提（每版本一进程，全局单例问题从根上消失）。
- 前置依赖：§4.1 的 Chain 事件同步 RPC 语义必须先形式化为可跨进程的调用契约。

### Track C —— HTTP 多 worker 拓扑（可选，默认关闭）

**降级为可选项**，因为它解决的是可用性而非本文开头的性能诉求。若要做：

| 角色 | 实例数 | 承载 | 生命周期组件 |
|---|---|---|---|
| **Control** | 恒为 1 | 调度器、监控器、插件、工作流、命令服务、事件总线、**全部 SSE 长连接** | `ALWAYS` + `NORMAL_ONLY` |
| **Web** | N，默认 0 | 纯 CRUD / 查询 / 文件流 | 仅 `ALWAYS` |

**关键设计决定：SSE 归 Control，不归 Web。** 教科书做法是让 HTTP 层彻底无状态、
共享态全外置到 Redis——但自托管场景不能强迫用户装 Redis（`CACHE_BACKEND_TYPE`
默认 `cachetools` 正是此考量）。依据 §4.3：SSE 端点是「轮询本进程状态」，
而它们轮询的状态**恰好全部属于 Control 角色**。让轮询者与被轮询状态同进程，
跨进程同步需求自然消失。

落地成本极低——`docker/nginx.common.conf` 里 SSE 已是**独立 location 块**，只需改 `proxy_pass`：

```nginx
upstream backend_control { server 127.0.0.1:${PORT}; }
upstream backend_api     { server 127.0.0.1:${WEB_PORT_1};
                           server 127.0.0.1:${WEB_PORT_2}; }

location ~ ^/api/v1/(system/(message|progress/|logging)|search/.*/stream$|message/agent/stream$) {
    proxy_pass http://backend_control;    # 唯一改动
}
location /api { proxy_pass http://backend_api; }
```

`N=0` 时退化为今天的单进程形态——这是必须保留的回退路径。

### 6.1 与原始命题的关系

| 维度 | 原设想 | 本文 | 修正理由 |
|---|---|---|---|
| 无状态/有状态分离 | 核心 | **认可**，且已实现大半 | `LifecycleMode` 已分组 |
| HTTP 层 | 完全无状态 | 无状态但**不含 SSE** | HTTP 层实际持有会话态；外置需强依赖 Redis |
| 状态塔 | 持有状态 | 持有状态 **+ 独占长连接** | 消除跨进程同步需求 |
| worker 池 | 核心之一 | **边界改画在插件周围** | HTTP 分片会**复制**失控插件而非隔离它 |
| 释放单核压力 | 目标 | **先确诊** | Rust 已接管热点；40 线程槽才是疑似饱和点 |

---

## 六bis、落地状态（2026-08-24）

Track A 与 Track B 第一期已实现，提交 `ac0a31565`、`2dbb7fc04`、`e0f680358`。

### Track A

| 项 | 状态 | 落点 |
|---|---|---|
| A0 事件循环延迟探针 | 已落地 | `app/runtime/diagnostics/loop_probe.py` |
| A1 anyio 线程槽对齐 | 已落地 | `app/runtime/thread.py`，`API_THREAD_LIMIT`，`LifecycleComponent("并发线程槽", start_order=1)` |
| A2 事件循环阻塞 | 已落地 | image / site / servarr / system / message 五处 + 插件同步方法卸载 |
| A3 阻塞归因与点名 | 已落地 | `app/runtime/diagnostics/blocking.py` + `app/doctor/checks.py` 检查项 |
| A4 插件执行配额 | 已落地 | `app/runtime/extensions/plugin_quota.py`，覆盖插件方法调用与广播扇出两条入口 |
| A5 作业看门狗与熔断 | 已落地 | `app/scheduler/{watchdog,breaker,supervision}.py` |
| A6 PyO3 `allow_threads` 下沉 | **未做** | 属 `moviepilot-rust` 独立仓，不在本仓库范围 |

关键设计决定：

- **不 patch stdlib 阻塞函数**。插件可引入任意 C 扩展，patch 覆盖面无法穷尽，
  HA 自身也承认「能抓 `open`，抓不到之后的 read/write」。改用独立 OS 线程按
  `sys._current_frames()` 采样事件循环线程活帧，能看到真正的阻塞现场且零干扰。
- **doctor 检查项区分两种病因**：栈中有插件帧则点名插件，否则指向线程池繁忙线程
  经 GIL 争抢饿死事件循环。这是 Track A0「先确诊，别赌」的落点。
- **配额与熔断的收敛方向刻意相反**：配额按**插件类**发放（防止插件增开实例线性
  放大份额），熔断按**作业**跳闸（防止一条定时任务拖死整个插件的 API、页面与事件处理）。
- **广播扇出用独立的短等待超时**（1 秒，协程路径为 60 秒）。取槽阻塞的是唯一的
  广播消费者线程，等待期间全部排队事件停止分发；宁可让占满配额的插件短暂突破上限，
  也不能让它拖停整条事件总线。
- **看门狗只观测不终止**。Python 没有安全的线程终止手段，强杀会留下不一致状态。
- **作业观测挂在作业函数外层而非 APScheduler 作业事件**：`SchedulerEngine.start`
  吞掉作业异常故 `EVENT_JOB_ERROR` 永不触发；协程作业提交后 `start` 立即返回故
  `EVENT_JOB_EXECUTED` 会在作业仍在运行时就发出。作业事件仅用于 `EVENT_JOB_MISSED`。

### Track B 第一期

`app/runtime/extensions/remote/`（protocol / host_api / proxy / plugin_worker），
**独立模块，未接入插件系统**，默认不启用。

PoC 已证明核心命题：一个**既不 sleep 也不做 IO 的死循环插件**——在宿主进程内
无法中断——跨进程后被超时 SIGKILL 隔离，宿主完好、惰性重启并重放 `init_plugin`。
**这是进程边界能做而 Track A 的配额做不到的事**：配额只能限制并发数，无法中断
一个已经跑起来的死循环。两轨互补，不是重复。

### 遗留项

| 项 | 说明 |
|---|---|
| A6 PyO3 `allow_threads` | 需在 `moviepilot-rust` 独立仓推进 |
| `async_dispatch_chain` 的配额 | `invoke_async` 把插件同步绑定卸载到 anyio 池（非共享池），未加闸门。该路径 handler 串行 `await`、无无界扇出，风险低 |
| `misfire_grace_time=1` | 确认过紧（调度延迟 1 秒即整次跳过），建议 60 秒。本轮只加观测（`EVENT_JOB_MISSED` 计数），待真实数据再调 |
| `app/monitor/monitor.py:176` 第二个 BackgroundScheduler | 该纳管但不能接 `JobSupervision`（裸 APScheduler，且自带名为 `watchdog` 的作业语义打架）。应显式配置其 executor/jobstore/job_defaults 并复用 `JobWatchdog` |
| Track B 接入 `plugin_manager` 的三个障碍 | ①宿主回调白名单落地会撞分层门禁——`app/runtime/` 不能反向依赖 `app/db/`，装配点归属需先裁决；②白名单最小子集撑不住真实插件，`get_plugin_database()` 交出活的 SQLAlchemy 会话句柄**根本过不了进程边界**；③十二族里只有纯数据族能原样过界，逐族判定可序列化边界的工作量大于 RPC 骨架本身 |

### 已知 pre-existing 测试失败（非本次引入，均由开工前的提交带入）

- `test_official_plugin_baseline_records_external_source`——fixture `schema_version` 2≠3
- `test_no_unmapped_class_level_annotations_in_db_package`——`app/db/oper/subscribe.py`
  的 `SubscribeStageResult` 用了裸类级注解，由 `35e616242` 引入

---

## 六ter、单核满载的确诊结果（2026-08-24）

Track A0 主张「先确诊，别赌」。生产反馈**单核 CPU 持续 100%**（持续而非周期尖峰）
后，三路并行排查（忙循环猎捕 / SSE 轮询开销 / 后台常驻任务）给出了结论。

**先缩小范围的推论**：Python 单进程受 GIL 约束最多占满一个核。「单核满载且不再上涨」
必然意味着**有一个线程在持续执行纯 Python 字节码**——IO 等待不吃 CPU，Rust 加速器
会释放 GIL。所以这不是「负载重需要更多核」，而是**某处在空转**。加机器、开多进程
都治不了，只会让每个 worker 各烧一个核。

### 根因：随机壁纸无界自旋（上游缺陷）

`app/application/orchestration/tmdb.py` 的 `get_random_wallpager` 与
`async_get_random_wallpager` 以 `while True` + `random.choice` 反复抽取，直到抽中带
`backdrop_path` 的条目。趋势榜整页不带该字段时循环没有退出条件、不休眠、不做 IO。

- `media_type=person` 的条目天然没有背景图；TMDB 反代裁剪载荷时会整页缺失。
- 入口 `GET /login/wallpaper` **公开未鉴权**且是同步路由，跑在 anyio 线程池上会
  **永久占用一个 worker 且无法取消**；`@cached` 无 single-flight，登录页每刷新一次
  就再多一个自旋线程。异步孪生版本直接卡死事件循环。
- `git log -S` 追溯到 2023-09-22 提交 `838048fd8`，`upstream/v2` 的
  `app/chain/tmdb.py:153` 与 `:309` 至今仍在。**这是上游缺陷，非本 fork 引入。**

### 三个放大器

| 项 | 位置 | 机制 |
|---|---|---|
| 目录监控轮询 | `app/monitor/watcher.py` | 轮询模式每间隔递归 stat 整棵目录树；该模式恰恰只在大媒体库触发（兼容模式 / 目录数接近 inotify 上限）。原 300ms 是上游为小型开发目录调的默认值 |
| 日志等级闸门击穿 | `app/runtime/log.py` | 精确闸写作 `if plugin_id and ...`，宿主日志无精确闸，只受「最宽松一档」下限约束。任一插件开 DEBUG，全进程 `logger.debug()` 都付 30-80 帧栈回溯并写盘 |
| 阻塞采样自身开销 | `app/runtime/diagnostics/blocking.py` | 10Hz 调 `traceback.extract_stack`，后者对栈中每个文件做 `os.stat` 并读源码行。**本分支自己引入**，等于在制造它要测量的延迟 |

### 已修（提交 `fe1e049d0`、`eaa6da5d1`）

自旋改为先筛候选再随机选取；采样改为直接沿帧链读代码对象；日志精确闸提到栈回溯
之前并改读 ContextVar；本地轮询间隔 300ms→2000ms 且新增 `MONITOR_POLL_DELAY_LOCAL`，
并修正降级路径按目录当前性质重新推导间隔；日志 SSE 增长分支补节流与批量读取。

### 运维侧缓解（无需改代码）

- 壁纸源改为非 `tmdb`，可立即规避根因。
- 提高宿主机 `fs.inotify.max_user_watches`（建议 524288）避免目录监控降级到轮询。
- `py-spy dump --pid <PID>` 是定位此类问题的首选：单核满载时那个线程会明确停在
  某个纯 Python 函数里，不必猜。

### 后续优化（提交 `ef5afb8c8`、`c26a95b7f`）

确诊后对四个方向做了实测测绘，**Rust 加速器判定为已完成**——逐个 benchmark 后
NFO 生成 0.111ms、图片处理只做格式嗅探且已卸载、重命名模板每文件仅一次、
bencode 解析在 Python 侧根本不存在、字符集检测已被性能模式短路。热路径剩余部分
全在等网络与磁盘，**不存在值得新增的 PyO3 绑定**。真正的浪费是每写一行 fsync
一次与串行等待，据此落地：

| 项 | 关键决策 |
|---|---|
| SQLite `PRAGMA synchronous=NORMAL` | 经 connect 事件设置（每连接会话状态）；`journal_mode` 保持构建期一次性设置（持久化于库文件头），二者语义不同不可统一 |
| 同步 HTTP 连接复用 | 只共享 `HTTPAdapter`，`Session` 每请求新建（非线程安全且 jar 会串味，新建实测仅 7µs）。cookie 隔离由结构保证而非策略过滤 |
| 站点刷新并发化 | 并发抓取 + 顺序汇总，共享可变状态全留主线程。**不用 `as_completed`**——缓存键插入序决定返回值序，下游订阅匹配依赖它。**不加 per-site 超时**——Python 杀不掉线程，future 超时是假超时 |
| discover 缓存容量 1→256 | `call_cached=False` 保持不变，它是刻意让组合式列表端点跳过共享低层缓存 |
| 缓存键遗漏实例身份 | `@cached` 剥去 `self`，实例相关结果必须把身份写进参数（Plex 服务器地址、tnode 站点域名） |
| 批量循环异常隔离 | 修 9 处；交互式命令、纯内存遍历、单实体聚合判定为刻意 fail-fast 不改 |

### 遗留项

- 全仓 **448 处 `logger.debug(f"...")`**，f-string 在调用点无条件求值，闸门修复
  消除了栈回溯与写盘成本但消不掉这笔格式化开销。需改为惰性 `%s` 参数或在调用点加
  `isEnabledFor` 守卫，工作量大且分散。
- **并发上限不一致**：异步侧 `_DEFAULT_MAX_CONNECTIONS=40`，而 `search.py:2414`
  的信号量允许 50。当前因跨站点扇出、单 host 并发远低于 40 而不会真触发丢连接，
  但两个数字应显式对齐。
- 媒体服务器 `Recursive=true` 与 per-series 剧集 N+1（`emby.py:859`、
  `jellyfin.py:1017`、`mediaserver.py:466`）：500 部剧 = 500 次串行请求，
  在 fsync 项落地后会成为 6 小时同步的主导项。改动涉及库遍历语义，风险中高。

---

## 七、风险与回退

| 风险 | 缓解 |
|---|---|
| 插件可在宿主进程内自由起线程，行为不可控 | Track A4/A5 配额与熔断；Track B 根治 |
| SQLite 多进程写争用（Jellyfin 拒绝多实例的同一理由） | Track C 阶段 Web 只读；多 worker 场景文档建议切 PostgreSQL |
| Control 成为单点 | Control 即今日单进程，可用性不低于现状 |
| 改造引入回归 | `tests/test_process_topology.py` + `test_uvicorn_entrypoint.py` + lifecycle/session/singleton 共 **65 项现有测试**（已验证全绿）；全套 8007 项 |
| 用户不装 Redis | 全部三轨均不把 Redis 列为必需 |

**回退路径**：`API_WORKERS=1` 即恢复今日单进程形态，无需回滚代码。

---

## 附：本文事实来源

六路并行测绘（运行时并发模型 / 全局可变状态 / DB 与缓存并发边界 / API 层状态耦合 /
部署与依赖清单 / 外部技术选型），全部结论均带 `file:line` 或外部来源。
关键外部来源：PEP 779、PEP 734、PEP 803、Python 3.14 What's New、
py-free-threading tracking（2026-08-22）、PyO3 free-threading guide、CPython #144337、
Home Assistant Blocking operations 文档、Paperless-ngx / Immich / Jellyfin 架构文档。
