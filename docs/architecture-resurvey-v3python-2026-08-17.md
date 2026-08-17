# v3 结构再梳理：从"分层单体 + 补丁治理"到真微内核

> 本文是对 v3-python 系分支（基线 `feat/plugin-multi-instance` @ 421b64c72）的一次全量结构重测。
> 前提：**忽略既有文档中的一切约束性结论，唯一保留的硬性要求是"单向 import"**。
> 本文只做梳理、诊断与设计方案，不包含任何源码修改。
>
> 测量方法：AST 级全量 import 扫描、逐包行数统计、四路专项排查
> （编排层重叠 / 扩展机制全景 / api-agent 耦合面 / 插件真实 API 面）。
> *Date: 2026-08-17*

---

## 一、测量结果：现状到底长什么样

### 1.1 规模分布

| 包 | 行数 | 文件数 | 名义角色 | 实测角色 |
|---|---:|---:|---|---|
| `app/modules/` | 68,512 | 146 | 可插拔后端 | 37 个内建扩展（树内、随宿主发版） |
| `app/plugins/` | 47,379 | 194 | 插件宿主目录 | 4 个内置插件（p115strmhelper 一家占 42,388 行） |
| `app/agent/` | 40,441 | 140 | "入口层" | 内嵌巨型子系统（82 个内建工具静态焊死） |
| `app/chain/` | 30,275 | 36 | 编排层 | v2 遗留编排内核 + 上帝基类 |
| `app/api/` | 16,477 | 42 | HTTP 端点 | 事实上的第三业务层（见 1.4） |
| `app/runtime/` | 15,220 | 50 | "进程级契约" | 契约 + 机制 + 3 个重型子系统的大杂烩 |
| `app/application/` | 14,167 | 39 | 应用服务 | 被全体上层直接消费的共享服务库 |
| `app/adapters/` | 12,098 | 27 | 技术 I/O | 基本名实相符 |
| `app/db/` | 8,793 | 55 | 数据访问 | 名实相符（但寄养着 agent 的 3 张表） |
| `app/domain/` | 7,654 | 21 | 纯业务语义 | 名实相符，最干净的一层 |
| `app/schemas/` | 7,329 | 39 | 传输模型 | 混入了运行时依赖与渠道能力静态表 |
| 根散件 `*.py` | 3,798 | 6 | — | `scheduler.py` 1,598 / `cli.py` 1,203 / `command.py` 489 |
| 其余（workflow/monitor/doctor/startup/sdk/foundation/testing） | ~8,400 | — | — | — |

**结论 1：不存在"最小内核"。** 除去 modules/plugins，宿主自身约 16 万行；
号称入口层的 agent 是全树第三大包；号称契约层的 runtime 是第六大包。

### 1.2 单向 import：文件级成立，包级失守

`tests/test_architecture_dependencies.py` 用 Tarjan 强连通分量保证了**模块（文件）级无环**，
并自陈"允许的环只存在于单一包内部"。但包级聚合后，方向性已经失守：

| 违规 | 具体边 | 门禁现状 |
|---|---|---|
| `runtime ↔ db` | `runtime/extensions/plugin_manager/*`、`service_registry.py` 等 8 文件 → db；db → runtime.config/log | `FORBIDDEN_IMPORT_PREFIXES["app.runtime"]` 只禁 application/sdk，**未禁 db** |
| `runtime ↔ schemas` | `schemas/response.py:5`、`schemas/dashboard.py:5` → `runtime.localization.LocaleHelper` | 无禁令 |
| `application ↔ agent` | `application/messaging/skill.py:8` → `agent.skills.registry`；agent 18 文件 → application | 门禁只看住了 `application/agent.py` 门面这一个文件 |
| `chain ↔ workflow` | `chain/workflow.py` → `app.workflow.WorkFlowManager`；workflow 9 文件 → chain | 无禁令 |
| `modules → application`（反向） | **29 个模块文件**引用 DirectoryHelper / MessageHelper / TemplateHelper / ImageHelper / AudioMetadataHelper / MediaServerIdentityHelper / messaging.agent | 文档图声称 `App → Modules` 单向；门禁对 `app.modules` **没有任何出向禁令**（只禁跨模块与 chain） |
| `sdk → api`（向上） | `sdk/_legacy/user.py` → `app.api.deps`（8 个 get_current_* 函数） | manifest 里唯一一条 `owner="api"` 映射 |
| 运行态双向 | `ChainBase.__init__`（`chain/__init__.py:62-63`）把 `self.multicast` 注入 application 层的 `MessageQueueManager` | 静态分析不可见 |

**结论 2：**"严格单向依赖分层"目前只是文件级事实；
**包级依赖图不是 DAG**，而文档与门禁都在按"已是 DAG"来叙述。

### 1.3 治理方式：墓碑 + 特判

- 门禁测试里躺着 **38 项 `RETIRED_CANONICAL_FILES` 墓碑清单** 与 8 个 `RETIRED_CANONICAL_ROOTS`
  （infrastructure / messaging / platform / security / services / extensions / integrations / compat）——
  这些顶级包都曾存在又被收敛，靠"防复活断言"钉死。
- `app/service/`、`app/managers/` 两个**幽灵目录**（只剩 `__pycache__`）仍留在树上。
- 约 20 个点状特判测试（StringUtils 禁用、cache 契约不许碰具体适配器、chain 不许 import 下载器 SDK……）
  各自钉住一个历史事故。

**结论 3：架构边界不是由结构自证的，而是由一堆事后补丁断言钉住的。**
每次结构漂移 → 加一条特判；特判越多，说明结构本身越无法表达约束。

### 1.4 四个编排面与一个上帝基类

专项排查证实"编排"这件事目前散在四处：

1. **`app/chain/`（v2 内核）**：`ChainBase` MRO 合计 **106 个方法（78 public）**，
   其中 **58 个能力端口横跨 8 个互不相干的业务域**，无条件下发给全部 25 个子类——
   29 行的 `chain/notification.py` 继承了 100+ 个无关方法；`chain/agent.py` 是 `pass` 空壳，
   继承 ChainBase 只为拿消息状态机。同时 **6 个 chain 文件零分发、6 个近零分发**：
   `workflow.py`(1271) / `interaction.py`(1567) / `recommend.py`(673) / `site.py`(987) /
   `_music.py`(420) / `torrents.py`(843) 合计约 5,760 行只有 4 次模块分发——
   它们不需要 run_module 聚合能力，纯粹为继承而继承。
2. **`app/application/`（v3 内核）**：38 个文件中**仅 3 个是 chain 专属**
   （formatting / messaging.plugin / security.cookie），其余被 api / agent / modules / sdk 直接消费。
   application 实际不是"编排层的下半部"，而是一个被所有人拿来用的**共享服务库**。
3. **`app/scheduler.py`（1,598 行根散件）**：自带 `SchedulerChain`，import 6 个 Chain + 4 个 Model +
   PluginManager，是**事实上的第二编排层**；被 5 个大端点直接 `Scheduler().start("<字符串 job id>")`。
4. **`app/command.py`（489 行根散件）**：自带 `CommandChain`，import 6 个 Chain + Scheduler。

而 **api 端点层自己又长成了第三个业务层**：16+ 处直接调 ORM Model 静态方法
（`site.py`、`subscribe.py`、`servarr.py` 12 处）、20 处直接踢 `Scheduler()`、
12 处直接 `eventmanager.send_event` 充当 chain 事件发起方；
`endpoints/agent.py` 2,315 行，内含进程级可变状态注册表和 **`subprocess.run(["ffmpeg",…])` 音频转码**；
`endpoints/workflow.py:340-382` 在 HTTP handler 里手写完整的调度事务。

另有命名共振加剧混乱：`chain/storage.py` 与 `application/storage.py`、
`chain/notification.py` 与 `application/notification.py` 是**纯同名零调用关系**的两组东西；
`chain/site.py`、`application/site/`（外部二进制落地目录）、`application/messaging/site.py` 三个"site"互不相干；
`chain/interaction.py` 与 `application/messaging/interaction.py` 存在同名同义函数的**重复实现**
（`_page_items`/`page_items` 等，互不 import）。

### 1.5 扩展机制：11 套并存，"微内核"被实例化了 3 次

全树共发现 **11 套互相独立的扩展机制**（详细判据见附录 A），要点：

| 机制 | 单元数 | 新增是否动内核 |
|---|---:|---|
| Host Module（`_ModuleBase` + capability.toml） | 37 | **半焊死**：同族免改；新族必改 `ModuleType` + 6 个 subtype 枚举 + `_SERVICE_CONFIG_GETTERS` |
| Plugin（`_PluginBase`） | 市场 | 否（12 个 hook 方法名探测） |
| 配置化服务（Downloader/MediaServer/Notification） | 3 族 | 实例否；**新族要改 3 处静态表** |
| Managed Resource（adapters 的 capability.toml） | 1 | 发现否；**使用方硬编码 capability id** |
| Agent Capability（agent 的 capability.toml） | 4 | **是**（硬编码常量 + 具名 loader） |
| Workflow Action | 15 | 否 |
| Agent 内建工具 | 82(+3) | **是（焊死）**：硬编码 90 行 import + 静态元组 |
| Agent 插件/MCP 工具、Skills/Personas/Subagents | 动态 | 否 |
| Storage 后端 | 7 | **是**：`StorageSchema` 枚举焊死在 `schemas/types.py` |
| Indexer Parser / Spider | 20 / 8 | Parser 枚举焊死；**Spider 纯 if/elif 链，新增要改 4 处** |
| 静态清单族（API 路由 35、调度作业 20、命令 preset 14、Doctor 检查 9、认证 1、渠道能力表） | — | **是**（全部硬编码 list/dict） |

- `CapabilityRuntime`（1,427 行，真正的微内核候选）被实例化了 **3 次**
  （ModuleManager / managed_resources / agent runtime_loader），Registry 互不共享；
  `capability.toml` 共 42 份（modules 37 + adapters 1 + agent 4）。
- 能力申明存在**三重表达**：manifest 的 `metadata.type/subtype`（静态）、
  类上的 `get_type()/get_subtype()`（运行期）、`provided_capabilities()` 反射推导（真正用于分发）。
- 真正做到"新增扩展不动内核"的只有 5 处：Plugin、Workflow Action、Agent 插件/MCP 工具、Skills 族。

**结论 4：不是"一切皆扩展"，而是"每样东西各造一套扩展机制"。**

### 1.6 插件真实 API 面：官方正门使用率为 0

以 4 个内置插件全部 318 条面向宿主的 import 语句为分母：

```
旧 compat 路径（app.core / app.helper / app.utils / app.log / app.db.*_oper）   243 条   76.4%
canonical 直捅（app.chain / app.db / app.schemas / app.modules / app.scheduler）  55 条   17.3%
canonical 模块 + 旧符号 overlay（Notification→Message 等）                        20 条    6.3%
app.sdk.* 官方正门                                                                 0 条    0.0%
```

- `app/sdk/` 在**全部生产代码中零直接消费者**（含宿主自身），只被 compat manifest 的 9 条 target
  和 3 个测试文件触达。**compat（148 条映射 + meta path finder）才是事实上的 SDK**，
  它在 `app/__init__.py:18` 无条件安装，任何 `import app` 的进程都绕不开。
- 宿主自己的 `_PluginBase`（`app/plugins/__init__.py`）就走 4 条 compat 路径——
  插件哪怕一行不写，继承基类即吃进旧路径。
- 除两条官方通路外还存在**第三条通路**（无任何声明与版本承诺）：直捅 8 个 Chain 类（24 处）、
  宿主 ORM 模型与 `DbOper` 基类、`app.modules.filemanager` 内部（4 处）、
  模块级私有锁 `task_lock`、name-mangled 私有方法；
  以及**第四条通路**：826 行的 `p115strmhelper/patch/` 在运行时 monkey-patch
  宿主 `TransferChain` 私有方法、`U115Pan` 的 5 个方法、甚至另一个插件的类。

**结论 5：插件 API 处于"官方门无人走、事实门无承诺"的双轨失灵状态。**
插件生态实际锚定的是 v2 的旧路径 + v3 的内部实现细节。

---

## 二、诊断：为什么感觉是"两套产物的强行兼容"

把第一章的测量拼起来，混乱不是弥散的，而是集中在**五对"新旧双轨"**上。
每一对都是：v2 的机制没有退役，v3 的机制没有接管，两者在同一棵树上各自生长。

| # | 旧轨（v2 血统） | 新轨（v3 血统） | 现状 |
|---|---|---|---|
| 双轨 1 | `chain`：继承式广播内核（ChainBase 58 端口） | `application`：组合式服务库 | chain 吃掉了新业务（agent 空壳链、workflow 链），application 被越级消费，另有 scheduler/command 两个编外编排面 |
| 双轨 2 | `modules`：枚举族 + 静态表身份体系 | `plugins`：方法名探测 + 市场生态 | 分发面已同权（插件可 provides_modules 且优先响应），但身份/发现/生命周期/能力申明各一套 |
| 双轨 3 | `compat`：旧路径 meta path finder | `sdk`：官方稳定导入面 | 事实与名义完全倒挂（76% vs 0%） |
| 双轨 4 | 能力=枚举（ModuleType/subtype/StorageSchema/SiteSchema） | 能力=方法名索引（providers_for 反射推导） | 三重表达并存；枚举把 6 个扩展族焊死在内核 schemas 里 |
| 双轨 5 | 治理=墓碑+特判测试（38+20 条） | 治理=capability manifest 校验 | 结构不能自证，规则散在测试里 |

**根因判断**：v3 重构一直在做"把 v2 的器官搬到新房间"（目录迁移、门面注入、兼容映射），
但没有做"让两套心脏合并成一颗"。`CapabilityRuntime` + 能力索引这套真正的微内核骨架已经存在
且质量不错，但它只接管了 Host Module 一个族；其余 10 套机制、4 个编排面、
两套插件 API 各自为政。于是每引入一个 v3 机制，旧机制不减反增一层兼容——
这正是"两套产物强行兼容"的观感来源。

---

## 三、目标架构：六环模型与唯一硬规则

### 3.1 设计原则

1. **内核只认识一种东西：扩展。** 内核不 import 任何具体能力实现；
   "内建"与"三方"的差别只是发行方式（预装 vs 市场），不是机制。
2. **唯一硬规则：包级单向 import。** 用一张显式的"允许依赖矩阵"取代 20 条特判；
   文件级无环由包级 DAG 自然蕴含。
3. **静态依赖收敛到契约。** 服务层与扩展层互相不 import，双向通信全部经内核
   （能力分发 dispatch + 事件总线 events）。
4. **一份知识只表达一次。** 能力申明、路由清单、调度作业等不得同一知识多处硬编码。

### 3.2 六环分层（自下而上）

```
┌────────────────────────────────────────────────────────────────────┐
│ edge        app/api  app/cli  app/startup(组合根)  app/compat      │  ← 可依赖以下所有环
├────────────────────────────────────────────────────────────────────┤
│ extensions  app/extensions/*  =  现 modules/* + plugins/* + agent  │
│             + workflow + monitor + doctor + servarr…（一切扩展）    │  ← 只可依赖 services 门面(SDK) + 以下三环
├────────────────────────────────────────────────────────────────────┤
│ services    app/services/*  =  chain + application 合并后的用例层   │  ← 只可依赖以下三环
├────────────────────────────────────────────────────────────────────┤
│ domain      app/domain + app/schemas（纯语义与传输模型）             │  ← 只可依赖 foundation
├────────────────────────────────────────────────────────────────────┤
│ platform    app/adapters + runtime 的机制部分（thread/rate/…）      │  ← 只可依赖 kernel 契约 + foundation
├────────────────────────────────────────────────────────────────────┤
│ kernel      config / log / events / cache 契约 / capabilities       │
│             / ExtensionHost（现 runtime/extensions 收编重组）        │  ← 只可依赖 foundation
├────────────────────────────────────────────────────────────────────┤
│ foundation  无状态原语（现状保持，已达标）                            │  ← 依赖为空
└────────────────────────────────────────────────────────────────────┘
```

允许依赖矩阵（行=源，列=可 import 的目标；这是未来唯一的门禁主断言）：

| ↓源 \ 目标→ | foundation | kernel | platform | domain | services | extensions | edge |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| foundation | — | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| kernel | ✓ | — | ✗ | ✗ | ✗ | ✗ | ✗ |
| platform | ✓ | 契约✓ | — | ✗ | ✗ | ✗ | ✗ |
| domain | ✓ | ✗ | ✗ | — | ✗ | ✗ | ✗ |
| services | ✓ | ✓ | ✓ | ✓ | — | **✗** | ✗ |
| extensions | ✓ | ✓ | ✓ | ✓ | **仅 SDK 门面** | **✗（跨扩展禁）** | ✗ |
| edge | ✓ | ✓ | ✓ | ✓ | ✓ | 生命周期✓ | — |

关键裁定（对照现状的三处最痛）：

- **services ✗ extensions**：编排层触达扩展只经 kernel 的 dispatch（今天的
  broadcast/multicast/unicast 三级分发已达标，保留语义、下沉位置）。
- **extensions ✗ services 实现**：扩展需要宿主服务时走 SDK 门面（受版本承诺的投影），
  今天 `modules → application` 的 29 文件反向边与插件直捅 Chain 类都收敛到这里。
- **extensions ✗ extensions**：跨扩展协作经 kernel 事件或能力分发
  （今天 p115strmhelper patch 另一插件、agent 工具 import doctor 都属此类违规）。

### 3.3 内核的最终形态

kernel 收缩为五件东西，目标 ≤ 8k 行：

1. **contracts**：`Extension` 统一契约（见 D3）、能力模型、事件模型、缓存协议。
2. **ExtensionHost**：唯一一个 `CapabilityRuntime` 实例 + 唯一一张能力注册表；
   现 ModuleManager / PluginManager / managed_resources / agent runtime_loader 四套宿主合并于此。
3. **dispatch**：三级分发（广播/多播/单播）+ 能力索引（方法名反射推导，现有实现直接上收）。
4. **events**：事件总线（现 `runtime/events.py`，已达标）。
5. **config / log**：现 `runtime/config.py`、`runtime/log.py`（log 已是依赖叶子，达标）。

`runtime` 这个名字随之退役：契约部分升入 kernel，机制部分
（thread/rate/debounce/coalesce/execution/scheduling/progress/gc/state/reload/localization）归 platform，
compat/deprecation 归 edge。

---

## 四、设计决策

### D1　runtime 解体，plugin_manager 迁出"契约层"

- `runtime/extensions/`（19 文件，含访问 DB 的 plugin_manager 一族）整体迁为 kernel 的 ExtensionHost。
  其 DB 依赖（插件安装清单、配置）通过**注入的存储端口**解决：kernel 定义
  `ExtensionStateStore` 协议，db 层提供实现，startup 注入——kernel 不再 import `app.db`。
- `runtime.localization.LocaleHelper` 下沉：schemas 需要的翻译能力改为纯函数注入
  （schemas 定义 `Translator` 回调协议，startup 装配），消除 `schemas → runtime`。
- 三个 `CapabilityRuntime` 实例合一，42 份 capability.toml 进同一张注册表
  （kind 命名空间已天然区分：`host_module` / `plugin_module` / `managed_resource.*` / `agent_*`）。

### D2　chain + application 合并为 services，ChainBase 由继承改组合

- **分发原语脱离继承**：`broadcast/multicast/unicast/run_module` 从 ChainBase 摘出，
  变成 kernel dispatch 的自由函数/轻量客户端。任何服务（乃至扩展）按需 import 使用，
  不再靠继承一个 106 方法的基类获得。58 个能力端口按域拆成
  `MetadataPorts` / `DownloadPorts` / `MediaServerPorts` 等薄客户端（纯转发，无业务）。
- **零分发文件直接降为普通服务**：workflow / interaction / recommend / site 用户数据部分 /
  _music / torrents 缓存（约 5,760 行）改为 services 下的普通类，删掉继承。
  `chain/agent.py`（pass 空壳）与 `chain/theaudiodb.py`（只有常量）直接消失。
- **消息状态机独立**：ChainBase.__init__ 里的 MessageHelper / MessageQueueManager 装配
  移到 `services/messaging` 的会话服务中；`send_callback=multicast` 的回调注入改为
  显式构造参数，消除运行态双向持有。
- **命名共振清除**：合并后同一业务域只允许一个模块名。
  `storage`（编排）与 `storage`（配置）合并为 `services/storage/`；
  notification、site、download 同理。`application/site/`（外部二进制落地点）改用
  非共振名（如 `services/sites_pack/`），并保留其"无 Python 实现"的特殊性说明。
- **scheduler.py / command.py 收编**：调度器基础设施（APScheduler 封装、job 生命周期）
  归 platform；**20 个内建 job 的定义权归还各 services/extension**
  （以声明式注册取代 `self._jobs = {...}` 大字典）；`SchedulerChain`、`CommandChain` 随 ChainBase 拆解消失。
  `cli.py` 归 edge 并按子命令拆分。

### D3　统一扩展模型：`_ModuleBase` 与 `_PluginBase` 合并

单一 `Extension` 契约（kernel/contracts）：

```
Extension =
  identity        (id, 版本, 发行方式: builtin | market)
  manifest        (capability.toml：type/subtype 为自由字符串元数据，不再是枚举)
  lifecycle       (init / start / stop / test / config-watch)
  capabilities    (反射推导的方法名集合 —— 唯一分发依据，现有实现保留)
  hooks           (get_api / get_service / get_actions / get_agent_tools / …
                   —— 现 Plugin 的 12 hook 全数保留，Host Module 同权获得)
```

- **枚举退场**：`ModuleType` / 6 个 subtype 枚举 / `StorageSchema` / `SiteSchema`
  从"分发依据"降级为"展示元数据"（三级分发架构已确认能力索引键是方法名，
  枚举本来就只剩 UI 用途）。新增一个存储后端/站点解析器/消息渠道不再动 `schemas/types.py`。
- **二级扩展上浮为一级**：storages（7）、indexer parser（20）、indexer spider（8）
  改用统一 manifest 声明，由 ExtensionHost 发现。Spider 的 8 分支 if/elif ×2 + 静态字典
  收敛为一次注册表查找（同一知识四处表达 → 一处）。
- **能力申明单一来源**：分发依据 = 反射推导（保留）；元数据 = manifest（保留）；
  **类上的 `get_type()/get_subtype()` 删除**（与 manifest 重复的第三重表达）。
- 配置化服务的 `_FAMILY_CAPABILITIES` 5 项静态表改为 manifest 里的
  `family` 声明，新增服务族不再改 3 处内核静态表。

### D4　agent 摘出为（预装）扩展

agent 的控制面（runtime_loader + capabilities adapter + application/agent 门面 + 惰性物化）
已经达标，照搬进统一 ExtensionHost 即可。真正要还的债在数据面与工具面：

1. **表自持**：`app/db/models/agentchat|agenttask|agenttaskrun.py` + 对应 Oper 迁入 agent 包，
   走 `app/db/plugin/`（插件自管理表）同款机制——该机制正是为此类场景建的。
2. **schema 自持**：`app/schemas/agent.py`（315 行）迁入 agent；
   宿主侧（`chain/_transfer.py`、`chain/search.py`）反向消费的 `ReplyMode` 等
   改为经门面导出的契约类型。
3. **工具面走门面**：24 个工具文件直捅 16 种 Chain、32 个文件直捅 11 种 Oper，
   收敛为 agent 内部的一个 `HostGateway`（薄门面，逐能力列名），
   `tools/base.py` 与 `callback/__init__.py` 不再继承/引用 ChainBase。
4. **入向补门面**：端点实际绕过门面直取的 7 类符号
   （agent_mcp_manager / moviepilot_tool_manager / StreamingHandler / LLMProviderManager /
   server_tools / build_display_message / ReplyMode）纳入 `application/agent.py`（未来 SDK）导出。
5. **82 个内建工具的静态元组**改为目录扫描发现（与插件工具同机制），
   `endpoints/agent.py`（2,315 行）的 web-agent 会话/文件登记/ffmpeg 转码下沉为 agent 扩展内的服务。
6. `scheduler.py` 里的 `agent_heartbeat` / `execute_scheduled_task` 专属任务，
   随 D2 的"job 定义权归还"回到 agent 扩展声明。

workflow / monitor / doctor / servarr / servcookie 按同一模板处理（doctor 依赖面极窄，
是最好的首个试点；servarr 是纯协议适配器，天然是扩展）。

### D5　SDK/compat 定调：承认事实，反转生成方向

现状是"官方门无人走（0%）、事实门无承诺（76% compat + 17% 直捅）"。方案不是把插件赶进 sdk，
而是**把事实面收编为受管 API**：

1. **SDK = 由 manifest 生成的投影**。compat manifest 已经维护了 148 条
   "旧名 → canonical + 推荐替换"映射，把它升级为唯一事实源：
   `app/sdk/*` 的 re-export 从手工维护改为**由 manifest 生成/校验**
   （50+ 条 `replacement` 字段推荐 sdk 而 target 绕过 sdk 的自相矛盾随之消除）。
2. **把第三条通路合法化或给出替代**：插件直捅的 8 个 Chain 类 → SDK 提供对应服务门面；
   eventmanager / EventType → SDK events（已有，收编旧路径热点 `app.core.event`）；
   Oper 热点（SystemConfig/PluginData/TransferHistory/Site…）→ SDK data 模块列名导出；
   `app.modules` 内部与私有锁/私有方法 → 明确宣布为非 API，
   为 p115strmhelper 的三个 patch 场景提供官方扩展点
   （整理管线拦截事件已有 `ChainEventType.TransferIntercept` 族，补齐缺口后 patch 可退役）。
3. **`sdk/_legacy/user.py` 的 sdk→api 向上依赖**：认证依赖（get_current_*）的 canonical 位置
   从 `api/deps` 下沉到 services/security，api 与 _legacy 同时从那里取——向上依赖消除。
4. **compat 永不删除但停止生长**：旧路径面冻结为 v2 插件兼容层，归 edge；
   新符号一律只进 SDK。`_PluginBase` 自身改走 canonical/SDK，
   让"零代码插件"不再吃进 compat 路径。

### D6　api 减脂

- 端点回归"解析请求 → 调 services → 包装响应"。16 处直接 ORM、20 处 `Scheduler()`、
  12 处直发事件、workflow 端点内的手写事务，全部下沉 services。
- `endpoints/plugin.py` 的 27 处 `PluginManager()` 收敛为 ExtensionHost 的管理服务。
- 35 项 `API_V1_ROUTER_SPECS` 静态元组保留（组合根装配硬编码可接受），
  但扩展路由继续走 `get_api()` 动态注册，两者由同一注册器汇合。

### D7　治理重写：一条主断言 + 白名单

- 门禁主体换成 **3.2 的允许依赖矩阵**（包级 DAG 断言，一条测试覆盖今天约 15 条特判）。
- 现有 4 对包级循环与 modules→application 反向边，先进**显式豁免清单**
  （带 issue 链接与清偿计划），清一条删一条——把"混乱"从暗处的默许变成明处的负债表。
- 墓碑清单在目录重组完成后一次性重写（旧墓碑随旧目录失义）；幽灵目录立即删除。
- 点状特判只保留无法用矩阵表达的行为约束（如 foundation 禁 print、log 叶子）。

---

## 五、迁移路径（每阶段独立可合、始终保持绿）

| 阶段 | 内容 | 完成判据 |
|---|---|---|
| **P0 清障**（半天） | 删 `app/service`、`app/managers` 幽灵目录；修 5 条具体违规边（`schemas→runtime` 的 LocaleHelper 注入化、`application/messaging/skill.py→agent` 走注册表、`sdk/_legacy/user.py` 认证符号下沉、`chain/workflow.py` 与 workflow 的归并方向裁定、githubsso 死导入清理） | 包级循环 4→0；豁免清单建立 |
| **P1 门禁换轨**（1 PR） | 写入允许依赖矩阵断言 + 豁免清单（modules→application 29 文件全部入豁免） | 新门禁绿；特判测试删除 ~15 条 |
| **P2 runtime 解体**（2-3 PR） | extensions→kernel/ExtensionHost（DB 依赖端口化）；机制文件→platform；compat/deprecation→edge；CapabilityRuntime 三实例合一 | `runtime` 目录消失；kernel 无 db/adapters import |
| **P3 编排合并**（3-4 PR） | 分发原语脱离继承；零分发 chain 文件降为普通服务；命名共振清除；scheduler/command 收编、job 定义权归还 | ChainBase 拆除；编排面 4→1 |
| **P4 modules 反向边清偿**（1-2 PR） | 被模块消费的 7 个 Helper 下沉 domain/platform 或经 SDK 门面 | 豁免清单 modules 段清零 |
| **P5 扩展统一**（3-4 PR） | Extension 契约合并 _ModuleBase/_PluginBase；枚举降级为元数据；二级扩展（storages/parser/spider）上浮；agent 内建工具目录化 | "新增扩展不动内核"覆盖 11/11 套机制 |
| **P6 agent/workflow/doctor 扩展化**（各 1-2 PR） | 按 D4 模板逐个摘出（doctor 先行试点） | agent 表/schema 自持；宿主入向仅剩 SDK 门面 |
| **P7 SDK 定调**（1-2 PR） | manifest 生成 sdk；直捅面合法化清单；compat 冻结公告 | 插件 API 通路 4→2（SDK + 冻结 compat） |

依赖关系：P1 依赖 P0；P3 依赖 P2；P5 依赖 P2；P6 依赖 P3+P5；其余可并行。
每阶段结束跑全量测试基线（当前基线 0 failed）+ 新门禁。

---

## 六、边界与不做的事

- **不追求树外插件化**：modules 仍在树内随宿主发版（"预装扩展"），
  微内核化的判据是**机制统一与依赖方向**，不是物理仓库拆分。
- **不动 `application/site/` 的外部二进制模式**：SitesHelper 的动态拉取是刻意设计，仅改名去共振。
- **compat 不删除**：76% 的生态事实不可能靠公告迁移；冻结即胜利。
- **能力推导不下探 service 实例类**（既有裁定，避免假阳性），统一 Extension 后依旧成立。
- **测试面锁定**：87 个测试直捅 `app.agent` 私有符号，P6 阶段需同步搬迁——
  这是 agent 扩展化实际工作量的最大头，估算时不可漏。

---

## 附录 A　扩展机制判据留档

11 套机制的核心文件坐标：`runtime/capabilities/registry.py:167`（toml 扫描）、
`runtime/extensions/host_module_adapter.py:34-140`（枚举校验与包/manifest 1:1 强校验）、
`runtime/extensions/module_manager.py:188-235,581-654`（能力索引与插件模块注入）、
`runtime/extensions/plugin_manager/_loader.py:24-106`（目录扫描 + DB 安装清单双闸）、
`runtime/extensions/service_registry.py:29-35`（`_FAMILY_CAPABILITIES` 静态表）、
`runtime/extensions/managed_resource_adapter.py:173-194`（独立 Registry）、
`agent/capabilities/adapter.py:196-206`（第 3 个 Registry）、
`agent/tools/factory.py:1-187,246-327`（82 项静态元组 + 插件工具合并）、
`workflow/__init__.py:35-58,146`（Action 扫描）、
`modules/filemanager/__init__.py:38-41,111-123`（Storage 扫描与即用即建）、
`modules/indexer/__init__.py:12-35,270-322,630-645`（Spider 四处表达 / Parser 枚举）、
`api/router_specs.py:1-48`、`command.py:56-142`、`scheduler.py:416-560`、
`doctor/checks.py:130-144`、`runtime/events.py:144-156,890-925`、
`schemas/notification.py:83`（渠道能力静态表）、`application/rules.py`（内建规则表）。

## 附录 B　插件 API 面统计留档

318 条 import 四分类统计口径：AST 扫描 4 个内置插件全部 `app.*` 顶层 import。
核心文件坐标：`runtime/compat/manifest.py`（112 MODULE_ALIASES + 1 PACKAGE_ALIAS +
3 VIRTUAL_PACKAGES + 10 PACKAGE_EXPORTS + 26 SYMBOL_ALIASES ≈ 148 条）、
`runtime/compat/imports.py`（meta path finder，4 种 Loader，`app/__init__.py:18` 安装）、
`sdk/_legacy/*`（行为兼容分支：旧签名子类覆写）、
`plugins/p115strmhelper/patch/*`（826 行：TransferChain 私有方法 / U115Pan 5 方法 / 跨插件 P115Api）。
旧路径热点 Top5：`app.log` 87、`app.core.config` 47、`app.utils.string` 27、
`app.utils.http` 20、`app.core.event` 7。
