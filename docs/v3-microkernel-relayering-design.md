# v3 微内核重新分层设计

**日期**：2026-08-17
**基线**：`feat/plugin-multi-instance` @ `421b64c72`
**唯一硬约束**：import 只能向下，同层不得成环。除此之外不设结构限制。

本文替换 `docs/rules/05-architecture.md` 中除单向依赖之外的全部分层规定。
`docs/backend-module-refactor-compatibility.md` 记录的是上一轮重构，
本文收窄的 compat 层正是那一轮的产物。

## 1. 现状：四层地层叠压

本节结论全部来自对 `421b64c72` 的实测。

`app/` 下 22 个一级条目，按 Python 代码量：

| 包 | 文件 | 行数 | 包 | 文件 | 行数 |
|---|---:|---:|---|---:|---:|
| modules | 146 | 68512 | domain | 21 | 7654 |
| plugins | 194 | 47379 | schemas | 39 | 7329 |
| agent | 140 | 40441 | monitor | 8 | 2518 |
| chain | 36 | 30275 | workflow | 17 | 2086 |
| api | 42 | 16477 | foundation | 12 | 1394 |
| runtime | 50 | 15220 | doctor | 5 | 1337 |
| application | 39 | 14167 | startup | 15 | 990 |
| adapters | 27 | 12098 | sdk | 17 | 660 |
| db | 55 | 8793 | testing | 4 | 400 |

`app/service/` 与 `app/managers/` 源码已清空，仅余 42 / 19 个 `.pyc`。
`app/locales/` 是 3 个 i18n JSON，与代码包并列。

### 1.1 地层 1 — v2 单体（被虚拟化，仍在运行）

`app.core`、`app.utils`、`app.log`、`app.helper` 在磁盘上不存在。它们由
`app/runtime/compat/manifest.py`（831 行、139 条别名）与 `imports.py` 的
`LegacyImportFinder`（`MetaPathFinder`）在 import 时动态合成。

别名按前缀分布：`app.helper` 43、`app.utils` 28、`app.core` 21、`app.db` 17、
`app.schemas` 4、`app.chain` 3、`app.domain` 2、`app.application` 2、
`app.log` 1、`app.agent` 1。

194 个插件文件产生 237 次此类 import。插件生态的真实契约面等于 v2 的全量内部结构。

### 1.2 地层 2 — DDD 重构（未封口）

`foundation` → `domain`/`schemas` → `adapters` → `application` 的层序意图清晰，
`foundation` 实测零 `app.*` 出边，是唯一的真 leaf。但被 5 条双向边击穿（见 1.5）。

### 1.3 地层 3 — 微内核骨架（建成，零使用）

`app/runtime/extensions/` 共 4776 行，含 `contract.py`、`capability.py`、
`service_registry.py`、`module_manager.py`(709)、`plugin_manager/`(1800+)。

配套的 `app/sdk/`（17 文件 660 行）在生产代码中 import 次数为 **0**，仅测试引用。

### 1.4 地层 4 — 原生编排（未动）

`chain` 与 `application` 存在 7 个同名文件：`agent.py`、`mediaserver.py`、
`notification.py`、`storage.py`、`subscribe.py`、`transfer.py`、`__init__.py`。

`modules` 下 38 个内建集成以 `_ModuleBase` 为契约（17 个实现），
`plugins` 以 `_PluginBase`（41 个成员）为契约，两者各有独立加载器。

### 1.5 硬约束的 5 处实测违规

```
adapters ↔ runtime    (30/5)
db       ↔ runtime    (9/16)
runtime  ↔ schemas    (18/2)
agent    ↔ application(25/1)
chain    ↔ workflow   (1/14)
```

3 条穿过 `runtime`。根因是 `runtime` 同时承担三种互不相容的职责：
微内核本体（`extensions/`、`capabilities/`）、进程级基础设施（`config`、`log`、
`cache`、`state`、`scheduling`）、纯函数工具（`coalesce`、`debounce`、`rate`、
`thread`、`execution`、`gc`）。人人必须 import `runtime`（modules 189 次、
agent 151 次、chain 68 次、api 52 次、application 40 次），它成为新的 God Package。

`app/application/agent.py:9` 写有「本模块禁止静态或函数内导入 app.agent，
否则会重新形成跨层循环依赖」，而同包的 `app/application/messaging/skill.py:8`
正在 `from app.agent.skills.registry import SkillHelper, SkillInfo`。
约束靠注释守护而无静态检查，是这 5 条边得以存在的直接原因。

### 1.6 「两套产物」的四个坐标

| # | 重复项 | A 套 | B 套 |
|---|---|---|---|
| 1 | 扩展契约 | `_ModuleBase` + `module_manager` | `_PluginBase` + `plugin_manager` |
| 2 | 内核依赖面 | `app/sdk`（0 使用者） | 139 条幻影别名（237 次使用） |
| 3 | 编排内核 | `chain` 30k | `application` 14k |
| 4 | runtime 身份 | 微内核本体 | 工具箱 + 基础设施 |

## 2. 已确认的决定

1. **modules 统一到 `_PluginBase`，随包发行。** 删除 `_ModuleBase` 与
   `module_manager`，38 个内建集成成为预装扩展，与第三方插件共用契约、加载器、
   能力注册路径。内核不再认识 `emby`/`plex` 这类名字。
2. **`sdk` 为目标契约，`compat` 设废弃期限。** 补齐 `sdk` 至覆盖插件所需，
   `compat` 标记 deprecated 并设版本期限。
3. **`application` 留，`chain` 逐步并入。**

## 3. 关键发现：收敛成本低于预期

三处曾被认为是阻断性的依赖，实测均可由「把放错层的纯函数下沉」解决，
不需要引入抽象接口或依赖注入。

**其一：两条最粗的双向边内容单一。**

```
adapters -> runtime : log 12, config 11, cache 3, reload 2, managed_resources 2
db       -> runtime : log 5,  config 4
```

二者从不依赖 `extensions`。而 `runtime -> adapters` 的 5 次全部是
`adapters/system/host.py` 的 `SystemUtils`，用途仅为 `is_docker()`、
`is_frozen()`、`get_env_path()`、`cpu_arch()`、`copy()`。
`adapters/system/host.py` 自身零 `app.*` 依赖——它本就是纯的，只是放错了层。
把 `SystemUtils` 下沉到 `foundation` 后，这两条边同时消失。

**其二：`runtime ↔ schemas` 的反向边是 `LocaleHelper`。**
`schemas/response.py` 与 `schemas/dashboard.py` import `runtime.localization`，
而 `runtime/localization.py` 零 `app.*` 依赖，下沉到 L0 即可。

**其三：`runtime/events.py:15` 反向 import 内核 `extensions/plugin_instance`。**
仅需 `instance_key`、`plugin_id_of`、`split_instance_key` 三个纯字符串函数，
下沉到 L0 后，事件总线不再反向依赖内核。

**其四：插件 ABI 高度集中。**

```
app.log          87    app.core.event      8    app.helper.directory 4
app.core.config  48    app.core.metainfo   7    app.core.cache       4
app.utils.string 27    app.core.context    6    其余均为个位数
app.utils.http   20    app.core.meta       5
```

前 4 项占 182/237 = **77%**。`sdk` 只需将 `logger`、`settings`、`StringUtils`、
`RequestUtils` 做成一等公民，即覆盖四分之三的使用面。139 条别名中绝大多数
可直接收窄或删除。

## 4. 目标分层

唯一硬约束：**import 只能向下，同层不得成环。**

```
L7  host        组装与入口
                main.py  cli.py  factory.py  command.py  scheduler.py
                startup/  api/  doctor/  testing/

L6  extensions  一切扩展（互不 import，只经 L5/L4 通信）
                plugins/      第三方与 38 个内建集成，统一 _PluginBase
                application/  编排（chain 并入）
                agent/  workflow/  monitor/

L5  sdk         扩展稳定契约 — L6 唯一允许 import 的内核面
                sdk/

═══════════ 内核边界：L6 不得越过 L5 直接 import 以下任何一层 ═══════════

L4  kernel      微内核
                contract  capability  service_registry  registry  loader
                events（事件总线）  reload  state

L3  platform    基础设施
                db/  adapters/  scheduling  progress  managed_resources
                gc  deprecation  compat/

L2  config      config.py（依赖 schemas.MediaType，故位于 L1 之上）

L1  contracts   schemas/  domain/

L0  foundation  纯函数，零 app.* 依赖
                foundation/ 现有 12 个模块
                + log  cache  localization      （实测零 app.* 依赖）
                + rate  execution  debounce  coalesce  thread
                + SystemUtils                   （从 adapters/system/host 下沉）
                + instance_key 等 3 个键函数    （从 extensions/plugin_instance 下沉）
```

### 4.1 分层判据

- **L0 的判据可机检**：`grep -E "^from app\.|^import app\."` 结果为空，
  或仅命中 `app.foundation`。
- **L4/L5 之间是内核边界。** L6 的扩展只能 import `app.sdk`。这条由 CI 静态检查
  强制，不靠注释约定——1.5 节已经证明注释守不住。
- **L6 内部互不 import。** `plugins` 不 import `application`，`application` 不
  import `plugins`。二者的通信全部经 L4 的能力注册表与事件总线：application
  注册 handler 并通过能力表分发到扩展，扩展注册 provider 并向能力表发起请求。
  这是 `chain -> application`(49)、`api -> chain`(47)、`agent -> chain`(33)
  这批静态 import 的最终去向。
- **编排本身也是扩展。** `application` 与 `plugins` 在同一层，区别只是随包发行、
  优先级高。这是「一切皆扩展」在结构上唯一自洽的形态：若编排位于扩展之上，
  内核就必须认识编排，内核便无法最小化。

### 4.2 compat 是内核边界上的旁路

`compat` 注册在 `sys.meta_path` 上，是 import hook 而非被 import 的库。
插件写 `from app.core.config import settings`，hook 将其解析到 L2 的 `config`。
因此真实依赖边是 L6 → L2，**完全绕过 L5**。139 条别名各自指向 L0–L4 的不同位置，
等于在内核边界上开了 139 个洞。

这决定了两件事：

1. `compat` 在 4.3 表中列于 L3，指的是它自身代码的依赖位置，不代表它约束了谁。
   作为旁路，它不受层序保护。
2. 阶段 4 的 CI 静态检查必须把幻影名（`app.core.*`、`app.utils.*`、`app.log`、
   `app.helper.*`）一并计入 L6 的违规集，否则检查形同虚设——插件只要改用幻影名
   就能绕过任何针对真实包名的规则。

`compat` 条目数因此是内核边界完整度的直接度量：**归零之日，即 L5 成为唯一内核面之时。**

### 4.3 各包去向对照

| 现位置 | 去向 | 动作 |
|---|---|---|
| `foundation/` | L0 | 保持，接收下沉件 |
| `runtime/log.py` `cache.py` `localization.py` | L0 | 直接移动，零依赖 |
| `runtime/rate.py` `execution.py` `debounce.py` `coalesce.py` `thread.py` | L0 | 移动，`rate`/`execution` 需切断 `schemas` 依赖 |
| `adapters/system/host.py` 的 `SystemUtils` | L0 | 下沉 |
| `extensions/plugin_instance.py` 的 3 个键函数 | L0 | 下沉 |
| `schemas/` `domain/` | L1 | 保持，切断 `-> runtime.localization` |
| `runtime/config.py` | L2 | 移动 |
| `db/` `adapters/` | L3 | 保持 |
| `runtime/scheduling.py` `progress.py` `managed_resources.py` `gc.py` `deprecation/` | L3 | 移动 |
| `runtime/compat/` | L3 | 移动，标 deprecated |
| `runtime/extensions/` `runtime/capabilities/` | L4 | 提升为 `app/kernel/` |
| `runtime/events.py` `reload.py` `state.py` | L4 | 移动 |
| `sdk/` | L5 | 补齐至覆盖插件 ABI |
| `modules/` 38 个集成 | L6 | 并入 `plugins/`，改用 `_PluginBase` |
| `chain/` | L6 | 并入 `application/` |
| `application/` `agent/` `workflow/` `monitor/` | L6 | 保持 |
| `api/` `startup/` `doctor/` `testing/` | L7 | 保持 |
| `service/` `managers/` | 删除 | `.pyc` 墓碑 |
| `locales/` | 资源目录 | 移出代码包一级 |

## 5. 实施次序

每一阶段结束时 import 图必须无环，测试基线保持 0 failed。

**阶段 1 — 立住硬约束底座。** 消灭 5 条双向边。
下沉 `SystemUtils`、`localization`、3 个键函数；把 `log`/`cache` 移入 L0；
切断 `application/messaging/skill.py -> app.agent`；切断
`chain/workflow.py -> app.workflow`。同步加入 CI 静态依赖检查。
出口判据：包级依赖图零双向边，且该性质由 CI 守住。

**阶段 2 — 拆 runtime。** 按 4.3 把 `runtime` 的 17 个模块与 4 个子包
（`capabilities`/`compat`/`deprecation`/`extensions`）分派到 L0/L2/L3/L4，
`runtime/extensions` 提升为 `app/kernel/`。`runtime` 包消失。
出口判据：不存在名为 `runtime` 的包；`kernel` 不 import L5 以上任何内容。

**阶段 3 — 统一扩展契约。** `_ModuleBase` 并入 `_PluginBase`，
`module_manager` 并入 `plugin_manager`，38 个内建集成迁入 `plugins/`。
出口判据：内核代码中不出现任何具体集成名。

**阶段 4 — 立起 sdk，收窄 compat。** `sdk` 补齐 `logger`/`settings`/
`StringUtils`/`RequestUtils` 四项一等公民（覆盖 77%），再按实际使用面补足余量；
`compat` 的 139 条按插件真实引用收窄，标 deprecated 并公布版本期限。
出口判据：L6 的 import 静态检查只允许 `app.sdk`；`compat` 条目数单调下降。

**阶段 5 — 编排并轨。** `chain` 的 7 个同名文件与 `application` 合并，
`api`/`agent`/`workflow` 对 `chain` 的静态 import 改经 L4 能力表。
出口判据：`chain` 包消失；L6 内部零互相 import。

## 6. 风险

- **阶段 3 与阶段 5 会改变插件可见行为。** 38 个内建集成改契约后，依赖
  `app.modules.*` 的第三方插件会断。compat 需为此补别名，与阶段 4 的收窄方向相反。
  须明确区分「新增以偿还阶段 3」与「存量待删」两类条目，否则 compat 会重新膨胀。
- **阶段 5 是最大一块。** `chain` 30k 行，`api -> chain` 47 次、
  `agent -> chain` 33 次。可按 7 个同名文件逐个并轨，不必整包一次搬。
- **L6 内部零互相 import 是终局判据，不是阶段 1 判据。** 在能力表与事件总线
  承载全部跨扩展调用前，`application <-> plugins` 的临时直连需登记豁免清单并逐条消。
- **阶段 2 触及整个 `runtime` 包，而全库对它有约 645 次引用。**
  分派本身是机械搬运，但引用面广，宜按 L0 → L2 → L3 → L4 的顺序分批推进，
  每批独立可回滚。
