# v3-lite 设计

- 日期：2026-08-26
- 基线：`refactor/v3-pure` @ `f31300f64`
- 状态：P0、P1、P2 已完成；P3 样板验证（`discord`）已完成，核心假设验证为**部分成立**（缺口清单见 §4.5）；其余章节待评审

## 1. 目标

从 `refactor/v3-pure` 切出 `v3-lite` 并以之为新主线，达成三件事：

1. **功能减负**：把内置但实际使用面窄的扩展全部转为插件交付。
2. **运行时减负**：在不损失现有功能的前提下降低常驻内存与 CPU 占用。
3. **双版本发行**：对齐官方 v3，产出 Python 3.14 与 3.14t（free-threaded）两个镜像。

发行模型为**单套代码**：`v3-pure` 最终收敛到 `v3-lite`，不维护 full/lite 双轨。被移出内核的功能以官方插件形式交付，用户按需安装即可恢复完整体验。

## 2. 事实基线

以下数字均为 `f31300f64` 上的实测值，不是估算。

### 2.1 代码规模

| 范围 | 行数 |
| --- | --- |
| `app/` 合计 | 288,764 |
| `app/modules/`（47 个模块目录） | 69,018 |
| `app/agent/` | 41,452 |
| `app/workflow/` | 3,217 |

`app/agent/` 内部构成：`tools/` 19,177、`llm/` 6,468、`middleware/` 5,494、`policy/` 1,869、`skills/` 1,313，其余合计约 1,841。

### 2.2 依赖规模

- 直接运行时依赖 **95** 个；`venv` 实测 **921 MB**。
- 与上游 v3 的直接依赖差异仅 5 个包（`bcrypt`、`jieba-next`、`lxml`、`psycopg2-binary`、`zhconv-rs`），其中 4 个正是上游放进 `runtime-standard` 分组的那批。**依赖臃肿来自上游本身，不是本 fork 引入的。**

### 2.3 上游 v3 的 Python 现状

- `requires-python = ">=3.14"`（本 fork 原为 `>=3.12`，已于 P0 对齐，见 §7.4）。
- `.github/workflows/build-v3.yml` 与 `beta.yml` 已有完整的 free-threaded 双镜像流水线（amd64 + arm64，构建参数 `MOVIEPILOT_PYTHON_VARIANT=free-threaded`）。
- 依赖按 ABI 分成两组：

```toml
runtime-standard = ["Brotli==1.2.0", "bcrypt~=4.3.0", "lxml~=6.1.2",
                    "psycopg2-binary~=2.9.12", "zhconv-rs~=0.4.1"]
runtime-free-threaded = ["Brotli==1.2.0", "bcrypt~=5.0.0", "lxml==7.0.0b1",
                         "psycopg[c]==3.3.4"]
```

注意 `zhconv-rs` 在 free-threaded 组里被整个去掉——上游的 3.14t 镜像是**缺繁简转换**的。

### 2.4 已具备的架构支点

- **46 个内建模块各自带一份 `capability.toml`**，声明 `entrypoint` / `depends_on` / `service_capability` / `subtype` / `priority` / `multi_instance` / `activation.policy` / `activation.selector`。内建模块在形式上已经是预装扩展。（47 个目录中只有 `_base` 没有清单——它是下载器/媒体服务器/消息/存储四个抽象基类所在处，不是可发现模块。）
- 模块发现入口为 `CapabilityRegistry.discover((_MODULE_ROOT,), kinds={HOST_MODULE_KIND}, ...)`，**参数本就是根路径元组**，多根发现在 API 层面已支持。
- 插件扩展架构已定型十二族声明式注册（`docs/plugin-extension-architecture.md`），其中 `provides_modules`、`provides_service_instances`、`provides_channel_capabilities` 三族与本设计直接相关。
- 服务族是登记表（`service_family_registry`）而非硬编码枚举。

### 2.5 反向依赖面

**代码层**（对 `app/agent` / `app/workflow` 包的直接 import）：

| 子系统 | 被反向依赖的文件数 | 具体位置 |
| --- | --- | --- |
| `app/agent` | 10 | `startup/agent_initializer.py`、`startup/modules_initializer.py`、`api/endpoints/{agent,openai,llm,history,system,mcp}.py`、`api/service_secrets.py`、`sdk/agent.py` |
| `app/workflow` | 5 | `startup/{workflow,modules,hostport}_initializer.py`、`scheduler/workflows.py`、`api/endpoints/workflow.py` |

**数据与服务层**（对 agent/workflow 的模型、oper、服务类的引用）：散落在 `app/agent` 与 `app/workflow` 目录**之外**，共 **20 个文件**，关键位置：

| 位置 | 引用内容 |
| --- | --- |
| `app/application/messaging/chat.py` | `AgentChatService`、`AsyncAgentChatRepository`、`AsyncUnitOfWork` |
| `app/application/workflow_transactional.py` | 直接 `from app.db.oper.workflow import WorkflowOper` |
| `app/application/agentdata.py` | agent 数据端口 |
| `app/api/deps.py` | `WorkflowDefinitionCommand`、`WorkflowMutationCommand`、`WorkflowQueryService`、`AgentChatService`、`AgentChatRepository`、`AgentChatUnitOfWork` 的依赖注入 |
| `app/api/context.py`、`app/api/host_runtime.py` | `AgentChatRuntime` 是宿主运行时组成部分 |
| `app/scheduler/agent_tasks.py`、`app/scheduler/composition.py` | 调度接线 |
| `app/schemas/exports.py`、`app/runtime/compat/manifest.py` | 导出与兼容登记 |

**agent/workflow 的「执行引擎」在自己的包里，但「数据 + 服务 + 依赖注入」长在内核的 application/api 层**，因此它们不是可整包摘走的叶子子系统；外挂必须连同这一层一起搬，否则会出现「服务在内核、实现在插件」的割裂，`WorkflowOper` 那类直连会直接断。

### 2.6 agent / workflow 的持久化

内核主库有 4 张属 agent/workflow 的表：`AgentChat`、`AgentTask`、`AgentTaskRun`（`app/db/models/agent*.py`）、`Workflow`（`app/db/models/workflow.py`），配套 3 个 oper（`app/db/oper/{agentchat,agenttask,workflow}.py`）。

这 4 张表在 `database/versions/` 有 **7 个迁移文件**，最早可追到 `2_1_2` 与 `2_1_8`——自 v2 时代就存在，存量用户库里有真实数据（聊天记录、工作流定义、任务运行历史）。

业务上这些表只被 agent/workflow 自己消费，语义上应随之外挂；工程上的前置条件见 §6.4。

### 2.7 已具备的惰性加载骨架

`tests/test_agent_api_lazy_imports.py` 是既有契约测试，锁定「完整路由与 OpenAPI 注册不得物化 Agent、工具或模型运行时」，配合 `AI_AGENT_ENABLE` 开关；`tests/test_agent_lazy_runtime_boundary.py` 用子进程探针检查 `sys.modules` 保持冷态。

**宿主侧「能力不在也能起」的骨架已经存在**，§6.2 的改造是在它之上收口，不是从零建。这是个好消息，降低了 P5 难度。

## 3. 范围裁决

### 3.1 内核保留（19 个模块，37,938 行）

基础设施 7 个：`indexer`、`_base`、`filter`、`subtitle`、`postgresql`、`redis`、`localstorage`。

主流接入商 12 个：

| 品类 | 保留 |
| --- | --- |
| 元数据 | `themoviedb`、`douban` |
| 媒体服务器 | `emby`、`plex`、`jellyfin` |
| 下载器 | `qbittorrent`、`transmission` |
| 消息 | `telegram`、`wechat`、`webpush` |
| 存储 | `u115`、`alist` |

判据是「开箱即用不需装插件」：中文用户最常见的组合必须在内核里。

### 3.2 外挂（28 个模块，31,080 行）

`wechatclawbot`(2629)、`feishu`(2528)、`ugreen`(2385)、`musicbrainz`(2123)、`discord`(2041)、`anilist`(1676)、`slack`(1624)、`trimemedia`(1613)、`zspace`(1541)、`imdb`(1321)、`qqbot`(1304)、`rtorrent`(1147)、`bangumi`(1076)、`alipan`(1033)、`thetvdb`(852)、`smb`(771)、`theaudiodb`(720)、`rclone`(677)、`vocechat`(661)、`fanart`(632)、`synologychat`(598)、`navidrome`(497)、`medialibrary`(493)、`acoustid`(399)、`listenbrainz`(311)、`dingtalk`(234)、`lrclib`(223)、`alistgo`(32)。

加上 `app/agent`(41,452) 与 `app/workflow`(3,217)，共移出 **75,749 行**，内核降至约 **213,015 行（−26%）**。

### 3.3 明确不动的部分

以下两项经评估后**留在内核**，本设计不碰：

- **中文识别 NLP 栈**（`jieba` 38 MB + `Pinyin2Hanzi` 36 MB + `cn2an` + `zhconv`）：长在 `app/foundation` 与 `app/domain/meta` 里，属核心识别能力，不是「没人用的功能」。
- **站点抓取浏览器栈**（`cloakbrowser` → 传递依赖 `playwright` 132 MB）：虽然 `app/` 下仅 `app/adapters/network` 一处引用，但属反爬基础能力。

### 3.4 体积收益

| 外挂域 | 随之移出的包 | 体积 |
| --- | --- | --- |
| agent | langchain 全家 49 + langgraph 7 + openai 20 + anthropic 10 + google-genai 9 + boto3/botocore/s3transfer 33 + numpy 58 | 186 MB |
| modules | `lark_oapi` 98 + `discord.py` 8 + `slack-bolt`/`slack-sdk` 6 + `smbprotocol`/`smbclient` 2 | 114 MB |
| **合计** | | **约 300 MB** |

`venv` 921 MB → 约 621 MB（−33%）。

两点已验证的细节：

- `numpy` 的引入者是 `langchain_aws` / `langchain_community` / `openai`，**全在 agent 域**。`dateparser` 虽在元数据里列了 `numpy`，但限定于 `extra == "fasttext"`，本项目未启用该 extra，因此 numpy 会随 agent 一起消失。
- `websocket-client` 被保留模块 `wechat/wechatbot.py` 使用，**不随 `qqbot` 移出**。
- `oss2` 属保留模块 `u115`，留在内核。

## 4. 外挂机制

### 4.1 裁决：复用现有族，不新增第十三族

每个外挂模块打成 `_PluginBase` 插件，用现有族的组合承载原 `capability.toml` 语义：

| `capability.toml` 字段 | 承载体 |
| --- | --- |
| `entrypoint` | **不由** `ModuleDeclaration.impl` 承载——`module_declaration_violation`（`app/runtime/extensions/admission/module.py:45-67`）只校验 `methods` 与 `priority`，`impl` 对模块声明不被消费；entrypoint 实际由插件发现路径的目录名约定承担：目录名 = 类名小写（`app/runtime/extensions/plugin_manager.py:1181-1184`） |
| 方法表 | `ModuleDeclaration.methods` 能承载，但语义不同：宿主模块的方法表由反射自动推导（`app/runtime/extensions/contract/extension.py:76-86`，`is_implemented_callable` 会滤掉空实现），插件必须逐个手写方法名——discord 有 12 个可分发方法要手抄，原模块新增方法时插件的表会静默漂移（缺口 G8，见 §4.5） |
| `service_capability` + `subtype` | `ServiceInstanceDeclaration.capability` + 类型标识；但 `subtype` 在宿主侧无运行期消费者——`host_module_adapter.py:324-330` 只在清单校验里要求通知模块声明它，真实渠道标识走模块实例的 `get_subtype()` / `self._channel` |
| `multi_instance` | `ServiceInstanceDeclaration.multi_instance` |
| 渠道能力 | `provides_channel_capabilities` |
| `depends_on` | 插件自身的依赖声明 |
| `priority` | `ModuleDeclaration.priority`（字段已补；但插件源本身不读取该值排序，跨源仲裁仍缺失，见 §4.4、§4.5 G1） |
| `activation.policy` / `activation.selector` | 部分由服务实例配置存在性覆盖——实例生死等价，方法表闸门不等价（**已验证、部分成立**，见 §4.5 G2） |

一个内建模块 ≈ `ModuleDeclaration`（方法表）+ `ServiceInstanceDeclaration`（可配置类型）的组合。两族的职责分工在 `ModuleDeclaration` 的文档里已经写明——「本声明只描述方法表，按用户配置扇出多个具名服务实例是另一回事」——正好对应模块的两个面。

**不新增 `provides_host_modules` 族**的理由：新族与这两族职责重叠，违背「族存在的理由是取用形状不同，不是业务语义不同」的既定判据。

**不硬塞进单个 `provides_modules`** 的理由：`provides_modules` 是「无额外元数据需求的能力」的形态，而这些模块携带 `subtype` / `priority` / `multi_instance` / 激活选择器等元数据，硬塞会让该族退化成万能入口。

### 4.2 两处字段缺口的补法

**`priority`（分发顺序）**：`ModuleDeclaration` 已增加 `priority: int` 字段（提交 `627720379`），配套读取器 `declaration_module_priority()` 与注册期类型校验已就绪，声明层与投影层完整携带该值——字段本身已经落地，不再是待确认项。

但**宿主侧尚无消费方**：`PluginProviderSource._providers()` 遍历 `catalog.get_plugin_modules()`——由所有声明扁平化而成的 `{方法名: 可调用对象}` 字典，只按注册顺序遍历，从不读取 priority 值。也就是说，字段目前只保证语义在声明与投影层不丢失，真正待做的是**插件模块的排序机制设计**：谁读这个字段、在哪一层用它排序、如何与内建侧已有的排序方式协调。这块工作比字段本身更重，详见 §4.4。

**`activation.policy` / `activation.selector`**：不新增字段。P3 样板阶段（`discord`）已用真实分发链路实测验证，结论是**已验证、且被部分证伪**——activation 同时决定两件事，只有一半在插件侧有等价物：

1. **实例生死**——插件侧等价。`ServiceInstanceAdapter.get_instances()` 每次取用重读配置、按配置增删实例，效果与「配置存在性驱动」相符。
2. **方法表在不在分发目录里**——插件侧不等价。宿主侧唯一读 activation 的是 `host_module_adapter.py:391-412` 的 `should_run_host_module()`，由 `module_manager.py:150-184` 的 `_reconcile()` 驱动；而 `PluginExtension.capability_table()`（`projection/plugin.py:370-378`）的闸门是 `is_enabled()` → `plugin.get_state()`，即插件自己的启用开关，与 Notifications 里有没有 discord 配置无关。实测：一份 discord 配置都没有时，`PluginProjection.modules()` 里仍然有 `post_message` 提供者。

**且不能靠 `get_state()` 自绑配置存在性来补上这半差——会死锁**：`provided_service_instances()`（`projection/plugin.py:1798-1804`）在 `is_enabled()` 为假时整体跳过该实例，而 `/service/types/{capability}` 端点（`api/endpoints/service.py:254-296`）正是从这张表渲染「可新增哪些类型」的下拉框。链条是：没配置 → 插件不启用 → 类型不登记 → 用户看不到 discord 选项 → 永远配不出第一条配置。

绕法与代价见 §4.5 G2：接受语义放宽，插件启用即挂方法表，各方法内部按配置为空提前返回（discord 现有实现本就如此），代价是多一次空转调用。

综合两项：字段层面的缺口已经补齐（`priority` 落地、`activation` 判断已验证为部分成立），但**机制层面的缺口——插件模块的排序与跨源仲裁（G1）、以及 activation 方法表闸门的语义差（G2）——仍未解决**，且比字段缺口更重要：字段只负责携带数据，机制才决定分发结果。排序机制详见 §4.4，完整缺口清单见 §4.5。

### 4.3 插件外壳形态

以 `discord` 为例（示意，非最终代码）：

```python
class DiscordModulePlugin(_PluginBase):
    def provides_modules(self):
        return [ModuleDeclaration(impl=self._module, methods=self._module.get_methods(),
                                  priority=4)]

    def provides_service_instances(self):
        return [ServiceInstanceDeclaration(capability="notification",
                                           type="discord", multi_instance=True)]

    def provides_channel_capabilities(self):
        return [ChannelCapabilities(...)]
```

模块业务代码本身（`app/modules/discord/discord.py` 等）迁入插件包后基本不动，新增的是插件外壳与打包元数据。

### 4.4 外挂对分发顺序的影响

两个 provider 源的排序规则不同：宿主侧 `HostModuleExtension.priority` 读 `instance.get_priority()`，`ModuleManager._build_capability_index` 与 `HostModuleProviderSource.notify_providers` 均按其升序排序，priority 在这一侧真正被消费；插件侧 `PluginProviderSource._providers()` 遍历 `catalog.get_plugin_modules()`（声明扁平化后的 `{方法名: 可调用对象}` 字典），只按注册顺序遍历，不读取 priority。

跨源顺序还是硬编码的：`app/runtime/extensions/projection/dispatcher.py:92-93` 中 `PluginProviderSource` 永远排在 `HostModuleProviderSource` 之前，与任何 priority 值无关。

后果是模块外挂后从「priority 升序」整体跨到「注册顺序 + 插件源整体优先」这套完全不同的排序体系：按 §3.2 的裁决，28 个外挂模块会永远优先于仍留在内核的 19 个模块被调用，而外挂之前这 47 个模块本是按同一套 priority 统一排序的。`tests/test_plugin_provided_modules.py::test_plugin_priority_does_not_yet_govern_dispatch_order` 已用真实分发运行固化此事实：后注册、priority 数值更优（更小）的插件，在 `unicast()` 中仍输给先注册、priority 更差的插件。

**P3 样板阶段（discord）的实测数据**：`notification` 族三种分发方式都用——

- 多播：`post_message` / `post_medias_message` / `post_torrents_message`
- 单播：`send_direct_message` / `edit_message` / `delete_message` / `mark_message_processing_started` / `finalize_message` / `message_parser`
- 广播：`mark_message_processing_finished` / `register_commands`

真实优先级：telegram=0、wechat=1、feishu/wechatclawbot=2、slack=3、discord=4、vocechat=4、synologychat=5、webpush=6、qq=10、dingtalk=11。

用真实 `ModuleInvocationDispatcher` + 真实 `ModuleManager.providers_for` 实测对照：

| 场景 | 结果 |
| --- | --- |
| 基线：telegram(0) 与 discord(4) 都在内核，单播 `send_direct_message` | `telegram` |
| 外挂后：discord 变插件、telegram 留内核，同一单播 | **`discord`（结论翻转）** |
| 把 `ModuleDeclaration.priority` 压到 9999 再试 | 仍然 `discord`——声明优先级救不回来 |
| 基线多播 `post_message` | `["telegram", "discord"]` |
| 外挂后多播 | **`["discord", "telegram"]`** |

后果按分发方式分级：

- **多播**：改变的是发送次序，不是发送与否。可观察但不致错。
- **单播**：可致错。各渠道模块靠 `check_message()`（`app/modules/__init__.py:254-275`）自我让出，但让出条件是 `message.channel and message.channel != self._channel`——**`message.channel` 为空时全体都认领**。此时今天由 telegram 应答，外挂后改由 discord 应答。

在单播（只取一个结果）类分发下，这会直接改变现有行为——P3 样板阶段已用真实分发链路证实（缺口编号 G1，见 §4.5）。处置方向——插件源改按 priority 排序、统一两源到同一排序体系、还是保持插件优先并接受行为变化——仍是待定项，见 §12。

### 4.5 验证结论与缺口清单

**总体裁决**：部分成立。三族组合能承载清单里的**声明数据**，但承载不了清单的**运行语义**。`activation` 与 `priority` 两项在插件侧都没有等价消费者——字段能存住值，但宿主侧和插件侧都没有代码去读它们、做出与内建模块一致的行为。验证过程见 `tests/test_v3lite_discord_outsourcing.py` 与 `tests/test_v3lite_activation_semantics.py`（提交 `14700e57a`，共 18 例全绿）。

| 编号 | 缺口 | 性质 | 绕法 |
| --- | --- | --- | --- |
| G1 | 跨源顺序硬编码，插件永远优先于内建；`ModuleDeclaration.priority` 无消费者 | 阻塞性 | 无插件侧绕法，必须改宿主：`_answer_providers` / `_notify_providers` 把两源 provider 汇成按 priority 归并的单表，而非按源分段 |
| G2 | `activation.when_configured` 在插件侧无等价物；`get_state()` 自绑会与服务类型登记死锁 | 可绕过（有代价） | 接受语义放宽：插件启用即挂方法表，各方法内部按配置为空提前返回（discord 现有实现本就如此）。代价是多一次空转调用 |
| G3 | 内建静态渠道能力表遮蔽扩展登记 | 可绕过 | 删枚举 + 删静态表条目 + 装插件必须原子，无灰度过渡 |
| G4 | `interaction.py:672, 983` 对字符串渠道抛 `AttributeError` | 阻塞性（外挂即触发） | 归一后再取字段名；属既有缺陷，独立修复中 |
| G5 | 存量 `ServiceConfig.provider = "host:builtin"` 行在提供方消失时不被诊断 | 可绕过 | 迁移脚本回填 provider，或诊断端点覆盖该情形 |
| G6 | 渠道管理员解析与 `_MessageChannelModuleBase` 样板不在 SDK 导出面 | 可绕过（有代价） | 扩 SDK 导出，或每个渠道插件自带副本 |
| G7 | `.gitignore` 排除 `app/plugins/**`；前端内建类型清单需同步 | 可绕过 | 白名单 / 独立仓库二选一；前端改动跨仓协调 |
| G8 | 方法表从反射推导退化为手写清单 | 可绕过 | 加契约测试比对插件方法表与原模块公开方法集，防漂移 |

G1、G4 是阻塞性缺口：G1 不解决，单播场景外挂即改变今天的应答方；G4 不解决，任何扩展渠道消息触达 `interaction.py` 的守卫就会崩溃。其余六项有明确绕法，但都带代价或需要跨仓协调，不是零成本。

## 5. 渠道能力双轨的处理

### 5.1 冲突与消解

既有决策「渠道能力保持双轨、不把内建搬成新写法」的**前提是「内建渠道固定、随代码走」**。8 个 IM 渠道（`feishu`、`discord`、`slack`、`qqbot`、`wechatclawbot`、`vocechat`、`synologychat`、`dingtalk`）外挂后不再是内建，前提失效。

它们改走 `provides_channel_capabilities` **恰是双轨设计的原意**（扩展渠道自带能力声明），不是对该决策的违反。内核保留的 `telegram` / `wechat` / `webpush` 继续用 `app/schemas/notification.py:148` 的 `ChannelCapabilityManager._capabilities` 静态表，**该静态表保留、写法一行不动**。

**但静态表对扩展登记是遮蔽关系，不是并存关系**：`ChannelCapabilityManager.get_capabilities` 是内建优先——枚举成员且静态表有条目时直接返回内建值，插件登记的能力被整个压住（实测：插件登记 `max_message_length=4321` 被内建的 `1800` 遮蔽）。因此**「删枚举成员 + 删静态表条目 + 装插件」必须是同一次变更，不存在两者并存的过渡态**——这是对上一段「不是对该决策的违反」的补充约束而非推翻：双轨写法本身不用改，但迁移时点必须原子，不能先装插件再择期删枚举。

### 5.2 需要处理的迁移点

- 静态表让出上述 8 项，且须与枚举、内建条目的删除同一次变更完成（见 5.1）。
- `NotificationChannel` 枚举移除对应成员；扩展渠道以字符串标识存在。
- 存量用户配置里持久化的是渠道取值，归一路径已验证安全：`resolve_channel` / `channel_identity`（`app/schemas/notification.py:25-50`）命不中内建索引时原样交出字符串，不会 `AttributeError`；既有约定「不要用 `channel.value`，扩展渠道是字符串」在此处已经满足。`app/agent/tools/impl/add_subscribe.py:136-138` 用 `except ValueError` 优雅降级，同样已符合要求。
- **但 `app/application/orchestration/interaction.py:672` 与 `:983` 的 `channel.name.lower()` 守卫只有 `if channel`，非空字符串为真 → `AttributeError`。**这是既有缺陷（今天任何扩展渠道插件都会触发），外挂只是把它从潜在变成必然。该缺陷正由独立子任务修复中，不阻塞本设计但需跟踪完成（缺口 G4，见 §4.5）。
- 枚举移除不影响存量 Notifications 配置：枚举取值是 `"Discord"`（首字母大写），配置的 `type` 是 `"discord"`（小写），两者是不同的键。
- 但存量 `ServiceConfig.provider` 列为 `"host:builtin"`，外挂后归属实为插件；「提供方已消失」诊断端点（`api/endpoints/service.py:607-608`）对 `BUILTIN_PROVIDER` 的行直接 `continue`——**存量用户升级后不装插件，discord 静默失效且诊断不报**（缺口 G5，见 §4.5）。

## 6. agent / workflow 外挂

### 6.1 必须先解的硬结

`app/schemas/agent.py:6` 的 `from langchain_core.messages import BaseMessage` 是 langchain 类型泄漏进 schemas 层的唯一一处。schemas 属内核契约层，不能依赖将被移出的包。

**已解（原型阶段落地）**。解法不是在内核定义自有消息类型再做转换，而是把泄漏源整体移出：`BaseMessage` 的唯一用处是 `ConversationMemory.messages` 字段，而 `ConversationMemory` 的唯一使用者是 `app/agent/memory/` 的记忆管理器——它本就是 agent 专属模型，不该待在内核契约层。因此该模型连同其 langchain 依赖一并迁入 `app/agent/memory/`，内核 schemas 零损失，也不需要类型转换层。`app/schemas/exports.py` 由 `scripts/schema/exports.py --write` 重新生成，不手工编辑。

配套新增 `tests/test_v3lite_kernel_dependencies.py`，把「内核层不得 import 外挂第三方包」固化为护栏：`EXTERNALIZED_DISTRIBUTIONS` 列出随 agent 与冷门模块移出的 25 个第三方顶层包，`GUARDED_ROOTS` 列出已解耦、即刻受约束的内核目录（当前为 `schemas`），`PENDING_ROOTS` 记录尚未解耦目录及其清偿方向。后续每完成一个目录的解耦，就把它从后者移入前者——**不要放宽判定**。

### 6.2 宿主侧改造

10 个反向依赖 `app/agent` 的文件与 5 个反向依赖 `app/workflow` 的文件（去重共 14 个）改为「能力存在才注册」：

- `startup/agent_initializer.py`、`startup/workflow_initializer.py`：能力缺失时跳过初始化而非报错。
- `api/endpoints/{agent,openai,llm,history,system,mcp,workflow}.py`：路由按能力存在与否条件注册。
- `sdk/agent.py`：作为 SDK 契约保留，实现由插件提供。
- `api/service_secrets.py`、`scheduler/workflows.py`、`startup/hostport_initializer.py`：条件分支处理。

### 6.3 交付形态

agent 与 workflow 各作为一个插件交付，而非拆成多个。agent 内部 `tools/` 占 19,177 行，是其最大构成，但工具与 agent 内核耦合紧密，不在本设计里进一步拆分。

### 6.4 持久化外挂的两个前置条件

**前置一：插件自管理数据库框架在 `v3-pure` 上不存在。**

这套东西（`DbManager` 容器、`build_plugin_base()`、`_PluginBase.provides_models()` 钩子、PG per-schema 路由、Alembic 迁移骨架、ORM Mixin）是在**旧的 `v3-python` 分支**上做的。官方 v3 重新分层导致 fork 重新变基时，它随结构性重构一起作废了。已核实：`app/db/manager.py`、`app/db/plugin.py` 均不存在，`provides_models` 全仓零命中。当前分支上插件的持久化仍只有共享 KV 表 `PluginData`。

重建有完整的踩坑记录可复用（会话隔离导致静默丢数据、`reset_plugin` 路径 teardown 从不执行导致库泄漏、多 MetaData 静默漏建表、`merge` vs `add` 的脱管对象语义等），但这是一笔独立的、不小的前置工程，不是既有资产。且它对**所有**插件都有价值，不只 agent/workflow，因此更适合单独立项而非挂在 v3-lite 下面。

**前置二：顺序是反的。** 必须先把 application/api 层的 agent/workflow 服务与依赖注入移走，表才能跟着走；不能先移表。正确依赖链：

```
重建插件自管理 DB 框架（v3-python 成果，需重做）
  └─> 移 application/api 层的 agent/workflow 服务与依赖注入
        └─> 移 4 张表 + 3 个 oper
              └─> 存量数据搬迁 / 旧表兼容
```

存量数据处理二选一：一次性搬迁到插件库，或保留读旧表的兼容路径。此前设计完全未覆盖这一项。

## 7. Python 3.14 / 3.14t 双版本

### 7.1 步骤

1. `requires-python` 从 `>=3.12` 提到 `>=3.14`，对齐上游。
2. 采用上游的 `runtime-standard` / `runtime-free-threaded` 双 dependency-group 模式。
3. Docker 构建接受 `MOVIEPILOT_PYTHON_VARIANT` 参数，产出 `lite-3.14` 与 `lite-3.14t` 两个镜像。
4. CI 增加 free-threaded 变体的依赖审计与漏洞扫描（对齐上游 `build-v3.yml` 的做法）。

### 7.2 减负与 free-threading 的正向耦合

3.14t 的约束是 C 扩展必须有 free-threaded wheel。减负后本体依赖收窄约 300 MB，其中 `numpy`、`botocore` 等重型 C 扩展/大包全部移出内核，free-threaded 兼容面自然改善。**外挂插件是否支持 3.14t 由插件自身声明**，内核不为插件的 ABI 兼容性兜底。

### 7.3 已知取舍：3.14t 的中文能力降级比上游更重

上游在 free-threaded 组里放弃了 `zhconv-rs`（无 free-threaded wheel）。本 fork 还多一个上游没有的 `jieba-next`——经 PyPI 核实，它是 Rust 扩展、wheel 为版本特定 ABI（`cp39`–`cp314`），**所有已发布版本均无 `cp314t` wheel**。按 `zhconv-rs` 的同一处理范式，它只进 `runtime-standard`。

结果：**3.14t 变体同时缺中文分词与繁简转换**，而上游只缺后者。这两项都在 `app/foundation` 与 `app/domain/meta` 的识别路径上，降级会直接影响中文识别质量。

评审需决定：3.14t 变体是否接受这个比上游更重的降级；若不接受，可选方向是为这两个包寻找纯 Python 替代、或在 free-threaded 变体下改走降级路径而非缺失。

### 7.4 升级实测结果

P0 已完成（提交 `413aa09d1`、`c77a6bd39`、`11ddedab8`），实测数据：

| 检验项 | 结果 |
| --- | --- |
| `app/` 与 `tests/` 语法编译（3.14.7） | 零错误 |
| 依赖解析 `--python 3.14` / `3.14t` | 各 208 包，均成功 |
| 实际安装（`runtime-standard` 组） | 成功，含 Rust/C 扩展 |
| 全量测试 @ 3.14.7 | 8484 passed / 4 skipped / 1 failed |
| 新增回归 | 无 |

唯一失败为既有项 `test_official_plugin_baseline_records_external_source`（fixture `schema_version` 为 2、测试期望 3），与本次升级无关。

**语言层面零不兼容**——3.12→3.14 的风险不在代码而在依赖矩阵，这印证了把 P0 单列、不与外挂改造叠加的判断。仅一处需修：`asyncio.iscoroutinefunction` 在 3.14 弃用、3.16 移除，已改用 `inspect.iscoroutinefunction`。

### 7.5 未经验证的部分

以下事项受限于环境（无 docker、无法跑 trivy），只做了静态核对，**未实际验证**：

- `python:3.14.7-slim-trixie` 基础镜像是否可解析（照抄上游，未拉取）。
- `PYTHON_THREAD_INHERIT_CONTEXT=0` 的运行时效果（该环境变量本身经既有测试确认为真实意图）。
- **`.trivyignore.yaml` 未采用上游的 8 条 rclone/Go stdlib 忽略项**：它们绑定精确 purl 版本 `pkg:golang/stdlib@v1.26.5`，对应上游固定摘要镜像 `rclone/rclone:1.75.0@sha256:...`；本 fork 仍以 `curl install.sh` 浮动安装 rclone，照抄会得到永不生效的条目并制造已豁免的错觉。**CI 首次跑 trivy 很可能因此失败**，需以实际扫描结果重新生成，或把 Dockerfile 也改为固定摘要镜像。
- 上游 Dockerfile 的 `verify_venv_*` 阶段未移植：它们 `COPY` 的 `app/doctor/dependencies.py` 在本 fork 不存在，照抄会让所有镜像构建立即失败。

## 8. 运行时优化

主要收益来源是**未安装即不 import**——外挂模块的包不在环境里，其 import 开销与常驻对象一并消失，这是体积减负的直接副产品。

除此之外，独立纳入一项已确诊的缺陷修复：随机壁纸取用路径存在 `while True` 无界自旋，是实测的单核满载根因（该缺陷源自上游，`upstream/v2` 至今仍在）。

**不纳入**本设计的运行时议题：HTTP 多 worker 进程隔离（边界错位，已有裁决）、Rust 化重写。

## 9. 升级路径

> 以下为待确认假设，评审时需明确认可或改写。

**首启自动补装**：启动时扫描现有配置，发现引用了已外挂的模块就自动从插件市场拉取安装对应插件，用户无感。

- 代价：首次启动变慢、需联网。
- 离线环境降级为界面提示 + 一键安装按钮，不静默失败。
- 「配置还在但功能没了」的静默失败是必须避免的结果。

## 10. 风险

| 风险 | 说明 | 处置 |
| --- | --- | --- |
| Python 3.14 跳版 | 当前测试环境为 3.12，直升 3.14 会同时引入语言与依赖两层变化 | 先单独完成 3.12→3.14 升级并跑通测试基线，再开始外挂改造，不叠加 |
| 28 个插件外壳的一致性 | 逐个手写易出现形态漂移 | 先做 1 个样板定型，再批量套用。**验证样板与首发迁移对象要分开选**：`discord` 依赖独占、结构简单且能暴露 G1，适合作验证样板（已完成）；首发投产的迁移对象另选，判据见 §11 P3 |
| 外挂改变分发顺序 | 模块从宿主源（priority 升序）迁至插件源（注册顺序且整源优先），单播场景行为改变；P3 样板阶段已实测证实（G1，见 §4.5） | 阻塞性，须在 P4 批量外挂前于宿主侧完成排序机制改造，见 §11 |
| 渠道枚举移除 | 存量配置持有已移除的枚举取值 | 归一路径给可诊断结果；覆盖测试必须包含「配置引用未安装渠道」的用例 |
| 测试基线 | 外挂后大量既有测试引用被移出的模块 | 测试同步迁移，内核测试不得 import 外挂模块 |
| `_validate_manifest_inventory` | 该校验对清单完整性有要求，模块移出后需相应调整 | 改造时同步处理，不留静默跳过 |
| 已知脆弱测试 | `tests/test_cache_system.py` 注册全局 `torrent_analysis_port` 不复原，`test_torrent_filter.py` 靠字母序侥幸通过 | 属既有缺口，本设计不修，但批量改动可能触发，需预期 |
| agent/workflow 数据层耦合 | 原判断为叶子子系统，实为服务层长在 application/api，P5 工作量被低估 | 范围扩大到服务层与依赖注入一并迁移 |
| 插件自管理 DB 缺失 | v3-python 的框架在 v3-pure 上不存在，持久化外挂无地基 | 单独立项重建，不阻塞其余阶段 |
| 插件方法表漂移 | 方法表从宿主侧反射推导退化为插件手写清单，原模块新增方法时插件表不会同步（G8） | 加契约测试比对插件方法表与原模块公开方法集，CI 拦截漂移 |
| 存量 provider 诊断盲区 | 存量 `ServiceConfig.provider = "host:builtin"` 行外挂后归属实为插件，「提供方已消失」诊断端点对 `BUILTIN_PROVIDER` 直接 `continue`，静默失效不报（G5） | 迁移脚本回填 provider，或诊断端点覆盖该情形 |
| 前端内建类型清单跨仓同步 | `/service/types/{capability}` 由内建 `capability.toml` 与扩展声明并起来渲染，渠道从内建挪到扩展后 MoviePilot-Frontend 的内建类型清单需同步删项（G7） | 前后端改动配对发布，避免中间态下拉框重复或缺项 |

## 11. 实施顺序

各阶段独立可验证，每阶段结束测试须全绿。

1. **P0 — Python 3.14 升级**（**已完成**）：`requires-python` 提至 `>=3.14`、ABI 双 dependency-group、Docker 与 CI 双变体、8484 测试通过且无新增回归。实测与未验证项见 §7.4、§7.5。
2. **P1 — schemas 解耦**（**已完成**）：`ConversationMemory` 连同其 langchain 依赖迁入 `app/agent/memory/`，内核 schemas 不再依赖 `langchain_core`；新增内核第三方依赖护栏 `tests/test_v3lite_kernel_dependencies.py`。详见 §6.1。
3. **P2 — 声明字段补齐**（**已完成**）：`ModuleDeclaration` 增加 `priority` 字段（提交 `627720379`），声明层与投影层完整携带该值；`activation` 语义是否确由服务实例配置存在性覆盖，已在 P3 样板阶段验证为部分成立（见 §4.2、§4.5 G2）。
4. **P3 — 样板插件**（**可行性验证已完成，见 §4.5**）：前置条件是先解决 G1（跨源排序仲裁）——插件源目前无条件优先于宿主源，任何模块外挂都会在单播场景下改变分发结果，这条必须先于任何模块的外挂改造完成，不能留到批量阶段才补。

   已完成的是**语义层面**的可行性验证：三族组合对清单各字段的承载能力、`activation` 等价性、分发顺序变化、渠道能力接管路径，均以测试固化（`tests/test_v3lite_discord_outsourcing.py`、`tests/test_v3lite_activation_semantics.py`，共 18 例，提交 `14700e57a`）。其中 `activation.selector` 与配置存在性的等价假设验证为**部分证伪**（见 §4.2、§4.5 G2）。

   **端到端流程尚未执行**：打包布局、市场索引、安装与卸载路径是通过阅读宿主实现查清的（结论见 §4.5 G7），验证过程中未在 `app/plugins/` 下创建任何目录，替身均构造在测试内。真实的装机—启用—卸载闭环需在本阶段补做。

   discord 因 priority=4 居中、且提供 5 个单播方法（`send_direct_message` 等），是暴露 G1 的最好样本——但正因如此，它不是最安全的首发迁移对象：一旦在 G1 未修复前把它转为生产插件，单播分发的应答方会从 telegram 切到 discord（见 §4.4 实测）。建议首发迁移对象改选 priority 数值最大、且只提供多播/广播方法（不含单播）的模块，把 G1 未解决时的影响面限制在「发送次序变化」而非「应答方错位」；具体候选需在批量阶段逐个核实方法组成后确定。
5. **P4 — 批量外挂 modules**（前提：G1 已解决）：其余 27 个模块按样板套用；静态表让出 8 项（原子迁移，见 §5.1）；枚举与归一路径处理。
6. **P5 — agent / workflow 外挂**：范围扩大为宿主侧 14 个文件条件化 **加上** application/api 层的 agent/workflow 服务与依赖注入迁移（§2.5「数据与服务层」清单）；两个插件交付。
7. **P6 — 持久化外挂**：4 张表 + 3 个 oper（§2.6）随 agent/workflow 移出内核。前置为「插件自管理 DB 框架」重建（§6.4），该前置在 `v3-pure` 上尚不存在，本阶段在前置就绪前不具备开工条件，单列跟踪、不占用 P5 工期。
8. **P7 — 升级路径**：首启扫描与自动补装。
9. **P8 — 运行时优化**：修随机壁纸自旋；复测内存与 CPU。

## 12. 待确认清单

评审时需要明确表态的五项：

1. §4.2 / §4.5 的 `activation` 判断——已验证、部分证伪：实例生死等价，方法表闸门不等价（G2）。需评审表态的是 G2 的绕法是否接受：插件启用即挂方法表、各方法内部按配置为空提前返回的语义放宽方案（代价是多一次空转调用）。`priority` 字段已落地，不在本清单内。
2. §9 的升级路径（首启自动补装）。
3. §7.3 的 3.14t 中文能力降级是否接受——本 fork 因多一个 `jieba-next`，free-threaded 变体会同时缺分词与繁简转换，比上游更重。
4. 持久化外挂（4 张表 + 插件自管理 DB 重建，见 §2.6、§6.4）是纳入 v3-lite 范围，还是单独立项。
5. 插件模块的排序机制与跨源仲裁规则如何设计（让插件源也按 priority 排序、统一两源到同一排序体系、还是保持插件优先并接受行为变化，见 §4.4、§4.5 G1）。P3 样板阶段已实测证实该问题真实存在且属阻塞性，须在 P4 批量外挂前定案（见 §11）。
