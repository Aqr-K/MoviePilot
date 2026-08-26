# v3-lite 设计

- 日期：2026-08-26
- 基线：`refactor/v3-pure` @ `f31300f64`
- 状态：待评审

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

- `requires-python = ">=3.14"`（本 fork 当前为 `>=3.12`）。
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
| `entrypoint` | `ModuleDeclaration.impl` |
| 方法表 | `ModuleDeclaration.methods` |
| `service_capability` + `subtype` | `ServiceInstanceDeclaration.capability` + 类型标识 |
| `multi_instance` | `ServiceInstanceDeclaration.multi_instance` |
| 渠道能力 | `provides_channel_capabilities` |
| `depends_on` | 插件自身的依赖声明 |
| `priority` | `ModuleDeclaration.priority`（字段已补；宿主侧排序机制未定，见 4.4） |
| `activation.policy` / `activation.selector` | 假设由服务实例配置存在性覆盖（**待验证**，见 4.2） |

一个内建模块 ≈ `ModuleDeclaration`（方法表）+ `ServiceInstanceDeclaration`（可配置类型）的组合。两族的职责分工在 `ModuleDeclaration` 的文档里已经写明——「本声明只描述方法表，按用户配置扇出多个具名服务实例是另一回事」——正好对应模块的两个面。

**不新增 `provides_host_modules` 族**的理由：新族与这两族职责重叠，违背「族存在的理由是取用形状不同，不是业务语义不同」的既定判据。

**不硬塞进单个 `provides_modules`** 的理由：`provides_modules` 是「无额外元数据需求的能力」的形态，而这些模块携带 `subtype` / `priority` / `multi_instance` / 激活选择器等元数据，硬塞会让该族退化成万能入口。

### 4.2 两处字段缺口的补法

**`priority`（分发顺序）**：`ModuleDeclaration` 已增加 `priority: int` 字段（提交 `627720379`），配套读取器 `declaration_module_priority()` 与注册期类型校验已就绪，声明层与投影层完整携带该值——字段本身已经落地，不再是待确认项。

但**宿主侧尚无消费方**：`PluginProviderSource._providers()` 遍历 `catalog.get_plugin_modules()`——由所有声明扁平化而成的 `{方法名: 可调用对象}` 字典，只按注册顺序遍历，从不读取 priority 值。也就是说，字段目前只保证语义在声明与投影层不丢失，真正待做的是**插件模块的排序机制设计**：谁读这个字段、在哪一层用它排序、如何与内建侧已有的排序方式协调。这块工作比字段本身更重，详见 §4.4。

**`activation.policy` / `activation.selector`**：不新增字段，但这是**尚待验证的假设**，不是已定结论：

- `policy = "when_configured"` 的语义由 `provides_service_instances` 的**配置存在性**天然表达——用户没配就没有实例，效果等同。
- `activation.selector` 指向的 `system_config_item`（如 `Notifications` 里 `type == "discord"` 且 `enabled` 为真）本就是服务实例配置列表的一条记录，宿主已按这条记录构造实例。
- 插件自身的启用/停用开关覆盖 `policy` 的其余取值。

以上等价关系目前只是推论，尚未经代码验证，正由 P3 样板阶段（`discord`）实测确认 `activation.selector` 与「配置存在性」是否真的等价，见 §11。

综合两项：字段层面的缺口已经补齐（`priority` 落地、`activation` 判断降级为待验证假设），但**机制层面的缺口——插件模块的排序与跨源仲裁——尚未解决**，且比字段缺口更重要：字段只负责携带数据，机制才决定分发结果。详见 §4.4。

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

在单播（只取一个结果）类分发下，这会直接改变现有行为，是 v3-lite 尚未解决的问题。处置方向——插件源改按 priority 排序、统一两源到同一排序体系、还是保持插件优先并接受行为变化——需在样板阶段确定。

## 5. 渠道能力双轨的处理

### 5.1 冲突与消解

既有决策「渠道能力保持双轨、不把内建搬成新写法」的**前提是「内建渠道固定、随代码走」**。8 个 IM 渠道（`feishu`、`discord`、`slack`、`qqbot`、`wechatclawbot`、`vocechat`、`synologychat`、`dingtalk`）外挂后不再是内建，前提失效。

它们改走 `provides_channel_capabilities` **恰是双轨设计的原意**（扩展渠道自带能力声明），不是对该决策的违反。内核保留的 `telegram` / `wechat` / `webpush` 继续用 `app/schemas/notification.py:148` 的 `ChannelCapabilityManager._capabilities` 静态表，**该静态表保留、写法一行不动**。

### 5.2 需要处理的迁移点

- 静态表让出上述 8 项。
- `NotificationChannel` 枚举移除对应成员；扩展渠道以字符串标识存在。
- 存量用户配置里持久化的是渠道取值，需保证 `resolve_channel` / `channel_identity` 归一路径对「枚举已移除但配置仍在」的取值给出可诊断的结果，而不是 `AttributeError`。既有约定「不要用 `channel.value`，扩展渠道是字符串」在此处成为硬要求。

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

### 7.3 已知取舍

上游在 free-threaded 组里放弃了 `zhconv-rs`。本设计选择保留中文 NLP 栈（见 3.3），因此 3.14t 变体在 `zhconv-rs` 上会遇到同样问题。评审时需决定：3.14t 变体是否接受与上游相同的繁简转换降级。

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
| 28 个插件外壳的一致性 | 逐个手写易出现形态漂移 | 先做 1 个样板（建议 `discord`，依赖独占、结构简单）定型，再批量套用 |
| 外挂改变分发顺序 | 模块从宿主源（priority 升序）迁至插件源（注册顺序且整源优先），单播场景行为改变 | 样板阶段实测确认影响范围，排序机制随之设计 |
| 渠道枚举移除 | 存量配置持有已移除的枚举取值 | 归一路径给可诊断结果；覆盖测试必须包含「配置引用未安装渠道」的用例 |
| 测试基线 | 外挂后大量既有测试引用被移出的模块 | 测试同步迁移，内核测试不得 import 外挂模块 |
| `_validate_manifest_inventory` | 该校验对清单完整性有要求，模块移出后需相应调整 | 改造时同步处理，不留静默跳过 |
| 已知脆弱测试 | `tests/test_cache_system.py` 注册全局 `torrent_analysis_port` 不复原，`test_torrent_filter.py` 靠字母序侥幸通过 | 属既有缺口，本设计不修，但批量改动可能触发，需预期 |
| agent/workflow 数据层耦合 | 原判断为叶子子系统，实为服务层长在 application/api，P5 工作量被低估 | 范围扩大到服务层与依赖注入一并迁移 |
| 插件自管理 DB 缺失 | v3-python 的框架在 v3-pure 上不存在，持久化外挂无地基 | 单独立项重建，不阻塞其余阶段 |

## 11. 实施顺序

各阶段独立可验证，每阶段结束测试须全绿。

1. **P0 — Python 3.14 升级**：`requires-python` 提版、双 dependency-group、CI 双变体、测试基线恢复。不含任何外挂改造。
2. **P1 — schemas 解耦**（**已完成**）：`ConversationMemory` 连同其 langchain 依赖迁入 `app/agent/memory/`，内核 schemas 不再依赖 `langchain_core`；新增内核第三方依赖护栏 `tests/test_v3lite_kernel_dependencies.py`。详见 §6.1。
3. **P2 — 声明字段补齐**（**已完成**）：`ModuleDeclaration` 增加 `priority` 字段（提交 `627720379`），声明层与投影层完整携带该值；`activation` 语义是否确由服务实例配置存在性覆盖，留待 P3 样板阶段实测验证。
4. **P3 — 样板插件**：`discord` 外挂全流程走通（外壳、打包、市场索引、安装、启用、渠道能力注册、卸载）；同时验证 `activation.selector` 与配置存在性的等价假设，并设计插件模块的排序机制与跨源仲裁规则（§4.4）。
5. **P4 — 批量外挂 modules**：其余 27 个模块按样板套用；静态表让出 8 项；枚举与归一路径处理。
6. **P5 — agent / workflow 外挂**：范围扩大为宿主侧 14 个文件条件化 **加上** application/api 层的 agent/workflow 服务与依赖注入迁移（§2.5「数据与服务层」清单）；两个插件交付。
7. **P6 — 持久化外挂**：4 张表 + 3 个 oper（§2.6）随 agent/workflow 移出内核。前置为「插件自管理 DB 框架」重建（§6.4），该前置在 `v3-pure` 上尚不存在，本阶段在前置就绪前不具备开工条件，单列跟踪、不占用 P5 工期。
8. **P7 — 升级路径**：首启扫描与自动补装。
9. **P8 — 运行时优化**：修随机壁纸自旋；复测内存与 CPU。

## 12. 待确认清单

评审时需要明确表态的五项：

1. §4.2 的 `activation` 判断（不为 `policy` / `selector` 新增字段，改由服务实例配置存在性覆盖）——该假设待 P3 样板阶段实测确认。`priority` 字段已落地，不在本清单内。
2. §9 的升级路径（首启自动补装）。
3. §7.3 的 3.14t 是否接受繁简转换降级。
4. 持久化外挂（4 张表 + 插件自管理 DB 重建，见 §2.6、§6.4）是纳入 v3-lite 范围，还是单独立项。
5. 插件模块的排序机制与跨源仲裁规则如何设计（让插件源也按 priority 排序、统一两源到同一排序体系、还是保持插件优先并接受行为变化，见 §4.4）。
