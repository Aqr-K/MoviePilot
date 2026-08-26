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

| 子系统 | 被反向依赖的文件数 | 具体位置 |
| --- | --- | --- |
| `app/agent` | 10 | `startup/agent_initializer.py`、`startup/modules_initializer.py`、`api/endpoints/{agent,openai,llm,history,system,mcp}.py`、`api/service_secrets.py`、`sdk/agent.py` |
| `app/workflow` | 5 | `startup/{workflow,modules,hostport}_initializer.py`、`scheduler/workflows.py`、`api/endpoints/workflow.py` |

`app/domain`、`app/application`、`app/modules` 对 `app/agent` **零依赖**——它是干净的叶子子系统。

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
| `priority` | **缺口，见 4.2** |
| `activation.policy` / `activation.selector` | **缺口，见 4.2** |

一个内建模块 ≈ `ModuleDeclaration`（方法表）+ `ServiceInstanceDeclaration`（可配置类型）的组合。两族的职责分工在 `ModuleDeclaration` 的文档里已经写明——「本声明只描述方法表，按用户配置扇出多个具名服务实例是另一回事」——正好对应模块的两个面。

**不新增 `provides_host_modules` 族**的理由：新族与这两族职责重叠，违背「族存在的理由是取用形状不同，不是业务语义不同」的既定判据。

**不硬塞进单个 `provides_modules`** 的理由：`provides_modules` 是「无额外元数据需求的能力」的形态，而这些模块携带 `subtype` / `priority` / `multi_instance` / 激活选择器等元数据，硬塞会让该族退化成万能入口。

### 4.2 两处字段缺口的补法

> 以下为待确认假设，评审时需明确认可或改写。

**`priority`（分发顺序）**：给 `ModuleDeclaration` 增加 `priority: int` 字段。这是「用什么提供」之外的分发元数据，落在方法表声明上语义正确——同一方法名有多个提供者时，宿主按 priority 排序。

**`activation.policy` / `activation.selector`**：不新增字段。理由：

- `policy = "when_configured"` 的语义由 `provides_service_instances` 的**配置存在性**天然表达——用户没配就没有实例，效果等同。
- `activation.selector` 指向的 `system_config_item`（如 `Notifications` 里 `type == "discord"` 且 `enabled` 为真）本就是服务实例配置列表的一条记录，宿主已按这条记录构造实例。
- 插件自身的启用/停用开关覆盖 `policy` 的其余取值。

因此两个缺口实际只需新增**一个**字段。

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

`app/schemas/agent.py:6` 的 `from langchain_core.messages import BaseMessage` 是 langchain 类型泄漏进 schemas 层的唯一一处。schemas 属内核契约层，不能依赖将被移出的包。需先定义自有消息类型并切断该 import，否则 agent 无法外挂。

### 6.2 宿主侧改造

10 个反向依赖 `app/agent` 的文件与 5 个反向依赖 `app/workflow` 的文件（去重共 14 个）改为「能力存在才注册」：

- `startup/agent_initializer.py`、`startup/workflow_initializer.py`：能力缺失时跳过初始化而非报错。
- `api/endpoints/{agent,openai,llm,history,system,mcp,workflow}.py`：路由按能力存在与否条件注册。
- `sdk/agent.py`：作为 SDK 契约保留，实现由插件提供。
- `api/service_secrets.py`、`scheduler/workflows.py`、`startup/hostport_initializer.py`：条件分支处理。

### 6.3 交付形态

agent 与 workflow 各作为一个插件交付，而非拆成多个。agent 内部 `tools/` 占 19,177 行，是其最大构成，但工具与 agent 内核耦合紧密，不在本设计里进一步拆分。

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
| 渠道枚举移除 | 存量配置持有已移除的枚举取值 | 归一路径给可诊断结果；覆盖测试必须包含「配置引用未安装渠道」的用例 |
| 测试基线 | 外挂后大量既有测试引用被移出的模块 | 测试同步迁移，内核测试不得 import 外挂模块 |
| `_validate_manifest_inventory` | 该校验对清单完整性有要求，模块移出后需相应调整 | 改造时同步处理，不留静默跳过 |
| 已知脆弱测试 | `tests/test_cache_system.py` 注册全局 `torrent_analysis_port` 不复原，`test_torrent_filter.py` 靠字母序侥幸通过 | 属既有缺口，本设计不修，但批量改动可能触发，需预期 |

## 11. 实施顺序

各阶段独立可验证，每阶段结束测试须全绿。

1. **P0 — Python 3.14 升级**：`requires-python` 提版、双 dependency-group、CI 双变体、测试基线恢复。不含任何外挂改造。
2. **P1 — schemas 解耦**：切断 `app/schemas/agent.py` 对 `langchain_core` 的依赖，定义自有消息类型。
3. **P2 — 声明字段补齐**：`ModuleDeclaration` 增加 `priority`；验证 `activation` 语义确由服务实例配置存在性覆盖。
4. **P3 — 样板插件**：`discord` 外挂全流程走通（外壳、打包、市场索引、安装、启用、渠道能力注册、卸载）。
5. **P4 — 批量外挂 modules**：其余 27 个模块按样板套用；静态表让出 8 项；枚举与归一路径处理。
6. **P5 — agent / workflow 外挂**：14 个宿主侧文件条件化；两个插件交付。
7. **P6 — 升级路径**：首启扫描与自动补装。
8. **P7 — 运行时优化**：修随机壁纸自旋；复测内存与 CPU。

## 12. 待确认清单

评审时需要明确表态的三项：

1. §4.2 的字段缺口补法（`ModuleDeclaration.priority` + `activation` 不新增字段）。
2. §9 的升级路径（首启自动补装）。
3. §7.3 的 3.14t 是否接受繁简转换降级。
