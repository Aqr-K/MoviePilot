# MoviePilot AI Agent Guide

本文件用于统一在 MoviePilot 仓库内工作的 AI Agent 行为。除非更深层目录存在新的 `AGENTS.md` 覆盖，以下规则适用于整个仓库。

## 1. 项目定位

- 本仓库是 MoviePilot 的后端、CLI、MCP/API、Docker 与 AI skills 仓库。
- 后端基于 FastAPI，主要代码位于 `app/`。
- 前端源码不在本仓库，前端源仓库是 `MoviePilot-Frontend`；
- 本仓库还包含本地 CLI、数据库迁移、开发文档、测试、Docker 相关脚本与 AI skills。

## 2. 工作原则

- 先阅读相关实现、测试和文档，再修改代码；不要凭目录名猜行为。
- 采用最小正确改动，优先复用现有函数、模式与命名。
- 不做与当前任务无关的大规模重构、批量重命名或样式清扫。
- 新增抽象前先判断是否真的会被复用；能放在现有函数、现有类、现有链路中的，不要额外拆层。
- 工作区可能存在用户未提交修改；不要回滚、覆盖或整理你未理解的内容。
- 默认使用中文输出结论、验证结果和风险说明。

## 3. 关键目录说明

- `app/api/endpoints/`：HTTP 接口入口，处理鉴权、参数、响应和少量简单 CRUD。
- `app/chain/`：业务编排层，承接搜索、识别、订阅、下载、消息交互等用例。
- `app/modules/`：动态加载的系统模块层，封装下载器、媒体服务器、消息渠道及其他可插拔能力。
- `app/helper/`：可复用的低层辅助逻辑，不承载完整业务编排。
- `app/core/config.py`：环境变量、部署参数、启动级配置。
- `app/schemas/types.py`：`SystemConfigKey`、模块类型、枚举等共享类型定义。
- `app/db/`：数据库模型、会话和 `*_oper.py` 数据访问封装。
- `moviepilot`：本地 CLI 入口与帮助文本。
- `database/versions/`：Alembic 迁移脚本。
- `docs/`：CLI、MCP/API、开发流程等文档。
- `skills/`：可供 AI agent 使用的 skills 定义和脚本。
- `tests/`：pytest 测试与少量手动测试脚本。
- `config/`、`.moviepilot.env`、`*.db`：本地配置或运行数据，除非用户明确要求，否则不要修改或提交。

## 4. 分层与访问边界

### API / Endpoint 层

- endpoint 只处理 HTTP 相关内容：鉴权、参数解析、响应模型、流式输出适配、简单输入校验。
- 简单列表、详情、开关读写、纯 CRUD 型接口，可以直接调用 `app/db/` 或已有 `helper`。
- 涉及跨模块调度、事件发送、缓存、搜索识别下载联动、复杂业务判断时，应该下沉到 `chain` 层。
- 新增接口优先放进现有领域文件；只有出现新的顶层资源域时，才新增 endpoint 文件。
- 新增 endpoint 后要同步注册到 `app/api/apiv1.py`。

### Chain 层

- `chain` 是业务编排层，服务于 API、CLI、消息交互、agent、调度器等多个入口。
- `chain` 负责组合 `module`、`helper`、`db`、事件、缓存和其它稳定的 `chain` 能力。
- 在 `chain` 内优先通过 `run_module()` / `async_run_module()` 触发模块能力；只有确实需要枚举模块、取实例、做健康检查时，再直接使用 `ModuleManager` 或相关 helper。
- `chain` 应聚焦用例与流程，不应承载底层协议细节、HTTP 请求对象或页面参数拼装细节。
- 新增 `chain` 前先判断：这是不是一个会被多个入口复用的业务用例，或者需要协调多个模块/多种资源。如果只是单个 endpoint 的短逻辑，不要新建 `chain`。
- `chain` 之间可以复用，但要避免新增环依赖。

### Module 层

- `module` 是可插拔能力实现层，通过 `ModuleManager` 动态发现和加载。
- 适合放在 `module` 的内容：新下载器、新媒体服务器、新消息渠道、新识别/过滤/文件管理类系统能力，或任何需要启停、优先级、配置开关、独立测试的实现。
- 新增 `module` 时，应遵循现有基类约定，实现或对齐 `init_module()`、`init_setting()`、`get_name()`、`get_type()`、`get_subtype()`、`get_priority()`、`test()`、`stop()` 等接口。
- `module` 应聚焦单一后端或单一能力实现，返回领域结果，不返回 HTTP 响应，不感知 endpoint、鉴权或 FastAPI 请求对象。
- `chain -> module` 是主路径。仓库中存在少量历史性的 `module -> chain` 反向依赖；新增代码不要继续扩大这种模式。若模块也需要复用一段业务判断，优先上移到 `chain` 或下沉到 `helper`。
- 不要新增 `module -> module` 的直接耦合；多模块协同应由 `chain` 组织。

### Helper 层

- `helper` 适合承载可复用的低层支撑逻辑，例如路径处理、配置聚合、站点索引读取、协议客户端包装、限流、缓存辅助、页面解析等。
- 只有当逻辑会被多处复用，或本身就是一个独立的低层问题时，才新增 `helper`。
- 如果逻辑只在一个 `chain` 或一个 `module` 内使用，优先留在原文件中，避免把 `helper` 变成杂物箱。
- 如果一段代码已经需要配置开关、运行时装载、优先级、独立测试入口或多实现分发，它更像 `module`，而不是 `helper`。
- `helper` 不应演变为新的业务编排层；完整业务流程仍应放在 `chain`。

### 推荐调用方向

- 首选方向：`endpoint/CLI/agent/command -> chain -> module/helper/db`
- 允许方向：`chain -> chain`，前提是复用稳定领域能力且不引入环依赖。
- 谨慎方向：`endpoint -> db/model/oper/helper`，仅限简单查询、简单 CRUD 或输入校正。
- 避免方向：`module -> chain`、`module -> module`、`helper -> chain`、`helper -> endpoint`。

## 5. 新增能力如何落点

- 场景：新增一个搜索、识别、订阅、下载、消息交互之类的业务流程。
  处理：优先放到 `app/chain/`，让 API、CLI、agent 或调度器复用同一套编排逻辑。
- 场景：新增一个下载器、媒体服务器、消息渠道或其他可插拔后端接入。
  处理：放到 `app/modules/`；如涉及新的模块类别或子类型，同步检查 `app/schemas/types.py` 与相关 schema。
- 场景：新增一个对外 HTTP API。
  处理：放到 `app/api/endpoints/`，注册 `app/api/apiv1.py`，补齐鉴权、schema、文档和测试；复杂逻辑下沉到 `chain`。
- 场景：新增一个低层通用工具、解析器、配置读取器或协议包装。
  处理：放到 `app/helper/`；前提是它不是一次性逻辑，也不是完整业务用例。
- 场景：新增一个部署级、环境级、启动前确定的配置项，例如端口、路径、代理、开关、密钥、第三方服务地址。
  处理：放到 `app/core/config.py` 的 `ConfigModel` / `Settings`。
- 场景：新增一个运行时业务配置、用户可编辑规则、系统持久化选项。
  处理：优先使用 `SystemConfigKey` + `SystemConfigOper`，不要散落裸字符串 key。
- 场景：配置变更后需要自动重载长生命周期对象。
  处理：在对应 `chain`、`module`、`helper` 或管理类上补 `CONFIG_WATCH`、`on_config_changed()`、必要时补 `get_reload_name()`。
- 场景：只是在一个 `chain`/`module` 内多出几十行私有逻辑。
  处理：优先提炼为当前文件内的私有函数或私有方法，不要默认新建 `helper`。

## 6. 代码与注释要求

- 保持现有代码风格，不引入没有明确收益的新抽象层。
- 仓库当前风格中，大量类和方法使用简短 docstring；新增公开类、公开方法时，优先沿用所在文件的现有风格。
- 注释和 docstring 默认使用中文，若文件周边已经稳定使用英文，则与周边保持一致。
- 注释要解释“为什么这样做”以及“不直观的约束”，例如边界条件、兼容性原因、调用顺序、缓存/重载语义、外部系统限制。
- 不要写逐行翻译式注释，不要解释显而易见的赋值、分支或简单调用。
- 复杂注释优先写在代码块之前，避免长篇行尾注释。
- 修改代码时，同步更新或删除已经过时的注释；不要留下与实现不一致的说明。
- 不要加入无上下文的 TODO/FIXME；只有在当前任务无法一并处理、且这条备注对后续维护确实有帮助时才保留。
- 不要添加“修改开始/修改结束”“这里很重要”之类没有信息密度的注释。

## 7. 依赖与环境约定

- 目标 Python 版本为 `3.11+`；当前 CI 使用 Python `3.12`。
- 依赖源文件是 `requirements.in`。
- `requirements.txt` 是通过 `pip-compile requirements.in` 生成的锁定文件，不要手工维护内容。
- 安装依赖使用：`pip install -r requirements.txt`。
- 新增或升级依赖时：
  1. 先修改 `requirements.in`
  2. 再执行 `pip-compile requirements.in`
  3. 最后补跑相关测试与安全检查

## 8. 联动修改规则

- 修复 bug 时，优先补一个能复现问题的测试；新增功能时，优先补最小覆盖测试。
- 变更 CLI 行为时，同时检查并更新：`moviepilot`、`docs/cli.md`、相关测试。
- 变更 MCP/REST API、工具暴露或 AI 交互行为时，同时检查并更新：`docs/mcp-api.md`、相关 `skills/*/SKILL.md` 或脚本、相关测试。
- 变更开发流程、依赖管理或安全检查方式时，同时更新 `docs/development-setup.md`。
- 涉及数据库结构变化时，补充 `database/versions/` 迁移脚本；不要只改模型不改迁移。
- 变更用户可见配置、默认值或初始化流程时，同时检查相关文档、帮助文本、setup/init 流程和测试。
- 新增 skill 时，遵循现有 `skills/<name>/SKILL.md` 结构，保留 YAML front matter，并优先使用相对 `SKILL.md` 的脚本路径描述。

## 9. 验证要求

- 至少运行与当前改动直接相关的测试，例如：`pytest tests/test_xxx.py`。
- 影响公共模块、初始化流程、CLI 或 agent 运行时时，扩大测试范围。
- Python 代码改动后，至少确认不会为 `pylint app/` 引入新的错误级问题。
- 变更 CLI 时，至少验证相关帮助输出，例如：`moviepilot help` 或对应子命令帮助。
- 变更依赖时，补跑：`pip-compile requirements.in` 与 `safety check -r requirements.txt --policy-file=safety.policy.yml`。
- 如果本次只修改文档，明确说明未运行测试即可；不要伪造验证结果。

## 10. 提交与发布约定

- 只有在用户明确要求提交时才创建 commit。
- commit message 优先使用 Conventional Commits，例如：`feat: ...`、`fix: ...`、`docs: ...`。
- 这样做不是形式要求；仓库的发布流水线会按 Conventional Commits 生成 changelog 分类。
- 不要顺手修改版本号、发布配置或 Docker 发布流程，除非任务明确涉及这些内容。

## 11. 输出要求

- 结果说明聚焦三件事：改了什么、怎么验证的、还有什么风险。
- 不写空泛总结，不把未执行的检查写成“已完成”。
- 若发现兼容性影响、配置迁移风险或用户数据风险，必须明确指出。
