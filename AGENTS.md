# MoviePilot AI Agent Guide

本文件用于统一在 MoviePilot 仓库内工作的 AI Agent 行为。除非更深层目录存在新的 `AGENTS.md` 覆盖，以下规则适用于整个仓库。

## 1. 项目定位

- 本仓库是 MoviePilot 的后端、CLI、MCP/API、Docker 与 AI skills 仓库。
- 后端基于 FastAPI，主要代码位于 `app/`。
- 前端源码不在本仓库，前端源仓库是 `MoviePilot-Frontend`；本仓库中的 `public/` 仅视为前端构建产物目录。
- 本仓库还包含：
  - 本地 CLI 入口：`moviepilot`
  - 数据库迁移：`database/versions/`
  - 测试：`tests/`
  - 开发与接口文档：`docs/`
  - AI skills：`skills/`

## 2. 工作原则

- 先阅读相关实现、测试和文档，再修改代码；不要凭目录名猜行为。
- 采用最小正确改动，优先复用现有函数、模式与命名。
- 不做与当前任务无关的大规模重构、批量重命名或样式清扫。
- 工作区可能存在用户未提交修改；不要回滚、覆盖或整理你未理解的内容。
- 默认使用中文输出结论、验证结果和风险说明。

## 3. 关键目录说明

- `app/`：后端业务代码与启动流程，运行入口为 `app/main.py`
- `moviepilot`：本地 CLI 启动脚本与帮助文本
- `database/versions/`：Alembic 迁移脚本
- `docs/`：CLI、MCP、开发流程等文档
- `docker/`：镜像构建与容器启动脚本
- `skills/`：可供 AI agent 使用的 skills 定义和脚本
- `tests/`：pytest 测试与少量手动测试脚本
- `config/`、`.moviepilot.env`、`*.db`：本地配置或运行数据，除非用户明确要求，否则不要修改或提交

## 4. 不要手工修改的内容

- `__pycache__/`、`.mypy_cache/`、`.ruff_cache/`、`venv/`、`.runtime/`、`build/`、`dist/`
- Cython 或平台相关编译产物，例如 `app/helper/sites.cpython-*.so`
- 本地数据库、日志、缓存、cookie、token、环境文件
- `version.py`，除非任务明确是发版、对齐版本或用户明确要求修改版本号
- `public/` 中的构建产物，除非任务明确是更新前端发布资源

说明：`setup.py` 会编译 `app/**/*.py`（排除 `app/main.py`），普通后端改动通常不需要同步重建二进制产物，除非任务明确要求交付编译结果。

## 5. 依赖与环境约定

- 目标 Python 版本为 `3.11+`；当前 CI 使用 Python `3.12`
- 依赖源文件是 `requirements.in`
- `requirements.txt` 是通过 `pip-compile requirements.in` 生成的锁定文件，不要手工维护内容
- 安装依赖使用：`pip install -r requirements.txt`
- 新增或升级依赖时：
  1. 先修改 `requirements.in`
  2. 再执行 `pip-compile requirements.in`
  3. 最后补跑相关测试与安全检查

## 6. 代码与文档修改规则

- 保持现有代码风格，不引入没有明确收益的新抽象层。
- 注释保持克制，只解释不直观的逻辑或边界条件。
- 修复 bug 时，优先补一个能复现问题的测试；新增功能时，优先补最小覆盖测试。
- 变更 CLI 行为时，同时检查并更新：
  - `moviepilot`
  - `docs/cli.md`
  - 相关测试
- 变更 MCP/REST API、工具暴露或 AI 交互行为时，同时检查并更新：
  - `docs/mcp-api.md`
  - `skills/` 中相关 `SKILL.md` 或脚本
  - 相关测试
- 变更开发流程、依赖管理或安全检查方式时，同时更新 `docs/development-setup.md`
- 涉及数据库结构变化时，补充 `database/versions/` 迁移脚本；不要只改模型不改迁移

## 7. Skills 相关约定

- 新增 skill 时，遵循现有 `skills/<name>/SKILL.md` 结构，保留 YAML front matter（如 `name`、`version`、`description`）。
- skill 内引用脚本时，优先使用相对 `SKILL.md` 的路径描述。
- 如果 skill 对应的 CLI/API 行为变化，必须同步更新 skill 文档，避免文档与实际能力脱节。

## 8. 验证要求

- 至少运行与当前改动直接相关的测试，例如：`pytest tests/test_xxx.py`
- 影响公共模块、初始化流程、CLI 或 agent 运行时时，扩大测试范围
- Python 代码改动后，至少确认不会为 `pylint app/` 引入新的错误级问题
- 变更 CLI 时，至少验证相关帮助输出，例如：`moviepilot help` 或对应子命令帮助
- 变更依赖时，补跑：
  - `pip-compile requirements.in`
  - `safety check -r requirements.txt --policy-file=safety.policy.yml`

如果本次只修改文档，说明未运行测试即可；不要伪造验证结果。

## 9. 提交与发布约定

- 只有在用户明确要求提交时才创建 commit。
- commit message 优先使用 Conventional Commits，例如：`feat: ...`、`fix: ...`、`docs: ...`
- 这样做不是形式要求；仓库的发布流水线会按 Conventional Commits 生成 changelog 分类。
- 不要顺手修改版本号、发布配置或 Docker 发布流程，除非任务明确涉及这些内容。

## 10. 常见任务提示

- 新增 API 或工具：同时检查路由、鉴权、schema、文档、测试
- 新增 CLI 子命令：同时检查帮助文本、参数解析、文档、测试
- 新增数据库字段：同时检查模型、迁移、默认值与兼容路径
- 新增 agent/LLM 能力：同时检查 `skills/`、MCP/API 暴露、提示词行为与交互测试

## 11. 输出要求

- 结果说明聚焦三件事：改了什么、怎么验证的、还有什么风险
- 不写空泛总结，不把未执行的检查写成“已完成”
- 若发现兼容性影响、配置迁移风险或用户数据风险，必须明确指出
