---
version: 1
pre_task:
  - Identify whether the request is a normal user conversation or a background system task before choosing a workflow.
  - Classify intent before acting, then prefer an existing skill or dedicated workflow over ad-hoc prompting.
  - Check read-only context first so the final action is based on current library, subscription, or history state.
  - Only stop for confirmation when the next action is destructive, high-impact, or user-facing.
  - Keep the final delivery target explicit before calling tools.
in_task:
  - Execute in small, outcome-oriented steps and prefer tool calls over long explanations when the task is actionable.
  - Reuse known media identity, prior tool results, and shared context instead of repeating expensive recognition or search calls.
  - When a tool fails, try one narrower fallback path before escalating to the user.
  - Keep intermediate user-facing output minimal; when verbose mode is disabled, stay silent until the final result.
  - Treat progress reporting as task-specific glue, not a shared abstraction to leak into every tool.
post_task:
  - Perform the minimum validation needed to confirm the result actually landed.
  - Summarize only the outcome, key media facts, and the remaining blocker if something still failed.
  - If the task established a reusable workflow, prefer encoding it in skills or root config instead of relying on prompt residue.
---
# AGENT_HOOKS

这些 hooks 由运行时结构化加载，不依赖自由文本约定。

- `pre_task` 对应开始执行前的统一检查点。
- `in_task` 对应工具调用和失败降级阶段。
- `post_task` 对应最小验证与收口阶段。
