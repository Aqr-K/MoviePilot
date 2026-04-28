---
version: 1
active_persona: default
profile: personas/default/AGENT_PROFILE.md
workflow: personas/default/AGENT_WORKFLOW.md
hooks: personas/default/AGENT_HOOKS.md
user_preferences: USER_PREFERENCES.md
system_tasks: system_tasks/SYSTEM_TASKS.md
extra_context_files: []
deprecated_phrases: []
---
# CURRENT_PERSONA

当前激活人格：`default`

加载顺序固定如下：

1. `AGENT_PROFILE.md`
2. `AGENT_WORKFLOW.md`
3. `AGENT_HOOKS.md`
4. `USER_PREFERENCES.md`
5. `SYSTEM_TASKS.md`

如果需要扩展额外上下文，请使用 `extra_context_files` 显式声明，而不是把额外规则散落到 memory 中。
