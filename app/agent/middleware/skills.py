import re
from collections.abc import Awaitable, Callable
from typing import Annotated, List
from typing import NotRequired, TypedDict

import yaml  # noqa
from anyio import Path as AsyncPath
from langchain.agents.middleware.types import (
    AgentMiddleware,
    AgentState,
    ContextT,
    ModelRequest,
    ModelResponse,
    ResponseT,
)
from langchain.agents.middleware.types import PrivateStateAttr  # noqa
from langchain_core.runnables import RunnableConfig
from langgraph.runtime import Runtime

from app.agent.middleware.utils import append_to_system_message
from app.log import logger

# 安全提示: SKILL.md 文件最大限制为 10MB，防止 DoS 攻击
MAX_SKILL_FILE_SIZE = 10 * 1024 * 1024

# Agent Skills 规范约束 (https://agentskills.io/specification)
MAX_SKILL_NAME_LENGTH = 64
MAX_SKILL_DESCRIPTION_LENGTH = 1024
MAX_SKILL_COMPATIBILITY_LENGTH = 500


class SkillMetadata(TypedDict):
    """Skill 元数据，符合 Agent Skills 规范。"""

    path: str
    """SKILL.md 文件路径。"""

    id: str
    """Skill 标识符。
    约束: 1-64 字符，仅限小写字母/数字/连字符，不能以连字符开头或结尾，无连续连字符，需与父目录名一致。
    """

    name: str
    """Skill 名称。
    约束: Skill中文描述。
    """

    description: str
    """Skill 功能描述。
    约束: 1-1024 字符，应说明功能及适用场景。
    """

    license: str | None
    """许可证信息。"""

    compatibility: str | None
    """环境依赖或兼容性要求 (最多 500 字符)。"""

    metadata: dict[str, str]
    """附加元数据。"""

    allowed_tools: list[str]
    """(实验性) Skill 建议使用的工具列表。"""


class SkillsState(AgentState):
    """skills 中间件状态。"""

    skills_metadata: NotRequired[Annotated[list[SkillMetadata], PrivateStateAttr]]
    """已加载的 skill 元数据列表，不传播给父 agent。"""


class SkillsStateUpdate(TypedDict):
    """skills 中间件状态更新项。"""

    skills_metadata: list[SkillMetadata]
    """待合并的 skill 元数据列表。"""


def _parse_skill_metadata(  # noqa: C901
        content: str,
        skill_path: str,
        skill_id: str,
) -> SkillMetadata | None:
    """从 SKILL.md 内容中解析 YAML 前言并验证元数据。"""
    if len(content) > MAX_SKILL_FILE_SIZE:
        logger.warning("Skipping %s: content too large (%d bytes)", skill_path, len(content))
        return None

    # 匹配 --- 分隔的 YAML 前言
    frontmatter_pattern = r"^---\s*\n(.*?)\n---\s*\n"
    match = re.match(frontmatter_pattern, content, re.DOTALL)
    if not match:
        logger.warning("Skipping %s: no valid YAML frontmatter found", skill_path)
        return None
    frontmatter_str = match.group(1)

    # 解析 YAML
    try:
        frontmatter_data = yaml.safe_load(frontmatter_str)
    except yaml.YAMLError as e:
        logger.warning("Invalid YAML in %s: %s", skill_path, e)
        return None

    if not isinstance(frontmatter_data, dict):
        logger.warning("Skipping %s: frontmatter is not a mapping", skill_path)
        return None

    # SKill名称和描述
    name = str(frontmatter_data.get("name", "")).strip()
    description = str(frontmatter_data.get("description", "")).strip()
    if not name or not description:
        logger.warning("Skipping %s: missing required 'name' or 'description'", skill_path)
        return None
    description_str = description
    if len(description_str) > MAX_SKILL_DESCRIPTION_LENGTH:
        logger.warning(
            "Description exceeds %d characters in %s, truncating",
            MAX_SKILL_DESCRIPTION_LENGTH,
            skill_path,
        )
        description_str = description_str[:MAX_SKILL_DESCRIPTION_LENGTH]

    # 可选的工具列表，支持空格或逗号分隔
    raw_tools = frontmatter_data.get("allowed-tools")
    if isinstance(raw_tools, str):
        allowed_tools = [
            t.strip(",")  # 兼容 Claude Code 风格的逗号分隔
            for t in raw_tools.split()
            if t.strip(",")
        ]
    else:
        if raw_tools is not None:
            logger.warning(
                "Ignoring non-string 'allowed-tools' in %s (got %s)",
                skill_path,
                type(raw_tools).__name__,
            )
        allowed_tools = []

    # 能力或环境兼容性说明，最多 500 字符
    compatibility_str = str(frontmatter_data.get("compatibility", "")).strip() or None
    if compatibility_str and len(compatibility_str) > MAX_SKILL_COMPATIBILITY_LENGTH:
        logger.warning(
            "Compatibility exceeds %d characters in %s, truncating",
            MAX_SKILL_COMPATIBILITY_LENGTH,
            skill_path,
        )
        compatibility_str = compatibility_str[:MAX_SKILL_COMPATIBILITY_LENGTH]

    return SkillMetadata(
        id=skill_id,
        name=name,
        description=description_str,
        path=skill_path,
        metadata=_validate_metadata(frontmatter_data.get("metadata", {}), skill_path),
        license=str(frontmatter_data.get("license", "")).strip() or None,
        compatibility=compatibility_str,
        allowed_tools=allowed_tools,
    )


def _validate_metadata(
        raw: object,
        skill_path: str,
) -> dict[str, str]:
    """验证并规范化 YAML 前言中的元数据字段，确保为 dict[str, str] 类型。"""
    if not isinstance(raw, dict):
        if raw:
            logger.warning(
                "Ignoring non-dict metadata in %s (got %s)",
                skill_path,
                type(raw).__name__,
            )
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def _format_skill_annotations(skill: SkillMetadata) -> str:
    """构建许可证和兼容性说明字符串。"""
    parts: list[str] = []
    if skill.get("license"):
        parts.append(f"License: {skill['license']}")
    if skill.get("compatibility"):
        parts.append(f"Compatibility: {skill['compatibility']}")
    return ", ".join(parts)


async def _alist_skills(source_path: AsyncPath) -> list[SkillMetadata]:
    """异步列出指定路径下的所有技能。
    
    扫描包含 SKILL.md 的目录并解析其元数据。
    """
    skills: list[SkillMetadata] = []

    # 查找所有技能目录 (包含 SKILL.md 的目录)
    skill_dirs: List[AsyncPath] = []
    for path in source_path.iterdir():
        if await path.is_dir() and await (path / "SKILL.md").is_file():
            skill_dirs.append(path)

    if not skill_dirs:
        return []

    # 解析已下载的 SKILL.md
    for skill_path in skill_dirs:
        skill_md_path = skill_path / "SKILL.md"

        skill_content = await skill_path.read_text(encoding="utf-8")

        # 解析元数据
        skill_metadata = _parse_skill_metadata(
            content=skill_content,
            skill_path=skill_md_path,
            skill_id=skill_path.name,
        )
        if skill_metadata:
            skills.append(skill_metadata)

    return skills


SKILLS_SYSTEM_PROMPT = """
<skills_system>
You have access to a skills library that provides specialized capabilities and domain knowledge.

{skills_locations}

**Available Skills:**

{skills_list}

**How to Use Skills (Progressive Disclosure):**

Skills follow a **progressive disclosure** pattern - you see their name and description above, but only read full instructions when needed:

1. **Recognize when a skill applies**: Check if the user's task matches a skill's description
2. **Read the skill's full instructions**: Use the path shown in the skill list above
3. **Follow the skill's instructions**: SKILL.md contains step-by-step workflows, best practices, and examples
4. **Access supporting files**: Skills may include helper scripts, configs, or reference docs - use absolute paths

**When to Use Skills:**
- User's request matches a skill's domain (e.g., "research X" -> web-research skill)
- You need specialized knowledge or structured workflows
- A skill provides proven patterns for complex tasks

**Executing Skill Scripts:**
Skills may contain Python scripts or other executable files. Always use absolute paths from the skill list.

**Example Workflow:**

User: "Can you research the latest developments in quantum computing?"

1. Check available skills -> See "web-research" skill with its path
2. Read the skill using the path shown
3. Follow the skill's research workflow (search -> organize -> synthesize)
4. Use any helper scripts with absolute paths

Remember: Skills make you more capable and consistent. When in doubt, check if a skill exists for the task!
</skills_system>
"""


class SkillsMiddleware(AgentMiddleware[SkillsState, ContextT, ResponseT]):  # noqa
    """加载并向系统提示词注入 Agent Skill 的中间件。
    
    按源顺序加载 Skill，后加载的会覆盖重名的。
    """

    state_schema = SkillsState

    def __init__(self, *, sources: list[str]) -> None:
        """初始化 Skill 中间件。"""
        self.sources = sources
        self.system_prompt_template = SKILLS_SYSTEM_PROMPT

    def _format_skills_locations(self) -> str:
        """格式化技能位置信息用于系统提示词。"""
        locations = []

        for i, source_path in enumerate(self.sources):
            suffix = " (higher priority)" if i == len(self.sources) - 1 else ""
            locations.append(f"**MoviePilot Skills**: `{source_path}`{suffix}")

        return "\n".join(locations)

    def _format_skills_list(self, skills: list[SkillMetadata]) -> str:
        """格式化技能元数据列表用于系统提示词。"""
        if not skills:
            paths = [f"{source_path}" for source_path in self.sources]
            return f"(No skills available yet. You can create skills in {' or '.join(paths)})"

        lines = []
        for skill in skills:
            annotations = _format_skill_annotations(skill)
            desc_line = f"- **{skill['id']}**: {skill['name']} - {skill['description']}"
            if annotations:
                desc_line += f" ({annotations})"
            lines.append(desc_line)
            if skill["allowed_tools"]:
                lines.append(f"  -> Allowed tools: {', '.join(skill['allowed_tools'])}")
            lines.append(f"  -> Read `{skill['path']}` for full instructions")

        return "\n".join(lines)

    def modify_request(self, request: ModelRequest[ContextT]) -> ModelRequest[ContextT]:
        """将技能文档注入模型请求的系统消息中。"""
        skills_metadata = request.state.get("skills_metadata", [])  # noqa
        skills_locations = self._format_skills_locations()
        skills_list = self._format_skills_list(skills_metadata)

        skills_section = self.system_prompt_template.format(
            skills_locations=skills_locations,
            skills_list=skills_list,
        )

        new_system_message = append_to_system_message(request.system_message, skills_section)

        return request.override(system_message=new_system_message)

    async def abefore_agent(  # noqa
            self,
            state: SkillsState,
            runtime: Runtime,
            config: RunnableConfig
    ) -> SkillsStateUpdate | None:  # ty: ignore[invalid-method-override]
        """在 Agent 执行前异步加载技能元数据。
        
        每个会话仅加载一次。若 state 中已有则跳过。
        """
        # 如果 state 中已存在元数据则跳过
        if "skills_metadata" in state:
            return None

        all_skills: dict[str, SkillMetadata] = {}

        # 遍历源按顺序加载技能，重名时后者覆盖前者
        for source_path in self.sources:
            skill_source_path = AsyncPath(source_path)
            if not await skill_source_path.exists():
                await skill_source_path.mkdir(parents=True, exist_ok=True)
                continue
            source_skills = await _alist_skills(skill_source_path)
            for skill in source_skills:
                all_skills[skill["name"]] = skill

        skills = list(all_skills.values())
        return SkillsStateUpdate(skills_metadata=skills)

    async def awrap_model_call(
            self,
            request: ModelRequest[ContextT],
            handler: Callable[[ModelRequest[ContextT]], Awaitable[ModelResponse[ResponseT]]],
    ) -> ModelResponse[ResponseT]:
        """在模型调用时注入技能文档。"""
        modified_request = self.modify_request(request)
        return await handler(modified_request)


__all__ = ["SkillMetadata", "SkillsMiddleware"]
