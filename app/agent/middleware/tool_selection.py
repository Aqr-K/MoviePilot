"""MoviePilot 自定义工具筛选中间件。"""

import json
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, NotRequired

from langchain.agents.middleware.types import (
    AgentState,
    ContextT,
    ModelRequest,
    ModelResponse,
    ResponseT,
)
from langchain.agents.middleware.types import (
    PrivateStateAttr,  # noqa
)
from langchain.agents.middleware.tool_selection import (
    DEFAULT_SYSTEM_PROMPT,
    LLMToolSelectorMiddleware,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langgraph.runtime import Runtime
from typing_extensions import TypedDict  # noqa

from app.log import logger


class ToolSelectionState(AgentState):
    """工具筛选中间件私有状态。"""

    selected_tool_names: NotRequired[Annotated[list[str] | None, PrivateStateAttr]]
    """当前这条用户请求首轮筛选得到的工具名列表。"""


class ToolSelectionStateUpdate(TypedDict):
    """工具筛选中间件状态更新项。"""

    selected_tool_names: list[str] | None


class ToolSelectorMiddleware(LLMToolSelectorMiddleware):
    """
    为 DeepSeek 兼容端点提供更稳妥的工具筛选实现。

    LangChain 默认会通过 `with_structured_output()` 走 OpenAI 的
    `response_format=json_schema` 路径，但 DeepSeek 官方 OpenAI 兼容端点公开文档
    仅保证 `json_object` 模式可用。对于 `deepseek-reasoner`，这会在工具筛选阶段
    提前触发 400，导致 Agent 还没真正开始执行工具就失败。

    因此这里仅在识别到 DeepSeek 模型/端点时，退回到显式 JSON 输出模式：
    1. 使用 `response_format={"type": "json_object"}`；
    2. 在提示词中明确约束返回 JSON 结构；
    3. 手动解析 `{"tools": [...]}`，其余模型继续沿用 LangChain 默认实现。

    另外，LangChain 原生工具筛选挂在 `wrap_model_call` 上，会在同一条用户请求
    的每次“模型回合”前都重新筛选一次工具。对于会多轮调用工具的复杂任务，
    这会重复消耗一次额外的 LLM 调用。这里改成：
    - `abefore_agent()`：在本轮 Agent 执行开始时筛选一次；
    - `awrap_model_call()`：从 `request.state` 读取首轮筛选结果并复用。
    """

    state_schema = ToolSelectionState

    def __init__(
            self,
            model: BaseChatModel | str | None = None,
            system_prompt: str = DEFAULT_SYSTEM_PROMPT,
            selection_tools: list[Any] | None = None,
            max_tools: int | None = None,
            always_include: list[str] | None = None,
    ) -> None:
        super().__init__(
            model=model,
            system_prompt=system_prompt,
            max_tools=max_tools,
            always_include=always_include,
        )
        self.selection_tools = selection_tools or []

    def _process_selection_response(
            self,
            response: dict[str, Any],
            available_tools: list[BaseTool],
            valid_tool_names: list[str],
            request: ModelRequest[ContextT],
    ) -> ModelRequest[ContextT]:
        """
        处理工具筛选响应，并保留空结果回退所有工具的 MoviePilot 策略。
        """
        if response.get("tools") == []:
            logger.warning("工具筛选结果为空，将恢复使用所有工具。")

            always_included_tools: list[BaseTool] = [
                tool
                for tool in request.tools
                if not isinstance(tool, dict) and tool.name in self.always_include
            ]
            provider_tools = [tool for tool in request.tools if isinstance(tool, dict)]

            return request.override(
                tools=[*available_tools, *always_included_tools, *provider_tools]
            )

        return super()._process_selection_response(
            response,
            available_tools,
            valid_tool_names,
            request,
        )

    @staticmethod
    def _is_deepseek_compatible_model(model: BaseChatModel) -> bool:
        """
        判断当前模型是否应当走 DeepSeek JSON 兼容分支。

        除了官方 `langchain_deepseek`，用户也可能通过 OpenAI-compatible
        配置把 DeepSeek 端点接到 `ChatOpenAI`。因此这里同时检查模块名、模型名
        和 Base URL，避免只靠单一条件漏判。
        """
        module_name = type(model).__module__.lower()
        model_name = (
            str(getattr(model, "model_name", "") or getattr(model, "model", ""))
            .strip()
            .lower()
        )
        base_url = (
            str(getattr(model, "openai_api_base", "") or getattr(model, "api_base", ""))
            .strip()
            .lower()
        )

        return (
                "deepseek" in module_name
                or model_name.startswith("deepseek-")
                or "api.deepseek.com" in base_url
        )

    @staticmethod
    def _extract_text_content(content: Any) -> str:
        """
        从模型响应中提取纯文本。

        这里不依赖上层 LLMHelper，避免中间件与 LLM 构造逻辑互相耦合。
        """
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text_parts: list[str] = []
            for block in content:
                if isinstance(block, str):
                    text_parts.append(block)
                    continue
                if isinstance(block, dict):
                    if block.get("type") == "text" and isinstance(
                            block.get("text"), str
                    ):
                        text_parts.append(block["text"])
                        continue
                    if not block.get("type") and isinstance(block.get("text"), str):
                        text_parts.append(block["text"])
            return "".join(text_parts)
        if isinstance(content, dict):
            if content.get("type") == "text" and isinstance(content.get("text"), str):
                return content["text"]
            if not content.get("type") and isinstance(content.get("text"), str):
                return content["text"]
        return ""

    @staticmethod
    def _parse_json_object(text: str) -> dict[str, Any]:
        """
        解析模型返回的 JSON。

        DeepSeek 在 JSON 模式下通常会返回纯 JSON，但这里仍做一层兜底，
        兼容模型偶发输出围栏或前后说明文本的情况。
        """
        stripped_text = text.strip()
        if not stripped_text:
            raise ValueError("工具筛选返回了空响应")

        try:
            payload = json.loads(stripped_text)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass

        start = stripped_text.find("{")
        end = stripped_text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(f"工具筛选返回的内容不是合法 JSON: {stripped_text}")

        payload = json.loads(stripped_text[start: end + 1])
        if not isinstance(payload, dict):
            raise ValueError("工具筛选 JSON 顶层必须是对象")
        return payload

    @staticmethod
    def _render_tool_list(available_tools: list[Any]) -> str:
        """把工具名和描述渲染成稳定的文本列表。"""
        return "\n".join(
            f"- {tool.name}: {tool.description}" for tool in available_tools
        )

    def _build_deepseek_selection_prompt(self, selection_request: Any) -> str:
        """
        为 DeepSeek 生成显式 JSON 输出提示。

        DeepSeek 官方文档要求在 JSON 输出模式下，提示词中必须明确包含 JSON
        约束，否则兼容端点可能返回空内容或无意义输出。
        """
        limit_instruction = ""
        if self.max_tools:
            limit_instruction = f"- Select up to {self.max_tools} tools. IF NO TOOLS ARE RELEVANT, DO NOT RETURN AN EMPTY ARRAY. SELECT THE MOST APPLICABLE ONES TO ENSURE THE REQUEST IS HANDLED."

        return (
            f"{selection_request.system_message}\n\n"
            "Return the answer in JSON only.\n"
            'Use exactly this shape: {"tools": ["tool_name_1", "tool_name_2"]}\n'
            "Rules:\n"
            "- The `tools` field must be a JSON array of strings.\n"
            "- Only use tool names from the allowed list below.\n"
            "- Order tools by relevance, with the most relevant first.\n"
            f"{limit_instruction}\n"
            "- Do not add explanations, markdown, or extra keys.\n\n"
            "Allowed tools:\n"
            f"{self._render_tool_list(selection_request.available_tools)}"
        )

    def _normalize_selection_response(self, response: Any) -> dict[str, list[str]]:
        """
        解析并标准化 DeepSeek JSON 模式的工具筛选结果。
        """
        content = getattr(response, "content", response)
        text = self._extract_text_content(content)
        logger.debug(f"工具筛选原始响应: {text}")
        payload = self._parse_json_object(text)

        tools = payload.get("tools")
        if not isinstance(tools, list):
            raise ValueError(f"工具筛选 JSON 缺少 `tools` 数组: {payload}")

        normalized_tools = [
            tool_name for tool_name in tools if isinstance(tool_name, str)
        ]
        logger.debug(f"工具筛选标准化结果: {normalized_tools}")
        return {"tools": normalized_tools}

    async def _aselect_tools_with_deepseek(
            self, selection_request: Any
    ) -> dict[str, list[str]]:
        """
        使用 DeepSeek 兼容的 JSON 输出模式执行异步工具筛选。
        """
        logger.debug("工具筛选走 DeepSeek JSON 兼容分支")
        structured_model = selection_request.model.bind(
            response_format={"type": "json_object"}
        )
        response = await structured_model.ainvoke(
            [
                {
                    "role": "system",
                    "content": self._build_deepseek_selection_prompt(selection_request),
                },
                selection_request.last_user_message,
            ]
        )
        return self._normalize_selection_response(response)

    @staticmethod
    def _extract_selected_tool_names(request: ModelRequest) -> list[str]:
        """从已筛选后的请求中提取最终工具名，保留原有顺序。"""
        return [tool.name for tool in request.tools if not isinstance(tool, dict)]

    @staticmethod
    def _apply_selected_tools(
            request: ModelRequest[ContextT],
            selected_tool_names: list[str],
    ) -> ModelRequest[ContextT]:
        """
        将已筛选出的工具集应用到当前模型请求。

        这里只复用首次筛选出的客户端工具名；provider-specific 的 dict 工具仍然
        原样保留，避免破坏 LangChain/provider 自身的工具绑定约定。
        """
        if not selected_tool_names:
            return request

        current_tools_by_name = {
            tool.name: tool for tool in request.tools if not isinstance(tool, dict)
        }
        selected_tools = [
            current_tools_by_name[tool_name]
            for tool_name in selected_tool_names
            if tool_name in current_tools_by_name
        ]
        provider_tools = [tool for tool in request.tools if isinstance(tool, dict)]
        return request.override(tools=[*selected_tools, *provider_tools])

    async def _aselect_request_once(
            self, request: ModelRequest[ContextT]
    ) -> ModelRequest[ContextT]:
        """
        执行一次真实工具筛选，并返回筛选后的请求对象。

        这里单独抽成 helper，便于首次筛选后缓存结果，也便于测试覆盖
        “首轮筛选，后续复用”的行为。
        """
        selection_request = self._prepare_selection_request(request)
        if selection_request is None:
            return request

        if not self._is_deepseek_compatible_model(selection_request.model):
            captured_request: ModelRequest[ContextT] = request

            async def _capture_handler(
                    updated_request: ModelRequest[ContextT],
            ) -> ModelRequest[ContextT]:
                nonlocal captured_request
                captured_request = updated_request
                return updated_request

            await super().awrap_model_call(request, _capture_handler)
            return captured_request

        response = await self._aselect_tools_with_deepseek(selection_request)
        return self._process_selection_response(
            response,
            selection_request.available_tools,
            selection_request.valid_tool_names,
            request,
        )

    async def abefore_agent(  # noqa
            self,
            state: ToolSelectionState,
            runtime: Runtime,  # noqa
            config: RunnableConfig,
    ) -> ToolSelectionStateUpdate | None:  # ty: ignore[invalid-method-override]
        """
        在本轮 Agent 执行开始前完成一次真实工具筛选。

        这样后续多轮 `model -> tools -> model` 循环都只复用这一次结果，
        不会为每次模型回合重复追加一笔 selector LLM 开销。
        """
        if "selected_tool_names" in state:
            return None

        if not self.selection_tools or self.model is None:
            return ToolSelectionStateUpdate(selected_tool_names=None)

        selection_request = ModelRequest(
            model=self.model,
            tools=list(self.selection_tools),
            messages=state["messages"],
            state=state,
            runtime=runtime,
        )
        modified_request = await self._aselect_request_once(selection_request)
        selected_tool_names = self._extract_selected_tool_names(modified_request)
        return ToolSelectionStateUpdate(selected_tool_names=selected_tool_names or None)

    async def awrap_model_call(
            self,
            request: ModelRequest[ContextT],
            handler: Callable[
                [ModelRequest[ContextT]], Awaitable[ModelResponse[ResponseT]]
            ],
    ) -> ModelResponse[ResponseT]:
        """
        从 state 中读取首次筛选结果，并应用到每次模型回合。
        """
        selected_tool_names = request.state.get("selected_tool_names")  # noqa

        # 正常路径下，`abefore_agent()` 已经提前写入状态；这里只保留一层兜底，
        # 兼容直接单测或未来某些绕过 before_agent 的调用场景。
        if (
                selected_tool_names is None
                and self.selection_tools
                and self.model is not None
        ):
            request = await self._aselect_request_once(request)
            selected_tool_names = self._extract_selected_tool_names(request) or None
            request.state["selected_tool_names"] = selected_tool_names  # noqa

        if selected_tool_names:
            request = self._apply_selected_tools(request, selected_tool_names)

        return await handler(request)
