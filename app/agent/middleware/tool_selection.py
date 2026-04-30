"""MoviePilot 自定义工具筛选中间件。"""

from __future__ import annotations

import json
from typing import Any

from langchain.agents.middleware import LLMToolSelectorMiddleware
from langchain_core.language_models.chat_models import BaseChatModel

from app.log import logger


class MoviePilotToolSelectorMiddleware(LLMToolSelectorMiddleware):
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
    """

    @staticmethod
    def _is_deepseek_compatible_model(model: BaseChatModel) -> bool:
        """
        判断当前模型是否应当走 DeepSeek JSON 兼容分支。

        除了官方 `langchain_deepseek`，用户也可能通过 OpenAI-compatible
        配置把 DeepSeek 端点接到 `ChatOpenAI`。因此这里同时检查模块名、模型名
        和 Base URL，避免只靠单一条件漏判。
        """
        module_name = type(model).__module__.lower()
        model_name = str(
            getattr(model, "model_name", "") or getattr(model, "model", "")
        ).strip().lower()
        base_url = str(
            getattr(model, "openai_api_base", "") or getattr(model, "api_base", "")
        ).strip().lower()

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
        return (
            f"{selection_request.system_message}\n\n"
            "Return the answer in JSON only.\n"
            'Use exactly this shape: {"tools": ["tool_name_1", "tool_name_2"]}\n'
            "Rules:\n"
            "- The `tools` field must be a JSON array of strings.\n"
            "- Only use tool names from the allowed list below.\n"
            "- Order tools by relevance, with the most relevant first.\n"
            "- Do not add explanations, markdown, or extra keys.\n\n"
            f"Allowed tools:\n{self._render_tool_list(selection_request.available_tools)}"
        )

    def _normalize_selection_response(self, response: Any) -> dict[str, list[str]]:
        """
        解析并标准化 DeepSeek JSON 模式的工具筛选结果。
        """
        content = getattr(response, "content", response)
        text = self._extract_text_content(content)
        payload = self._parse_json_object(text)

        tools = payload.get("tools")
        if not isinstance(tools, list):
            raise ValueError(f"工具筛选 JSON 缺少 `tools` 数组: {payload}")

        normalized_tools = [tool_name for tool_name in tools if isinstance(tool_name, str)]
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
                    "content": self._build_deepseek_selection_prompt(
                        selection_request
                    ),
                },
                selection_request.last_user_message,
            ]
        )
        return self._normalize_selection_response(response)

    async def awrap_model_call(self, request: Any, handler: Any) -> Any:
        """
        异步版本的 DeepSeek 工具筛选兼容分支。
        """
        selection_request = self._prepare_selection_request(request)
        if selection_request is None:
            return await handler(request)

        if not self._is_deepseek_compatible_model(selection_request.model):
            return await super().awrap_model_call(request, handler)

        response = await self._aselect_tools_with_deepseek(selection_request)
        modified_request = self._process_selection_response(
            response,
            selection_request.available_tools,
            selection_request.valid_tool_names,
            request,
        )
        return await handler(modified_request)
