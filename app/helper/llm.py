"""LLM模型相关辅助功能"""

import asyncio
import inspect
import time
from functools import wraps
from typing import Any, List

from app.core.config import settings
from app.log import logger


class LLMTestError(RuntimeError):
    """LLM 测试调用异常，附带请求耗时。"""

    def __init__(self, message: str, duration_ms: int | None = None):
        super().__init__(message)
        self.duration_ms = duration_ms


class LLMTestTimeout(TimeoutError):
    """LLM 测试调用超时，附带请求耗时。"""

    def __init__(self, message: str, duration_ms: int | None = None):
        super().__init__(message)
        self.duration_ms = duration_ms


def _patch_gemini_thought_signature():
    """
    修复 langchain-google-genai 中 Gemini 2.5 思考模型的 thought_signature 兼容问题。
    langchain-google-genai 的 _is_gemini_3_or_later() 仅检查 "gemini-3"，
    导致 Gemini 2.5 思考模型（如 gemini-2.5-flash、gemini-2.5-pro）在工具调用时
    缺少 thought_signature 而报错 400。
    此补丁将检查范围扩展到 Gemini 2.5 模型。
    """
    try:
        import langchain_google_genai.chat_models as _cm

        # 仅在未修补时执行
        if getattr(_cm, "_thought_signature_patched", False):
            return

        def _patched_is_gemini_3_or_later(model_name: str) -> bool:
            if not model_name:
                return False
            name = model_name.lower().replace("models/", "")
            # Gemini 2.5 思考模型也需要 thought_signature 支持
            return "gemini-3" in name or "gemini-2.5" in name

        _cm._is_gemini_3_or_later = _patched_is_gemini_3_or_later
        _cm._thought_signature_patched = True
        logger.debug(
            "已修补 langchain-google-genai thought_signature 兼容性（覆盖 Gemini 2.5 模型）"
        )
    except Exception as e:
        logger.warning(f"修补 langchain-google-genai thought_signature 失败: {e}")


def _get_httpx_proxy_key() -> str:
    """
    获取当前 httpx 版本支持的代理参数名。
    httpx < 0.28 使用 "proxies"（复数），>= 0.28 使用 "proxy"（单数）。
    google-genai SDK 会静默过滤掉不在 httpx.Client.__init__ 签名中的参数，
    因此必须使用与当前 httpx 版本匹配的参数名。
    """
    try:
        import httpx

        params = inspect.signature(httpx.Client.__init__).parameters
        if "proxy" in params:
            return "proxy"
        return "proxies"
    except Exception:
        return "proxies"


def _deepseek_thinking_toggle(extra_body: Any) -> bool | None:
    """
    解析 DeepSeek extra_body 中显式传入的 thinking 开关。
    """
    if not isinstance(extra_body, dict):
        return None

    thinking = extra_body.get("thinking")
    if not isinstance(thinking, dict):
        return None

    thinking_type = str(thinking.get("type") or "").strip().lower()
    if thinking_type == "enabled":
        return True
    if thinking_type == "disabled":
        return False
    return None


def _is_deepseek_thinking_enabled(model_name: str | None, extra_body: Any) -> bool:
    """
    判断本次 DeepSeek 调用是否处于 thinking mode。
    """
    explicit_toggle = _deepseek_thinking_toggle(extra_body)
    if explicit_toggle is not None:
        return explicit_toggle

    normalized_model_name = str(model_name or "").strip().lower()
    if normalized_model_name == "deepseek-reasoner":
        return True
    if normalized_model_name.startswith("deepseek-v4-"):
        # DeepSeek V4 默认启用 thinking mode，除非显式关闭。
        return True
    return False


def _extract_input_messages(input_: Any) -> list[Any]:
    """
    将 chat model 输入还原为原始 BaseMessage 序列。
    """
    try:
        from langchain_core.messages import convert_to_messages

        return list(convert_to_messages(input_))
    except Exception:
        if isinstance(input_, list):
            return list(input_)
        return []


def _patch_deepseek_reasoning_content_support():
    """
    修补 langchain-deepseek 在 tool-call 场景下遗漏 reasoning_content 回传的问题。

    DeepSeek thinking mode 要求：若 assistant 历史消息包含 tool_calls，
    后续请求中必须带回该条消息的顶层 reasoning_content。
    某些 langchain-deepseek 版本虽然能从响应中拿到 reasoning_content，
    但不会在重放消息历史时写回请求载荷，导致 400。
    """
    try:
        from langchain_deepseek import ChatDeepSeek
    except Exception as err:
        logger.debug(f"跳过 langchain-deepseek reasoning_content 修补：{err}")
        return

    if getattr(ChatDeepSeek, "_moviepilot_reasoning_content_patched", False):
        return

    original_get_request_payload = getattr(ChatDeepSeek, "_get_request_payload", None)
    if not callable(original_get_request_payload):
        logger.warning("langchain-deepseek 缺少 _get_request_payload，无法修补 reasoning_content")
        return

    @wraps(original_get_request_payload)
    def _patched_get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = original_get_request_payload(self, input_, stop=stop, **kwargs)

        try:
            original_messages = _extract_input_messages(input_)
            payload_messages = payload.get("messages") or []
            model_name = getattr(self, "model_name", None) or getattr(
                self, "model", None
            )
            extra_body = kwargs.get("extra_body")
            if extra_body is None:
                extra_body = getattr(self, "extra_body", None)
            if extra_body is None:
                extra_body = getattr(self, "model_kwargs", {}).get("extra_body")

            if not _is_deepseek_thinking_enabled(model_name, extra_body):
                return payload

            for index, message in enumerate(payload_messages):
                if not isinstance(message, dict):
                    continue
                if message.get("role") != "assistant":
                    continue
                if not message.get("tool_calls"):
                    continue
                if message.get("reasoning_content") is not None:
                    continue

                reasoning_content = ""
                if index < len(original_messages):
                    additional_kwargs = (
                        getattr(original_messages[index], "additional_kwargs", None)
                        or {}
                    )
                    if isinstance(additional_kwargs, dict):
                        captured_reasoning = additional_kwargs.get("reasoning_content")
                        if isinstance(captured_reasoning, str):
                            reasoning_content = captured_reasoning

                message["reasoning_content"] = reasoning_content
        except Exception as err:
            logger.warning(
                f"修补 langchain-deepseek reasoning_content 请求载荷时失败，将继续使用原始载荷: {err}"
            )

        return payload

    ChatDeepSeek._get_request_payload = _patched_get_request_payload
    ChatDeepSeek._moviepilot_reasoning_content_patched = True
    logger.debug("已修补 langchain-deepseek thinking tool-call 的 reasoning_content 回传兼容性")


class LLMHelper:
    """LLM模型相关辅助功能"""

    _SUPPORTED_THINKING_LEVELS = frozenset(
        {"off", "auto", "minimal", "low", "medium", "high", "max", "xhigh"}
    )

    @staticmethod
    def _should_disable_thinking(disable_thinking: bool | None = None) -> bool:
        """
        判断本次调用是否应尝试关闭模型思考能力。
        """
        if disable_thinking is not None:
            return bool(disable_thinking)
        return bool(getattr(settings, "LLM_DISABLE_THINKING", False))

    @staticmethod
    def _normalize_model_name(model_name: str | None) -> str:
        """
        统一清理模型名称，便于按模型族做能力映射。
        """
        return (model_name or "").strip().lower()

    @classmethod
    def _normalize_thinking_level_value(cls, value: str | None) -> str | None:
        """
        统一清理思考级别/强度值，并兼容常见别名。
        """
        if value is None:
            return None

        normalized = str(value).strip().lower()
        if not normalized:
            return None

        alias_map = {
            "none": "off",
            "disabled": "off",
            "disable": "off",
            "enabled": "auto",
            "enable": "auto",
            "default": "auto",
            "dynamic": "auto",
        }
        return alias_map.get(normalized, normalized)

    @classmethod
    def _normalize_thinking_level(
        cls, thinking_level: str | None = None
    ) -> str | None:
        """
        统一清理 thinking_level 配置。
        """
        value = (
            thinking_level
            if thinking_level is not None
            else getattr(settings, "LLM_THINKING_LEVEL", None)
        )
        normalized = cls._normalize_thinking_level_value(value)
        if not normalized:
            return None

        if normalized not in cls._SUPPORTED_THINKING_LEVELS:
            logger.warning(f"忽略不支持的 thinking_level 配置: {normalized}")
            return None
        return normalized

    @classmethod
    def _normalize_reasoning_effort(
        cls, reasoning_effort: str | None = None
    ) -> str | None:
        """
        统一清理 legacy reasoning_effort 配置。
        """
        value = (
            reasoning_effort
            if reasoning_effort is not None
            else getattr(settings, "LLM_REASONING_EFFORT", None)
        )
        return cls._normalize_thinking_level(value)

    @classmethod
    def _resolve_thinking_level(
        cls,
        thinking_level: str | None = None,
        disable_thinking: bool | None = None,
        reasoning_effort: str | None = None,
    ) -> str:
        """
        统一解析本次调用的思考配置。

        优先级：
        1. 新字段 `thinking_level`
        2. 本次调用传入的 legacy 字段
        3. 已保存的新字段 `LLM_THINKING_LEVEL`
        4. 已保存的 legacy 字段
        """
        explicit_level = cls._normalize_thinking_level(thinking_level)
        if explicit_level:
            return explicit_level

        explicit_effort = (
            cls._normalize_reasoning_effort(reasoning_effort)
            if reasoning_effort is not None
            else None
        )
        if disable_thinking is not None or reasoning_effort is not None:
            if disable_thinking is not None and bool(disable_thinking):
                return "off"
            return explicit_effort or "auto"

        configured_level = cls._normalize_thinking_level(
            getattr(settings, "LLM_THINKING_LEVEL", None)
        )
        if configured_level:
            return configured_level

        legacy_disable = getattr(settings, "LLM_DISABLE_THINKING", None)
        legacy_effort = cls._normalize_reasoning_effort(
            getattr(settings, "LLM_REASONING_EFFORT", None)
        )
        if legacy_disable is not None:
            return "off" if bool(legacy_disable) else (legacy_effort or "auto")

        return legacy_effort or "off"

    @classmethod
    def _normalize_deepseek_reasoning_effort(
        cls, thinking_level: str | None = None
    ) -> str | None:
        """
        DeepSeek 文档当前建议使用 high/max；兼容常见 effort 别名。
        """
        normalized = cls._normalize_thinking_level(thinking_level)
        if not normalized or normalized in {"off", "auto"}:
            return None

        if normalized in {"minimal", "low", "medium", "high"}:
            return "high"
        if normalized in {"max", "xhigh"}:
            return "max"

        logger.warning(f"忽略不支持的 DeepSeek reasoning_effort 配置: {normalized}")
        return None

    @classmethod
    def _normalize_openai_reasoning_effort(
        cls, thinking_level: str | None = None
    ) -> str | None:
        """
        OpenAI reasoning_effort 支持更细粒度的 effort，统一做最近似映射。
        """
        normalized = cls._normalize_thinking_level(thinking_level)
        if not normalized or normalized == "auto":
            return None
        if normalized == "off":
            return "none"
        if normalized == "max":
            return "xhigh"
        return normalized

    @classmethod
    def _build_google_thinking_kwargs(
        cls, model_name: str, thinking_level: str
    ) -> dict[str, Any]:
        """
        Gemini 3 使用 thinking_level；Gemini 2.5 使用 thinking_budget。
        """
        if not model_name or thinking_level == "auto":
            return {}

        if "gemini-2.5" in model_name:
            if thinking_level == "off":
                if "pro" in model_name:
                    # Gemini 2.5 Pro 官方不支持完全关闭思考，回退到最小预算。
                    return {
                        "thinking_budget": 128,
                        "include_thoughts": False,
                    }
                return {
                    "thinking_budget": 0,
                    "include_thoughts": False,
                }

            budget_map = {
                "minimal": 512,
                "low": 1024,
                "medium": 4096,
                "high": 8192,
                "max": 24576,
                "xhigh": 24576,
            }
            budget = budget_map.get(thinking_level)
            return (
                {
                    "thinking_budget": budget,
                    "include_thoughts": False,
                }
                if budget is not None
                else {}
            )

        if "gemini-3" in model_name:
            level_map = {
                "off": "minimal",
                "minimal": "minimal",
                "low": "low",
                "medium": "medium",
                "high": "high",
                "max": "high",
                "xhigh": "high",
            }
            google_level = level_map.get(thinking_level)
            return (
                {
                    "thinking_level": google_level,
                    "include_thoughts": False,
                }
                if google_level
                else {}
            )

        return {}

    @classmethod
    def _build_kimi_thinking_kwargs(
        cls, model_name: str, thinking_level: str
    ) -> dict[str, Any]:
        """
        Kimi 当前公开文档仅支持思考开关，不支持显式深度调节。
        """
        if model_name.startswith("kimi-k2-thinking"):
            return {}
        if thinking_level == "off":
            return {"extra_body": {"thinking": {"type": "disabled"}}}
        return {}

    @classmethod
    def _build_thinking_kwargs(
        cls,
        provider: str,
        model: str | None,
        thinking_level: str | None = None,
        disable_thinking: bool | None = None,
        reasoning_effort: str | None = None,
    ) -> dict[str, Any]:
        """
        按 provider/model 生成思考模式相关参数。

        优先使用 LangChain/OpenAI SDK 已支持的原生字段；仅在 provider
        明确要求自定义请求体时，才回退到 extra_body。
        """
        provider_name = (provider or "").strip().lower()
        model_name = cls._normalize_model_name(model)
        resolved_thinking_level = cls._resolve_thinking_level(
            thinking_level=thinking_level,
            disable_thinking=disable_thinking,
            reasoning_effort=reasoning_effort,
        )

        if provider_name == "deepseek":
            if resolved_thinking_level == "off":
                return {"extra_body": {"thinking": {"type": "disabled"}}}
            if resolved_thinking_level == "auto":
                return {}

            kwargs: dict[str, Any] = {"extra_body": {"thinking": {"type": "enabled"}}}
            deepseek_effort = cls._normalize_deepseek_reasoning_effort(
                resolved_thinking_level
            )
            if deepseek_effort:
                kwargs["reasoning_effort"] = deepseek_effort
            return kwargs

        if model_name.startswith(("kimi-k2.5", "kimi-k2.6", "kimi-k2-thinking")):
            return cls._build_kimi_thinking_kwargs(model_name, resolved_thinking_level)

        if not model_name:
            return {}

        # OpenAI 原生推理模型优先走 LangChain 内置 reasoning_effort。
        if provider_name == "openai" and model_name.startswith(
            ("gpt-5", "o1", "o3", "o4")
        ):
            openai_effort = cls._normalize_openai_reasoning_effort(
                resolved_thinking_level
            )
            return {"reasoning_effort": openai_effort} if openai_effort else {}

        # Gemini 使用 google-genai / langchain-google-genai 内置思考控制参数。
        if provider_name == "google":
            return cls._build_google_thinking_kwargs(
                model_name, resolved_thinking_level
            )

        return {}

    @staticmethod
    def supports_image_input() -> bool:
        """
        判断当前模型是否启用了图片输入能力。
        """
        return bool(settings.LLM_SUPPORT_IMAGE_INPUT)

    @staticmethod
    def get_llm(
        streaming: bool = False,
        provider: str | None = None,
        model: str | None = None,
        thinking_level: str | None = None,
        disable_thinking: bool | None = None,
        reasoning_effort: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        """
        获取LLM实例
        :param streaming: 是否启用流式输出
        :return: LLM实例
        """
        provider_name = str(
            provider if provider is not None else settings.LLM_PROVIDER
        ).lower()
        model_name = model if model is not None else settings.LLM_MODEL
        api_key_value = api_key if api_key is not None else settings.LLM_API_KEY
        base_url_value = base_url if base_url is not None else settings.LLM_BASE_URL
        thinking_kwargs = LLMHelper._build_thinking_kwargs(
            provider=provider_name,
            model=model_name,
            thinking_level=thinking_level,
            disable_thinking=disable_thinking,
            reasoning_effort=reasoning_effort,
        )

        if not api_key_value:
            raise ValueError("未配置LLM API Key")

        if provider_name == "google":
            # 修补 Gemini 2.5 思考模型的 thought_signature 兼容性
            _patch_gemini_thought_signature()

            # 统一使用 langchain-google-genai 原生接口
            # 不使用 OpenAI 兼容端点，因其不支持 Gemini 思考模型的 thought_signature，
            # 会导致工具调用时报错 400
            from langchain_google_genai import ChatGoogleGenerativeAI

            client_args = None
            if settings.PROXY_HOST:
                proxy_key = _get_httpx_proxy_key()
                client_args = {proxy_key: settings.PROXY_HOST}

            model = ChatGoogleGenerativeAI(
                model=model_name,
                api_key=api_key_value,
                retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                client_args=client_args,
                **thinking_kwargs,
            )
        elif provider_name == "deepseek":
            from langchain_deepseek import ChatDeepSeek

            _patch_deepseek_reasoning_content_support()
            model = ChatDeepSeek(
                model=model_name,
                api_key=api_key_value,
                api_base=base_url_value,
                max_retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                stream_usage=True,
                **thinking_kwargs,
            )
        else:
            from langchain_openai import ChatOpenAI

            model = ChatOpenAI(
                model=model_name,
                api_key=api_key_value,
                max_retries=3,
                base_url=base_url_value,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                stream_usage=True,
                openai_proxy=settings.PROXY_HOST,
                **thinking_kwargs,
            )

        # 检查是否有profile
        if hasattr(model, "profile") and model.profile:
            logger.debug(f"使用LLM模型: {model.model}，Profile: {model.profile}")
        else:
            model.profile = {
                "max_input_tokens": settings.LLM_MAX_CONTEXT_TOKENS
                * 1000,  # 转换为token单位
            }

        return model

    @staticmethod
    def _extract_text_content(content) -> str:
        """
        从响应内容中提取纯文本，仅保留真实文本块。
        """
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text_parts = []
            for block in content:
                if isinstance(block, str):
                    text_parts.append(block)
                    continue

                if isinstance(block, dict) or hasattr(block, "get"):
                    block_type = block.get("type")
                    if block.get("thought") or block_type in (
                        "thinking",
                        "reasoning_content",
                        "reasoning",
                        "thought",
                    ):
                        continue
                    if block_type == "text":
                        text_parts.append(block.get("text", ""))
                        continue
                    if not block_type and isinstance(block.get("text"), str):
                        text_parts.append(block.get("text", ""))
            return "".join(text_parts)
        if isinstance(content, dict) or hasattr(content, "get"):
            if content.get("thought"):
                return ""
            if content.get("type") == "text":
                return content.get("text", "")
            if not content.get("type") and isinstance(content.get("text"), str):
                return content.get("text", "")
        return ""

    @staticmethod
    async def test_current_settings(
        prompt: str = "请只回复 OK",
        timeout: int = 20,
        provider: str | None = None,
        model: str | None = None,
        thinking_level: str | None = None,
        disable_thinking: bool | None = None,
        reasoning_effort: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> dict:
        """
        使用当前已保存配置执行一次最小 LLM 调用。
        """
        provider_name = provider if provider is not None else settings.LLM_PROVIDER
        model_name = model if model is not None else settings.LLM_MODEL
        api_key_value = api_key if api_key is not None else settings.LLM_API_KEY
        base_url_value = base_url if base_url is not None else settings.LLM_BASE_URL
        start = time.perf_counter()
        llm = LLMHelper.get_llm(
            streaming=False,
            provider=provider_name,
            model=model_name,
            thinking_level=thinking_level,
            disable_thinking=disable_thinking,
            reasoning_effort=reasoning_effort,
            api_key=api_key_value,
            base_url=base_url_value,
        )
        try:
            response = await asyncio.wait_for(llm.ainvoke(prompt), timeout=timeout)
        except TimeoutError as err:
            duration_ms = round((time.perf_counter() - start) * 1000)
            raise LLMTestTimeout("LLM 调用超时", duration_ms=duration_ms) from err
        except Exception as err:
            duration_ms = round((time.perf_counter() - start) * 1000)
            raise LLMTestError(str(err), duration_ms=duration_ms) from err

        reply_text = LLMHelper._extract_text_content(
            getattr(response, "content", response)
        ).strip()
        duration_ms = round((time.perf_counter() - start) * 1000)

        data = {
            "provider": provider_name,
            "model": model_name,
            "duration_ms": duration_ms,
        }
        if reply_text:
            data["reply_preview"] = reply_text[:120]
        return data

    def get_models(
        self, provider: str, api_key: str, base_url: str = None
    ) -> List[str]:
        """获取模型列表"""
        logger.info(f"获取 {provider} 模型列表...")
        if provider == "google":
            return self._get_google_models(api_key)
        else:
            return self._get_openai_compatible_models(provider, api_key, base_url)

    @staticmethod
    def _get_google_models(api_key: str) -> List[str]:
        """获取Google模型列表（使用 google-genai SDK v1）"""
        try:
            from google import genai
            from google.genai.types import HttpOptions

            http_options = None
            if settings.PROXY_HOST:
                proxy_key = _get_httpx_proxy_key()
                proxy_args = {proxy_key: settings.PROXY_HOST}
                http_options = HttpOptions(
                    client_args=proxy_args,
                    async_client_args=proxy_args,
                )

            client = genai.Client(api_key=api_key, http_options=http_options)
            models = client.models.list()
            return [
                m.name
                for m in models
                if m.supported_actions and "generateContent" in m.supported_actions
            ]
        except Exception as e:
            logger.error(f"获取Google模型列表失败：{e}")
            raise e

    @staticmethod
    def _get_openai_compatible_models(
        provider: str, api_key: str, base_url: str = None
    ) -> List[str]:
        """获取OpenAI兼容模型列表"""
        try:
            from openai import OpenAI

            if provider == "deepseek":
                base_url = base_url or "https://api.deepseek.com"

            client = OpenAI(api_key=api_key, base_url=base_url)
            models = client.models.list()
            return [model.id for model in models.data]
        except Exception as e:
            logger.error(f"获取 {provider} 模型列表失败：{e}")
            raise e
