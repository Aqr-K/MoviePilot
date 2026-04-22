"""LLM模型相关辅助功能"""

import asyncio
import inspect
import time
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


class LLMHelper:
    """LLM模型相关辅助功能"""

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
    def _build_disabled_thinking_kwargs(
        cls,
        provider: str,
        model: str | None,
        disable_thinking: bool | None = None,
    ) -> dict[str, Any]:
        """
        按 provider/model 生成“禁用思考”相关参数。

        优先使用 LangChain/OpenAI SDK 已支持的原生字段；仅在 provider
        明确要求自定义请求体时，才回退到 extra_body。
        """
        if not cls._should_disable_thinking(disable_thinking):
            return {}

        provider_name = (provider or "").strip().lower()
        model_name = cls._normalize_model_name(model)
        if not model_name:
            return {}

        # Moonshot Kimi K2.5/K2.6 需要在请求体显式声明 thinking.disabled。
        if model_name.startswith(("kimi-k2.5", "kimi-k2.6")):
            return {"extra_body": {"thinking": {"type": "disabled"}}}

        # OpenAI 原生推理模型优先走 LangChain 内置 reasoning_effort。
        if provider_name == "openai" and model_name.startswith(
            ("gpt-5", "o1", "o3", "o4")
        ):
            return {"reasoning_effort": "none"}

        # Gemini 使用 google-genai / langchain-google-genai 内置思考控制参数。
        if provider_name == "google":
            if "gemini-2.5" in model_name:
                return {
                    "thinking_budget": 0,
                    "include_thoughts": False,
                }
            if "gemini-3" in model_name:
                return {
                    "thinking_level": "minimal",
                    "include_thoughts": False,
                }

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
        disable_thinking: bool | None = None,
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
        thinking_kwargs = LLMHelper._build_disabled_thinking_kwargs(
            provider=provider_name,
            model=model_name,
            disable_thinking=disable_thinking,
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

            model = ChatDeepSeek(
                model=model_name,
                api_key=api_key_value,
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
        disable_thinking: bool | None = None,
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
            disable_thinking=disable_thinking,
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
