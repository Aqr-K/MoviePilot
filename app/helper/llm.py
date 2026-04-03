"""LLM模型相关辅助功能"""

import inspect
from typing import List

from app.core.config import settings
from app.log import logger


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
    def get_llm(streaming: bool = False):
        """
        获取LLM实例
        :param streaming: 是否启用流式输出
        :return: LLM实例
        """
        provider = settings.LLM_PROVIDER.lower()
        api_key = settings.LLM_API_KEY

        if not api_key:
            raise ValueError("未配置LLM API Key")

        if provider == "google":
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
                model=settings.LLM_MODEL,
                api_key=api_key,
                retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                client_args=client_args,
            )
        elif provider == "deepseek":
            from langchain_deepseek import ChatDeepSeek

            model = ChatDeepSeek(
                model=settings.LLM_MODEL,
                api_key=api_key,
                max_retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                stream_usage=True,
            )
        else:
            from langchain_openai import ChatOpenAI

            model = ChatOpenAI(
                model=settings.LLM_MODEL,
                api_key=api_key,
                max_retries=3,
                base_url=settings.LLM_BASE_URL,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                stream_usage=True,
                openai_proxy=settings.PROXY_HOST,
            )

        # 检查是否有profile
        if hasattr(model, "profile") and model.profile:
            logger.info(f"使用LLM模型: {model.model}，Profile: {model.profile}")
        else:
            model.profile = {
                "max_input_tokens": settings.LLM_MAX_CONTEXT_TOKENS
                * 1000,  # 转换为token单位
            }

        return model

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
