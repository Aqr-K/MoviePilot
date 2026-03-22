"""LLM模型相关辅助功能"""

from typing import List

from app.core.config import settings
from app.log import logger


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
            if settings.PROXY_HOST:
                # 通过代理使用 Google 的 OpenAI 兼容接口
                from langchain_openai import ChatOpenAI

                return ChatOpenAI(
                    model=settings.LLM_MODEL,
                    api_key=api_key,
                    max_retries=3,
                    base_url="https://generativelanguage.googleapis.com/v1beta/openai",
                    temperature=settings.LLM_TEMPERATURE,
                    streaming=streaming,
                    stream_usage=True,
                    openai_proxy=settings.PROXY_HOST,
                )
            else:
                # 使用 langchain-google-genai 原生接口（v4 API 变更：google_api_key → api_key，max_retries → retries）
                from langchain_google_genai import ChatGoogleGenerativeAI

                return ChatGoogleGenerativeAI(
                    model=settings.LLM_MODEL,
                    api_key=api_key,
                    retries=3,
                    temperature=settings.LLM_TEMPERATURE,
                    streaming=streaming
                )
        elif provider == "deepseek":
            from langchain_deepseek import ChatDeepSeek

            return ChatDeepSeek(
                model=settings.LLM_MODEL,
                api_key=api_key,
                max_retries=3,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                stream_usage=True,
            )
        else:
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(
                model=settings.LLM_MODEL,
                api_key=api_key,
                max_retries=3,
                base_url=settings.LLM_BASE_URL,
                temperature=settings.LLM_TEMPERATURE,
                streaming=streaming,
                stream_usage=True,
                openai_proxy=settings.PROXY_HOST,
            )

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

            client = genai.Client(api_key=api_key)
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
