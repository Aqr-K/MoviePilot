"""LLM模型相关辅助功能"""
from typing import List

from app.log import logger


class LLMHelper:
    """LLM模型相关辅助功能"""

    def get_models(self, provider: str, api_key: str, base_url: str = None) -> List[str]:
        """获取模型列表"""
        logger.info(f"获取 {provider} 模型列表...")
        if provider == "google":
            return self._get_google_models(api_key)
        else:
            return self._get_openai_compatible_models(provider, api_key, base_url)

    def _get_google_models(self, api_key: str) -> List[str]:
        """获取Google模型列表"""
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            models = genai.list_models()
            return [m.name for m in models if 'generateContent' in m.supported_generation_methods]
        except Exception as e:
            logger.error(f"获取Google模型列表失败：{e}")
            raise e

    def _get_openai_compatible_models(self, provider: str, api_key: str, base_url: str = None) -> List[str]:
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
