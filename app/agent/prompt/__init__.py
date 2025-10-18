"""提示词管理器"""

from pathlib import Path
from typing import Dict

from app.log import logger


class PromptManager:
    """提示词管理器"""

    def __init__(self, prompts_dir: str = None):
        if prompts_dir is None:
            self.prompts_dir = Path(__file__).parent
        else:
            self.prompts_dir = Path(prompts_dir)
        self.prompts_cache: Dict[str, str] = {}

    def load_prompt(self, prompt_name: str) -> str:
        """加载指定的提示词"""
        if prompt_name in self.prompts_cache:
            return self.prompts_cache[prompt_name]

        prompt_file = self.prompts_dir / "definition" / prompt_name

        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()

            # 缓存提示词
            self.prompts_cache[prompt_name] = content

            logger.info(f"提示词加载成功: {prompt_name}，长度：{len(content)} 字符")
            return content

        except FileNotFoundError:
            logger.error(f"提示词文件不存在: {prompt_file}")
            raise
        except Exception as e:
            logger.error(f"加载提示词失败: {prompt_name}, 错误: {e}")
            raise

    def get_agent_prompt(self) -> str:
        """获取智能体提示词"""
        return self.load_prompt("Agent Prompt.txt")

    def clear_cache(self):
        """清空缓存"""
        self.prompts_cache.clear()
        logger.info("提示词缓存已清空")
