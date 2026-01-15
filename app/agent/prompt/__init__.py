"""提示词管理器"""
from pathlib import Path
from typing import Dict

from app.log import logger
from app.schemas import ChannelCapability, ChannelCapabilities, MessageChannel, ChannelCapabilityManager


class PromptManager:
    """
    提示词管理器
    """

    def __init__(self, prompts_dir: str = None):
        if prompts_dir is None:
            self.prompts_dir = Path(__file__).parent
        else:
            self.prompts_dir = Path(prompts_dir)
        self.prompts_cache: Dict[str, str] = {}

    def load_prompt(self, prompt_name: str) -> str:
        """
        加载指定的提示词
        """
        if prompt_name in self.prompts_cache:
            return self.prompts_cache[prompt_name]

        prompt_file = self.prompts_dir / prompt_name
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

    def get_agent_prompt(self, channel: str = None) -> str:
        """
        获取智能体提示词
        :param channel: 消息渠道（Telegram、微信、Slack等）
        :return: 提示词内容
        """
        # 基础提示词
        base_prompt = self.load_prompt("Agent Prompt.txt")

        # 识别渠道
        msg_channel = next((c for c in MessageChannel if c.value.lower() == channel.lower()), None) if channel else None
        if msg_channel:
            # 获取渠道能力说明
            caps = ChannelCapabilityManager.get_capabilities(msg_channel)
            if caps:
                base_prompt = base_prompt.replace(
                    "{markdown_spec}",
                    self._generate_formatting_instructions(caps)
                )

        return base_prompt

    @staticmethod
    def _generate_formatting_instructions(caps: ChannelCapabilities) -> str:
        """
        根据渠道能力动态生成格式指令
        """
        instructions = []
        if ChannelCapability.RICH_TEXT not in caps.capabilities:
            instructions.append("- Formatting: Use **Plain Text ONLY**. The channel does NOT support Markdown.")
            instructions.append(
                "- No Markdown Symbols: NEVER use `**`, `*`, `__`, or `[` blocks. Use natural text to emphasize (e.g., using ALL CAPS or separators).")
            instructions.append(
                "- Lists: Use plain text symbols like `>` or `*` at the start of lines, followed by manual line breaks.")
            instructions.append("- Links: Paste URLs directly as text.")
        return "\n".join(instructions)

    def clear_cache(self):
        """
        清空缓存
        """
        self.prompts_cache.clear()
        logger.info("提示词缓存已清空")


prompt_manager = PromptManager()
