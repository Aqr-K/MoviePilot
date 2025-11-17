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
        base_prompt = self.load_prompt("Agent Prompt.txt")
        
        # 根据渠道添加特定的格式说明
        if channel:
            channel_format_info = self._get_channel_format_info(channel)
            if channel_format_info:
                base_prompt += f"\n\n## Current Message Channel Format Requirements\n\n{channel_format_info}"
        
        return base_prompt
    
    @staticmethod
    def _get_channel_format_info(channel: str) -> str:
        """
        获取渠道特定的格式说明
        :param channel: 消息渠道
        :return: 格式说明文本
        """
        channel_lower = channel.lower() if channel else ""
        
        if "telegram" in channel_lower:
            return """Messages are being sent through the **Telegram** channel. You must follow these format requirements:

**Supported Formatting:**
- **Bold text**: Use `*text*` (single asterisk, not double asterisks)
- **Italic text**: Use `_text_` (underscore)
- **Code**: Use `` `text` `` (backtick)
- **Links**: Use `[text](url)` format
- **Strikethrough**: Use `~text~` (tilde)

**IMPORTANT - Headings and Lists:**
- **DO NOT use heading syntax** (`#`, `##`, `###`) - Telegram MarkdownV2 does NOT support it
- **Instead, use bold text for headings**: `*Heading Text*` followed by a blank line
- **DO NOT use list syntax** (`-`, `*`, `+` at line start) - these will be escaped and won't display as lists
- **For lists**, use plain text with line breaks, or use bold for list item labels: `*Item 1:* description`

**Examples:**
- ❌ Wrong heading: `# Main Title` or `## Subtitle`
- ✅ Correct heading: `*Main Title*` (followed by blank line) or `*Subtitle*` (followed by blank line)
- ❌ Wrong list: `- Item 1` or `* Item 2`
- ✅ Correct list format: `*Item 1:* description` or use plain text with line breaks

**Special Characters:**
- Avoid using special characters that need escaping in MarkdownV2: `_*[]()~`>#+-=|{}.!` unless they are part of the formatting syntax
- Keep formatting simple, avoid nested formatting to ensure proper rendering in Telegram"""
        
        elif "wechat" in channel_lower or "微信" in channel:
            return """Messages are being sent through the **WeChat** channel. Please follow these format requirements:

- WeChat does NOT support Markdown formatting. Use plain text format only.
- Do NOT use any Markdown syntax (such as `**bold**`, `*italic*`, `` `code` `` etc.)
- Use plain text descriptions. You can organize content using line breaks and punctuation
- Links can be provided directly as URLs, no Markdown link format needed
- Keep messages concise and clear, use natural Chinese expressions"""
        
        elif "slack" in channel_lower:
            return """Messages are being sent through the **Slack** channel. Please follow these format requirements:

- Slack supports Markdown formatting
- Use `*text*` for bold
- Use `_text_` for italic
- Use `` `text` `` for code
- Link format: `<url|text>` or `[text](url)`"""
        
        # 其他渠道使用标准Markdown
        return None

    def clear_cache(self):
        """清空缓存"""
        self.prompts_cache.clear()
        logger.info("提示词缓存已清空")
