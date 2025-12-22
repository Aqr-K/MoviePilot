import re
from typing import Optional, List, Dict

from app.core.config import settings
from app.core.context import MediaInfo, Context
from app.core.metainfo import MetaInfo
from app.helper.image import ImageHelper
from app.log import logger
from app.utils.http import RequestUtils
from app.utils.string import StringUtils


class Discord:
    """
    Discord Webhook通知实现
    """
    _webhook_url: Optional[str] = None
    _username: Optional[str] = None
    _avatar_url: Optional[str] = None

    def __init__(self, DISCORD_WEBHOOK_URL: Optional[str] = None,
                 DISCORD_USERNAME: Optional[str] = None,
                 DISCORD_AVATAR_URL: Optional[str] = None, **kwargs):
        """
        初始化Discord webhook客户端
        :param DISCORD_WEBHOOK_URL: Discord webhook URL
        :param DISCORD_USERNAME: 自定义webhook消息的用户名
        :param DISCORD_AVATAR_URL: 自定义webhook消息的头像URL
        """
        if not DISCORD_WEBHOOK_URL:
            logger.error("Discord webhook URL未配置！")
            return

        self._webhook_url = DISCORD_WEBHOOK_URL
        self._username = DISCORD_USERNAME or "MoviePilot"
        self._avatar_url = DISCORD_AVATAR_URL

    def get_state(self) -> bool:
        """
        获取服务状态
        :return: Webhook URL已配置则返回True
        """
        return self._webhook_url is not None

    def send_msg(self, title: str, text: Optional[str] = None, image: Optional[str] = None,
                 userid: Optional[str] = None, link: Optional[str] = None,
                 buttons: Optional[List[List[dict]]] = None,
                 original_message_id: Optional[int] = None,
                 original_chat_id: Optional[str] = None) -> Optional[bool]:
        """
        通过webhook发送Discord消息
        :param title: 消息标题
        :param text: 消息内容
        :param image: 消息图片URL
        :param userid: 用户ID（webhook不使用）
        :param link: 跳转链接
        :param buttons: 按钮列表（基础webhook不支持）
        :param original_message_id: 原消息ID（不支持编辑）
        :param original_chat_id: 原聊天ID（不支持编辑）
        :return: 成功或失败
        """
        if not self._webhook_url:
            return None

        if not title and not text:
            logger.warn("标题和内容不能同时为空")
            return False

        try:
            # 解析消息内容，构建 fields 数组
            fields = []
            converted_text = '  '

            if text:
                # 按逗号分割消息内容
                lines = text.splitlines()
                # 遍历每行内容
                for line in lines:
                    # 将每行内容按冒号分割为字段名称和值
                    if '：' not in line:
                        converted_text = line
                    else:
                        name, value = line.split('：', 1)
                        # 创建一个字典表示一个 field
                        field = {
                            "name": name.strip(),
                            "value": value.strip(),
                            "inline": False
                        }
                        # 将 field 添加到 fields 列表中
                        fields.append(field)

            # 构建 embed
            embed = {
                "title": title,
                "url": link if link else "https://github.com/jxxghp/MoviePilot",
                "color": 15258703,
                "description": converted_text if converted_text else text,
                "fields": fields
            }

            # 添加图片
            if image:
                # 获取并验证图片
                image_content = ImageHelper().fetch_image(image)
                if image_content:
                    embed["image"] = {
                        "url": image
                    }
                else:
                    logger.warn(f"获取图片失败: {image}，将不带图片发送")

            # 构建payload
            payload = {
                "username": self._username,
                "embeds": [embed]
            }

            # 添加自定义头像
            if self._avatar_url:
                payload["avatar_url"] = self._avatar_url

            # 发送webhook请求
            response = RequestUtils(
                timeout=10,
                content_type="application/json"
            ).post_res(
                url=self._webhook_url,
                json=payload
            )

            if response and response.status_code == 204:
                # logger.info("Discord消息发送成功")
                return True
            else:
                logger.error(f"Discord消息发送失败: {response.status_code if response else 'No response'}")
                return False

        except Exception as e:
            logger.error(f"发送Discord消息时出现异常: {str(e)}")
            return False


    def stop(self):
        """
        停止Discord服务（webhook无需清理）
        """
        pass
