# -*- coding: utf-8 -*-
import json
from typing import Optional, Tuple

from app.log import logger
from app.modules.indexer.parser import SiteParserBase, SiteSchema
from app.utils.string import StringUtils


class RousiSiteUserInfo(SiteParserBase):
    """
    Rousi.pro 站点解析器
    使用 API v1 接口，通过 Passkey (Bearer Token) 进行认证
    """
    schema = SiteSchema.RousiPro
    request_mode = "apikey"

    def _parse_site_page(self, html_text: str):
        """
        配置 API 请求地址和请求头
        使用 API v1 的 /profile 接口获取用户信息
        """
        self._base_url = f"https://{StringUtils.get_url_domain(self._site_url)}"
        self._user_basic_page = "api/v1/profile?include_fields[user]=seeding_leeching_data"
        self._user_basic_params = {}
        self._user_basic_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.apikey}"
        }

        # Rousi.pro API v1 在单个接口返回所有信息，无需额外页面
        self._user_traffic_page = None
        self._user_detail_page = None
        self._torrent_seeding_page = None
        self._user_mail_unread_page = None
        self._sys_mail_unread_page = None

    def _parse_logged_in(self, html_text):
        """
        判断是否登录成功
        API 认证模式下，通过 HTTP 状态码判断，此处始终返回 True
        """
        return True

    def _parse_user_base_info(self, html_text: str):
        """
        解析用户基本信息
        通过 API v1 接口获取用户完整信息，包括上传下载量、做种数据等

        API 响应示例：
        {
            "code": 0,
            "message": "success",
            "data": {
                "id": 1,
                "username": "example",
                "level_text": "Lv.5",
                "registered_at": "2024-01-01T00:00:00Z",
                "uploaded": 1073741824,
                "downloaded": 536870912,
                "ratio": 2.0,
                "karma": 1000.5,
                "seeding_leeching_data": {
                    "seeding_count": 10,
                    "seeding_size": 10737418240,
                    "leeching_count": 2,
                    "leeching_size": 2147483648
                }
            }
        }
        """
        if not html_text:
            return

        try:
            data = json.loads(html_text)
        except json.JSONDecodeError:
            logger.error(f"{self._site_name} JSON 解析失败")
            return

        if not data or data.get("code") != 0:
            self.err_msg = data.get("message", "未知错误")
            logger.warn(f"{self._site_name} API 错误: {self.err_msg}")
            return

        user_info = data.get("data")
        if not user_info:
            return

        # 基本信息
        self.userid = user_info.get("id")
        self.username = user_info.get("username")
        self.user_level = user_info.get("level_text") or user_info.get("role_text")

        # 注册时间：统一格式为 YYYY-MM-DD HH:MM:SS
        join_at = StringUtils.unify_datetime_str(user_info.get("registered_at"))
        if join_at:
            # 确保格式为 YYYY-MM-DD HH:MM:SS (19位)
            if len(join_at) >= 19:
                self.join_at = join_at[:19]
            else:
                self.join_at = join_at

        # 流量信息
        self.upload = int(user_info.get("uploaded") or 0)
        self.download = int(user_info.get("downloaded") or 0)
        self.ratio = round(float(user_info.get("ratio") or 0), 2)

        # 魔力值（站点称为 karma）
        self.bonus = float(user_info.get("karma") or 0)

        # 做种/下载中数据
        sl_data = user_info.get("seeding_leeching_data", {})
        self.seeding = int(sl_data.get("seeding_count") or 0)
        self.seeding_size = int(sl_data.get("seeding_size") or 0)
        self.leeching = int(sl_data.get("leeching_count") or 0)
        self.leeching_size = int(sl_data.get("leeching_size") or 0)

    def _parse_user_traffic_info(self, html_text: str):
        """
        解析用户流量信息
        Rousi.pro API v1 在 _parse_user_base_info 中已完成所有解析，此方法无需实现
        """
        pass

    def _parse_user_detail_info(self, html_text: str):
        """
        解析用户详细信息
        Rousi.pro API v1 在 _parse_user_base_info 中已完成所有解析，此方法无需实现
        """
        pass

    def _parse_user_torrent_seeding_info(self, html_text: str, multi_page: Optional[bool] = False) -> Optional[str]:
        """
        解析用户做种信息
        Rousi.pro API v1 在 _parse_user_base_info 中已通过 seeding_leeching_data 获取做种数据

        :param html_text: 页面内容
        :param multi_page: 是否多页数据
        :return: 下页地址（无下页返回 None）
        """
        return None

    def _parse_message_unread_links(self, html_text: str, msg_links: list) -> Optional[str]:
        """
        解析未读消息链接
        Rousi.pro API v1 暂未提供消息相关接口

        :param html_text: 页面内容
        :param msg_links: 消息链接列表
        :return: 下页地址（无下页返回 None）
        """
        return None

    def _parse_message_content(self, html_text) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        解析消息内容
        Rousi.pro API v1 暂未提供消息相关接口

        :param html_text: 页面内容
        :return: (标题, 日期, 内容)
        """
        return None, None, None
