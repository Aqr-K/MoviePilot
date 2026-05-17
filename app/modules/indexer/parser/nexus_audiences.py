# -*- coding: utf-8 -*-
import json
import re
from urllib.parse import urljoin

from lxml import etree

from app.modules.indexer.parser import SiteSchema
from app.modules.indexer.parser.nexus_php import NexusPhpSiteUserInfo
from app.utils.string import StringUtils


class NexusAudiencesSiteUserInfo(NexusPhpSiteUserInfo):
    schema = SiteSchema.NexusAudiences

    def _parse_message_unread(self, html_text):
        """
        解析 Audiences 新版顶部用户栏中的未读消息数。
        """
        super()._parse_message_unread(html_text)
        if self.message_unread:
            return

        html = etree.HTML(html_text)
        try:
            if not StringUtils.is_valid_html_element(html):
                return

            message_tools = html.xpath(
                '//a[contains(@class, "site-userbar__compact-tool") and contains(@href, "messages.php") '
                'and (contains(@class, "site-userbar__compact-tool--has-unread") '
                'or .//*[contains(@class, "site-userbar__compact-tool-badge--unread")])]'
                '|//a[contains(@href, "messages.php") '
                'and (contains(@title, "收件箱") or contains(@aria-label, "收件箱"))]'
            )
            for message_link in message_tools:
                unread = self.__parse_inbox_unread(message_link)
                if unread is not None:
                    self.message_unread = unread
                    return
        finally:
            if html is not None:
                del html

    def _parse_message_unread_links(self, html_text: str, msg_links: list):
        """
        解析 Audiences 未读消息链接。
        """
        html = etree.HTML(html_text)
        try:
            if not StringUtils.is_valid_html_element(html):
                return None

            message_links = html.xpath(
                '//tr[.//img[contains(concat(" ", normalize-space(@class), " "), " unreadpm ") '
                'or @alt="Unread" or @title="未读"]]/td/a[contains(@href, "viewmessage")]/@href'
            )
            msg_links.extend(message_links)
            next_page = None
            next_page_text = html.xpath('//a[contains(.//text(), "下一页") or contains(.//text(), "下一頁")]/@href')
            if next_page_text:
                next_page = next_page_text[-1].strip()
        finally:
            if html is not None:
                del html

        return next_page

    def _parse_user_traffic_info(self, html_text):
        """
        解析用户流量信息
        """
        super()._parse_user_traffic_info(html_text)
        self.__parse_userbar_info(html_text)

    def _parse_user_detail_info(self, html_text: str):
        """
        解析用户额外信息
        """
        super()._parse_user_detail_info(html_text)
        self.__parse_userbar_info(html_text)

    def __parse_userbar_info(self, html_text: str):
        """
        解析 Audiences 新版顶部用户栏，覆盖 NexusPHP 通用正则的误判。
        """
        html = etree.HTML(html_text)
        try:
            if not StringUtils.is_valid_html_element(html):
                return

            for user_node in html.xpath('//*[@data-uploader-url or @data-uploader-stats]'):
                self.__parse_user_identity(user_node)
                self.__parse_uploader_stats(user_node.get("data-uploader-stats"))

            # data-uploader-stats 不包含分享率，需从 compact metric 的 class 中读取。
            self.__parse_compact_metric(html, "ratio", "ratio")
            self.__parse_compact_metric(html, "uploaded", "upload")
            self.__parse_compact_metric(html, "downloaded", "download")
            self.__parse_compact_metric(html, "bonus", "bonus")
            self.__parse_compact_metric(html, "active", "active")
        finally:
            if html is not None:
                del html

    def __parse_user_identity(self, user_node):
        """
        从新版用户卡属性中提取用户 ID、用户名和等级。
        """
        user_url = user_node.get("data-uploader-url") or ""
        user_detail = re.search(r"userdetails\.php\?id=(\d+)", user_url)
        if user_detail and user_detail.group(1).strip():
            self.userid = user_detail.group(1).strip()

        username = user_node.get("data-uploader-label")
        if username and username.strip():
            self.username = username.strip()

        user_level = user_node.get("data-uploader-badge")
        if user_level and user_level.strip():
            self.user_level = user_level.strip()

    def __parse_uploader_stats(self, stats_text: str):
        """
        解析 data-uploader-stats 中的结构化流量数据。
        """
        if not stats_text:
            return

        try:
            stats = json.loads(stats_text)
        except (TypeError, ValueError):
            return

        if not isinstance(stats, list):
            return

        for item in stats:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label") or "").strip(" ：:")
            tone = str(item.get("tone") or "").strip()
            value = str(item.get("value") or "").strip()
            self.__set_metric_value(label=label, tone=tone, value=value)

    def __parse_compact_metric(self, html, metric: str, field: str):
        """
        按 compact metric 的 class 读取新版用户栏中的单项数据。
        """
        values = html.xpath(
            f'//*[contains(concat(" ", normalize-space(@class), " "), " site-userbar__compact-metric--{metric} ")]'
            '//span[normalize-space()][last()]/text()'
        )
        if not values:
            values = html.xpath(
                f'//*[contains(concat(" ", normalize-space(@class), " "), " site-userbar__compact-metric--{metric} ")]'
                '/text()'
            )
        if values:
            self.__set_metric_value(field=field, value=values[-1].strip())

    def __set_metric_value(self, value: str, label: str = None, tone: str = None, field: str = None):
        """
        将 Audiences 用户栏指标写入通用用户数据字段。
        """
        if not value:
            return

        metric_key = field or tone or label
        if metric_key in {"uploaded", "上传量", "upload"}:
            self.upload = StringUtils.num_filesize(value)
        elif metric_key in {"downloaded", "下载量", "download"}:
            self.download = StringUtils.num_filesize(value)
        elif metric_key in {"bonus", "爆米花"}:
            self.bonus = StringUtils.str_float(value)
        elif metric_key == "ratio":
            self.ratio = StringUtils.str_float(value)
        elif metric_key in {"active", "活跃"}:
            active_match = re.search(r"↑\s*(\d+)\s*/\s*↓\s*(\d+)", value)
            if active_match:
                self.seeding = StringUtils.str_int(active_match.group(1))
                self.leeching = StringUtils.str_int(active_match.group(2))

    def __parse_inbox_unread(self, message_link):
        """
        从 Audiences 收件箱入口提取未读数。
        """
        inbox_texts = [
            message_link.get("title"),
            message_link.get("aria-label"),
            *message_link.xpath(
                './/*[contains(@class, "site-userbar__compact-tool-badge--unread") '
                'or contains(@class, "site-userbar__compact-tool-badge")]/text()'
            )
        ]

        for inbox_text in inbox_texts:
            unread = self.__extract_inbox_unread(inbox_text)
            if unread is not None:
                return unread

        return None

    @staticmethod
    def __extract_inbox_unread(text: str):
        """
        Audiences 收件箱角标格式为 总数/未读数，例如 1749/172。
        """
        if not text:
            return None

        text = re.sub(r"\s+", " ", text.replace("\xa0", " ")).strip()
        if not text:
            return None

        inbox_count = re.search(r"(?:收件箱\s*)?(\d[\d,]*)\s*/\s*(\d[\d,]*)", text)
        if inbox_count:
            return StringUtils.str_int(inbox_count.group(2))

        single_count = re.search(r"收件箱\s*(\d[\d,]*)", text)
        if single_count:
            return StringUtils.str_int(single_count.group(1))
        return None

    def _parse_seeding_pages(self):
        if not self._torrent_seeding_page:
            return
        self._torrent_seeding_headers = {"Referer": urljoin(self._base_url, self._user_detail_page)}
        html_text = self._get_page_content(
            url=urljoin(self._base_url, self._torrent_seeding_page),
            params=self._torrent_seeding_params,
            headers=self._torrent_seeding_headers
        )
        if not html_text:
            return
        html = etree.HTML(html_text)
        try:
            if not StringUtils.is_valid_html_element(html):
                return
            total_row = html.xpath('//table[@class="table table-bordered"]//tr[td[1][normalize-space()="Total"]]')
            if not total_row:
                return
            seeding_count = total_row[0].xpath('./td[2]/text()')
            seeding_size = total_row[0].xpath('./td[3]/text()')
            self.seeding = StringUtils.str_int(seeding_count[0]) if seeding_count else 0
            self.seeding_size = StringUtils.num_filesize(seeding_size[0].strip()) if seeding_size else 0
        finally:
            if html is not None:
                del html
