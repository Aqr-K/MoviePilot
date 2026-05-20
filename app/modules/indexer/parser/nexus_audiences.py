# -*- coding: utf-8 -*-
import json
import re
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from lxml import etree

from app.modules.indexer.parser import SiteSchema
from app.modules.indexer.parser.nexus_php import NexusPhpSiteUserInfo
from app.utils.string import StringUtils


class NexusAudiencesSiteUserInfo(NexusPhpSiteUserInfo):
    schema = SiteSchema.NexusAudiences

    def __init__(self, *args, **kwargs):
        """
        初始化 Audiences 未读私信列表地址，第一页不能携带 page 参数。
        """
        super().__init__(*args, **kwargs)
        self._user_mail_unread_page = self.__build_unread_mailbox_page(box=1)
        self._sys_mail_unread_page = self.__build_unread_mailbox_page(box=-2)

    def _parse_message_unread(self, html_text):
        """
        解析 Audiences 新版顶部用户栏中的未读消息数。
        """
        html = etree.HTML(html_text)
        try:
            if not StringUtils.is_valid_html_element(html):
                super()._parse_message_unread(html_text)
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

        super()._parse_message_unread(html_text)

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
            next_page = self.__parse_next_message_page(html)
        finally:
            if html is not None:
                del html

        return next_page

    @classmethod
    def __build_unread_mailbox_page(cls, box: int) -> str:
        """
        构造 Audiences 未读私信列表首页地址。
        """
        return f"messages.php?action=viewmailbox&box={box}&unread=yes"

    @classmethod
    def __parse_next_message_page(cls, html) -> Optional[str]:
        """
        解析 Audiences 新版分页中的下一页链接，兼容图标按钮和英文无障碍标签。
        """
        next_pages = []
        for link in html.xpath('//a[@href]'):
            if cls.__is_next_message_page_link(link):
                next_pages.append(cls.__normalize_message_page_link(link.get("href").strip()))
        if next_pages:
            return next_pages[-1]

        return cls.__parse_next_numeric_message_page(html)

    @classmethod
    def __parse_next_numeric_message_page(cls, html) -> Optional[str]:
        """
        从数字分页中推断下一页，兼容只展示页码按钮的私信列表。
        """
        current_page = None
        page_links = []
        for link in html.xpath('//a[@href]'):
            page = cls.__extract_message_page(link.get("href"))
            if page is None:
                continue
            page_links.append((page, link.get("href").strip()))
            if cls.__is_current_page_link(link):
                current_page = page

        if current_page is None:
            current_page = cls.__extract_current_page_from_markup(html)
        if current_page is None or not page_links:
            return None

        next_links = [(page, href) for page, href in page_links if page > current_page]
        if not next_links:
            return None

        _, next_link = sorted(next_links, key=lambda item: item[0])[0]
        return cls.__normalize_message_page_link(next_link)

    @staticmethod
    def __is_next_message_page_link(link) -> bool:
        """
        判断分页链接是否指向下一页，避免只识别中文“下一页”文本。
        """
        link_class = f" {link.get('class') or ''} ".lower()
        if any(flag in link_class for flag in (" disabled ", " disable ", " inactive ")):
            return False

        link_text = re.sub(r"\s+", " ", link.xpath("string(.)") or "").strip().lower()
        title = (link.get("title") or "").strip().lower()
        aria_label = (link.get("aria-label") or "").strip().lower()
        rel = (link.get("rel") or "").strip().lower()
        signal_text = " ".join([link_text, title, aria_label, rel])
        if any(keyword in signal_text for keyword in ("下一页", "下一頁", "next")):
            return True

        if link_text in {">", "›", "»"}:
            return True

        return any(flag in link_class for flag in (" next ", " pager-next ", " page-next "))

    @classmethod
    def __extract_message_page(cls, href: str) -> Optional[int]:
        """
        从 Audiences 私信分页链接中提取页码。
        """
        if not href:
            return None

        query_params = dict(parse_qsl(urlsplit(href).query, keep_blank_values=True))
        if query_params.get("action") != "viewmailbox":
            return None
        return StringUtils.str_int(query_params.get("page"))

    @staticmethod
    def __is_current_page_link(link) -> bool:
        """
        判断页码链接是否表示当前页。
        """
        link_class = f" {link.get('class') or ''} ".lower()
        parent_class = f" {link.getparent().get('class') or ''} ".lower() if link.getparent() is not None else ""
        aria_current = (link.get("aria-current") or "").strip().lower()
        current_flags = (" active ", " current ", " selected ")
        return aria_current == "page" or any(flag in link_class or flag in parent_class for flag in current_flags)

    @staticmethod
    def __extract_current_page_from_markup(html) -> Optional[int]:
        """
        从非链接的当前页标记中提取 Audiences 的 page 参数值。
        """
        current_texts = html.xpath(
            '//*[contains(concat(" ", normalize-space(@class), " "), " active ") '
            'or contains(concat(" ", normalize-space(@class), " "), " current ") '
            'or contains(concat(" ", normalize-space(@class), " "), " selected ") '
            'or @aria-current="page"]/text()'
        )
        for current_text in current_texts:
            page_match = re.search(r"\d+", str(current_text))
            if page_match:
                # Audiences 页码展示从 1 开始，但 URL 中 page=1 表示第二页。
                return max(StringUtils.str_int(page_match.group()) - 1, 0)
        return None

    @classmethod
    def __normalize_message_page_link(cls, href: str) -> str:
        """
        给翻页链接补齐未读过滤，避免后续页退回站点完整收件箱。
        """
        if not href:
            return href

        url_info = urlsplit(href)
        query_params = dict(parse_qsl(url_info.query, keep_blank_values=True))
        if query_params.get("action") != "viewmailbox":
            return href

        query_params.setdefault("unread", "yes")
        return urlunsplit(
            (
                url_info.scheme,
                url_info.netloc,
                url_info.path,
                urlencode(query_params),
                url_info.fragment,
            )
        )

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
