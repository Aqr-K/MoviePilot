# -*- coding: utf-8 -*-
import re
from typing import Optional, Tuple

from app.modules.indexer.parser import SiteParserBase, SiteSchema
from app.utils.string import StringUtils
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class ZhixingSiteUserInfo(SiteParserBase):
    schema = SiteSchema.Zhixing

    def _parse_site_page(self, html_text: str):
        """
        获取站点页面地址
        """
        self._user_basic_page = "user/{uid}/"
        self._user_detail_page = None
        self._user_basic_params = {}
        self._user_traffic_page = None
        self._sys_mail_unread_page = None
        self._user_mail_unread_page = None
        self._mail_unread_params = {}
        self._torrent_seeding_page = "user/{uid}/seeding"
        self._torrent_seeding_params = {}
        self._torrent_seeding_headers = {}
        self._addition_headers = {}

    def _parse_logged_in(self, html_text):
        """
        判断是否登录成功, 通过判断是否存在用户信息
        """
        soup = BeautifulSoup(html_text, 'html.parser')
        return bool(soup.find(id='um'))

    def _parse_user_base_info(self, html_text: str):
        """
        解析用户基本信息，这里把_parse_user_traffic_info和_parse_user_detail_info合并到这里
        """
        if not html_text:
            return None
        soup = BeautifulSoup(html_text, 'html.parser')
        details_tabs = soup.find_all('div', class_='user-details-tabs')
        info_dict = {}
        for tab in details_tabs:
            for p in tab.find_all('p'):
                text = p.text.strip()
                if '：' in text:
                    parts = text.split('：', 1)
                elif ':' in text:
                    parts = text.split(':', 1)
                else:
                    continue
                if len(parts) == 2:
                    key = parts[0].strip()
                    value_text = parts[1].strip()
                    value = re.split(r'\s*\(', value_text)[0].strip().split('查看')[0].strip()
                    info_dict[key] = value

        self.userid = info_dict.get('UID')
        self.username = info_dict.get('用户名')
        self.user_level = info_dict.get('用户组')
        self.join_at = StringUtils.unify_datetime_str(info_dict.get('注册时间')) if '注册时间' in info_dict else None

        def num_filesize_safe(s: str):
            if s:
                s = s.strip()
                if re.match(r'^\d+(\.\d+)?$', s):
                    s += ' B'
            return StringUtils.num_filesize(s) if s else 0

        self.upload = num_filesize_safe(info_dict.get('上传流量')) if '上传流量' in info_dict else 0
        self.download = num_filesize_safe(info_dict.get('下载流量')) if '下载流量' in info_dict else 0
        self.ratio = float(info_dict.get('共享率')) if '共享率' in info_dict else 0
        self.bonus = float(info_dict.get('保种积分')) if '保种积分' in info_dict else 0.0
        self.message_unread = 0  # 暂无消息解析

        self.seeding = int(info_dict.get('当前保种数量')) if '当前保种数量' in info_dict else 0
        self.seeding_size = num_filesize_safe(info_dict.get('当前保种容量')) if '当前保种容量' in info_dict else 0

    def _parse_user_traffic_info(self, html_text: str):
        """
        解析用户流量信息
        """
        pass

    def _parse_user_detail_info(self, html_text: str):
        """
        解析用户详细信息
        """
        pass

    def _parse_user_torrent_seeding_info(self, html_text: str, multi_page: Optional[bool] = False) -> Optional[str]:
        """
        解析用户做种信息
        """
        if not html_text:
            return None
        soup = BeautifulSoup(html_text, 'html.parser')
        torrents = soup.find_all('tr', id=re.compile(r'^t\d+'))
        page_seeding = 0
        page_seeding_size = 0
        for torrent in torrents:
            size_td = torrent.find('td', class_='r')
            if size_td:
                size_text = size_td.find('a').text if size_td.find('a') else size_td.text.strip()
                page_seeding += 1
                page_seeding_size += StringUtils.num_filesize(size_text)

        self.seeding += page_seeding
        self.seeding_size += page_seeding_size

        # 是否存在下页数据
        next_page = None
        # 假设有分页元素，类似 <div class="pager"> 中的 <a href="...?p=2">下一页</a>
        pager = soup.find('div', class_='pager')
        if pager:
            next_link = pager.find('a', string=re.compile('下一页'))
            if next_link:
                next_page = next_link['href']

        return next_page

    def _parse_message_unread_links(self, html_text: str, msg_links: list) -> Optional[str]:
        """
        解析未读消息链接，这里直接读出详情
        """
        pass

    def _parse_message_content(self, html_text) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        解析消息内容
        """
        pass

    def parse(self):
        """
        解析站点信息
        """
        super().parse()
        # 先从首页解析userid
        if self._index_html:
            soup = BeautifulSoup(self._index_html, 'html.parser')
            user_link = soup.find('a', href=re.compile(r'/user/\d+/'))
            if user_link:
                uid_match = re.search(r'/user/(\d+)/', user_link['href'])
                if uid_match:
                    self.userid = uid_match.group(1)
        # 如果有userid，则格式化页面
        if self.userid:
            if self._user_basic_page:
                basic_url = self._user_basic_page.format(uid=self.userid)
                basic_html = self._get_page_content(url=urljoin(self._base_url, basic_url))
                self._parse_user_base_info(basic_html)
            if self._torrent_seeding_page:
                self._torrent_seeding_page = self._torrent_seeding_page.format(uid=self.userid)
