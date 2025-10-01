# -*- coding: utf-8 -*-
import json
from typing import Optional, Tuple
import re

from app.modules.indexer.parser import SiteParserBase, SiteSchema
from app.utils.string import StringUtils
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class BitptSiteUserInfo(SiteParserBase):
    schema = SiteSchema.Bitpt

    def _parse_site_page(self, html_text: str):
        """
        获取站点页面地址
        """
        self._user_basic_page = "userdetails.php?uid={uid}"  # uid 需要在解析时替换
        self._user_detail_page = None
        self._user_basic_params = {}
        self._user_traffic_page = None
        self._sys_mail_unread_page = None
        self._user_mail_unread_page = None
        self._mail_unread_params = {}
        self._torrent_seeding_page = "browse.php?t=myseed"
        self._torrent_seeding_params = {
            "st": "2",
            "d": "desc"
        }
        self._torrent_seeding_headers = {}
        self._addition_headers = {}

    def _parse_logged_in(self, html_text):
        """
        判断是否登录成功, 通过判断是否存在用户信息
        """
        soup = BeautifulSoup(html_text, 'html.parser')
        return bool(soup.find(id='userinfotop'))

    def _parse_user_base_info(self, html_text: str):
        """
        解析用户基本信息，这里把_parse_user_traffic_info和_parse_user_detail_info合并到这里
        """
        if not html_text:
            return None
        soup = BeautifulSoup(html_text, 'html.parser')
        table = soup.find('table', class_='frmtable')
        if not table:
            return

        rows = table.find_all('tr')
        info_dict = {}
        for row in rows:
            cells = row.find_all('td')
            if len(cells) == 2:
                key = cells[0].text.strip()
                value = cells[1].text.strip()
                info_dict[key] = value

        self.userid = info_dict.get('UID')
        self.username = info_dict.get('用户名').split('\xa0')[0] if '用户名' in info_dict else None
        self.user_level = info_dict.get('用户级别') if '用户级别' in info_dict else None
        self.join_at = StringUtils.unify_datetime_str(info_dict.get('注册时间')) if '注册时间' in info_dict else None

        self.upload = StringUtils.num_filesize(info_dict.get('上传流量')) if '上传流量' in info_dict else 0
        self.download = StringUtils.num_filesize(info_dict.get('下载流量')) if '下载流量' in info_dict else 0
        self.ratio = float(info_dict.get('共享率')) if '共享率' in info_dict else 0
        bonus_str = info_dict.get('星辰', '')
        self.bonus = float(re.search(r'累计([\d\.]+)', bonus_str).group(1)) if re.search(r'累计([\d\.]+)', bonus_str) else 0
        self.message_unread = 0  # 暂无消息解析

        # 做种信息从页面底部提取
        seeding_info = soup.find('div', style="margin:0 auto;width:90%;font-size:14px;margin-top:10px;margin-bottom:10px;text-align:center;")
        if seeding_info:
            seeding_link = seeding_info.find_all('a')[1].text if len(seeding_info.find_all('a')) > 1 else ''
            match = re.search(r'当前上传的种子\((\d+)个, 共([\d\.]+ [KMGT]B)\)', seeding_link)
            if match:
                self.seeding = int(match.group(1))
                self.seeding_size = StringUtils.num_filesize(match.group(2))
            else:
                self.seeding = 0
                self.seeding_size = 0

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
        torrents = soup.find_all('tr', class_=['btr0', 'btr1'])
        page_seeding = 0
        page_seeding_size = 0
        for torrent in torrents:
            size_td = torrent.find('td', class_='r')
            if size_td:
                size_text = size_td.find('a').text if size_td.find('a') else size_td.text
                page_seeding += 1
                page_seeding_size += StringUtils.num_filesize(size_text)

        self.seeding += page_seeding
        self.seeding_size += page_seeding_size

        # 是否存在下页数据
        pager = soup.find('div', class_='pager')
        next_page = None
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
            user_link = soup.find('a', href=re.compile(r'userdetails\.php\?uid=\d+'))
            if user_link:
                uid_match = re.search(r'uid=(\d+)', user_link['href'])
                if uid_match:
                    self.userid = uid_match.group(1)
        # 如果有userid，则格式化_user_basic_page
        if self.userid and self._user_basic_page:
            basic_url = self._user_basic_page.format(uid=self.userid)
            basic_html = self._get_page_content(url=urljoin(self._base_url, basic_url))
            self._parse_user_base_info(basic_html)