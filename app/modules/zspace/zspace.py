import json
from typing import Any, Generator, List, Optional, Tuple, Union

from app import schemas
from app.log import logger
from app.modules.emby.emby import Emby
from app.utils.http import RequestUtils
from app.utils.url import UrlUtils


class ZSpace(Emby):
    _password: Optional[str] = None

    def __init__(self, host: Optional[str] = None, username: Optional[str] = None,
                 password: Optional[str] = None, play_host: Optional[str] = None,
                 sync_libraries: list = None, **kwargs):
        if not host or not username or not password:
            logger.error("极影视服务器配置不完整！")
            return
        self._host = host
        if self._host:
            self._host = UrlUtils.standardize_base_url(self._host)
        self._playhost = play_host
        if self._playhost:
            self._playhost = UrlUtils.standardize_base_url(self._playhost)
        self._username = username
        self._password = password
        self._apikey = None
        self.user = None
        self.folders = []
        self.serverid = None
        self._sync_libraries = sync_libraries or []
        if not self.reconnect():
            logger.error(f"请检查极影视服务端地址 {host}")

    def is_inactive(self) -> bool:
        """
        判断是否需要重连
        """
        if not self._host or not self._username or not self._password:
            return False
        if not self._apikey or not self.user:
            return True
        current_user = self.__get_current_user()
        if not current_user:
            return True
        self.user = current_user.get("Id") or self.user
        return False

    def reconnect(self) -> bool:
        """
        重连
        """
        token, user_id = self.__login(self._username, self._password)
        if not token:
            self._apikey = None
            self.user = None
            self.folders = []
            self.serverid = None
            return False
        self._apikey = token
        if not user_id:
            current_user = self.__get_current_user()
            if not current_user:
                self._apikey = None
                self.user = None
                self.folders = []
                self.serverid = None
                return False
            user_id = current_user.get("Id")
        self.user = user_id
        self.folders = self.get_emby_folders()
        self.serverid = self.get_server_id()
        return True

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """
        用户认证
        :param username: 用户名
        :param password: 密码
        :return: 认证token
        """
        token, _ = self.__login(username, password)
        if token:
            logger.info(f"用户 {username} 极影视认证成功")
        return token

    def get_user(self, user_name: Optional[str] = None) -> Optional[Union[str, int]]:
        """
        获取用户ID。
        极影视使用登录态 token 时，不一定总能枚举全部用户，失败时回退当前登录用户。
        """
        if user_name and user_name == self._username and self.user:
            return self.user
        user_id = super().get_user(user_name)
        if user_id:
            return user_id
        current_user = self.__get_current_user()
        if current_user:
            current_user_id = current_user.get("Id")
            current_user_name = current_user.get("Name")
            if current_user_id:
                self.user = current_user_id
            if not user_name or user_name == current_user_name:
                return current_user_id
        return self.user

    def get_user_count(self) -> int:
        """
        获取用户数量。
        无法枚举用户时，至少返回当前登录用户数量。
        """
        count = super().get_user_count()
        if count:
            return count
        return 1 if self.user else 0

    def get_librarys(self, username: Optional[str] = None,
                     hidden: Optional[bool] = False) -> List[schemas.MediaServerLibrary]:
        """
        获取媒体服务器所有媒体库列表
        """
        libraries = super().get_librarys(username=username, hidden=hidden)
        for library in libraries or []:
            library.server = "zspace"
            library.server_type = "zspace"
        return libraries

    def get_movies(self, title: str, year: Optional[str] = None,
                   tmdb_id: Optional[int] = None) -> Optional[List[schemas.MediaServerItem]]:
        """
        根据标题和年份，检查电影是否在极影视中存在，存在则返回列表
        """
        movies = super().get_movies(title=title, year=year, tmdb_id=tmdb_id)
        for movie in movies or []:
            movie.server = "zspace"
        return movies

    def get_iteminfo(self, itemid: str) -> Optional[schemas.MediaServerItem]:
        """
        获取单个项目详情
        """
        item = super().get_iteminfo(itemid)
        if item:
            item.server = "zspace"
        return item

    def get_items(self, parent: Union[str, int], start_index: Optional[int] = 0,
                  limit: Optional[int] = -1) -> Generator[schemas.MediaServerItem, Any, None]:
        """
        获取媒体服务器项目列表
        """
        for item in super().get_items(parent=parent, start_index=start_index, limit=limit) or []:
            if item:
                item.server = "zspace"
                yield item

    def get_webhook_message(self, form: Any, args: dict) -> Optional[schemas.WebhookEventInfo]:
        """
        解析极影视 Webhook 报文
        """
        event_item = super().get_webhook_message(form, args)
        if event_item:
            event_item.channel = "zspace"
        return event_item

    def get_resume(self, num: Optional[int] = 12,
                   username: Optional[str] = None) -> Optional[List[schemas.MediaServerPlayItem]]:
        """
        获得继续观看
        """
        items = super().get_resume(num=num, username=username)
        for item in items or []:
            item.server_type = "zspace"
        return items

    def get_latest(self, num: Optional[int] = 20,
                   username: Optional[str] = None) -> Optional[List[schemas.MediaServerPlayItem]]:
        """
        获得最近更新
        """
        items = super().get_latest(num=num, username=username)
        for item in items or []:
            item.server_type = "zspace"
        return items

    def __login(self, username: Optional[str], password: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """
        使用用户名密码登录极影视，返回访问令牌和用户ID
        """
        if not self._host or not username or not password:
            return None, None
        url = f"{self._host}emby/Users/AuthenticateByName"
        try:
            res = RequestUtils(headers={
                'X-Emby-Authorization': 'MediaBrowser Client="MoviePilot", '
                                         'Device="requests", '
                                         'DeviceId="1", '
                                         'Version="1.0.0"',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }).post_res(
                url=url,
                data=json.dumps({
                    "Username": username,
                    "Pw": password
                })
            )
            if res:
                result = res.json() or {}
                token = result.get("AccessToken")
                user_id = result.get("User", {}).get("Id")
                if token:
                    return token, user_id
            else:
                logger.error("Users/AuthenticateByName 未获取到返回数据")
        except Exception as e:
            logger.error(f"连接Users/AuthenticateByName出错：{e}")
        return None, None

    def __get_current_user(self) -> Optional[dict]:
        """
        获取当前登录用户信息
        """
        if not self._host or not self._apikey:
            return None
        url = f"{self._host}emby/Users/Me"
        params = {
            "api_key": self._apikey
        }
        try:
            res = RequestUtils().get_res(url, params)
            if res:
                return res.json()
            logger.error("Users/Me 未获取到返回数据")
        except Exception as e:
            logger.error(f"连接Users/Me出错：{e}")
        return None
