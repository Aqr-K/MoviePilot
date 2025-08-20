import pickle
import random
import time
import traceback
from pathlib import Path
from threading import RLock
from typing import Optional

from app.core.config import settings
from app.core.meta import MetaBase
from app.core.metainfo import MetaInfo
from app.helper.redis import RedisHelper
from app.log import logger
from app.schemas.types import MediaType
from app.utils.singleton import WeakSingleton

lock = RLock()

CACHE_EXPIRE_TIMESTAMP_STR = "cache_expire_timestamp"
EXPIRE_TIMESTAMP = settings.CONF.meta


class DoubanCache(metaclass=WeakSingleton):
    """
    豆瓣缓存数据
    {
        "id": '',
        "title": '',
        "year": '',
        "type": MediaType
    }
    """
    # TMDB缓存过期
    _douban_cache_expire: bool = True

    def __init__(self):
        # 初始化Redis缓存助手
        self._redis_helper = None
        if settings.CACHE_BACKEND_TYPE == "redis":
            try:
                self._redis_helper = RedisHelper(redis_url=settings.CACHE_BACKEND_URL)
            except RuntimeError as e:
                logger.warning(f"豆瓣缓存Redis初始化失败，将使用本地缓存: {e}")
                self._redis_helper = None
        # 加载本地缓存数据
        self._meta_path = settings.TEMP_PATH / "__douban_cache__"
        if not self._redis_helper:
            self._meta_data = self.__load(self._meta_path)

    def clear(self):
        """
        清空所有豆瓣缓存
        """
        with lock:
            self._meta_data = {}
            # 如果Redis可用，同时清理Redis缓存
            if self._redis_helper:
                try:
                    self._redis_helper.clear(region="douban_cache")
                    logger.debug("已清理豆瓣Redis缓存")
                except Exception as e:
                    logger.warning(f"清理豆瓣Redis缓存失败: {e}")

    @staticmethod
    def __get_key(meta: MetaBase) -> str:
        """
        获取缓存KEY
        """
        return f"[{meta.type.value if meta.type else '未知'}]" \
               f"{meta.doubanid or meta.name}-{meta.year}-{meta.begin_season}"

    def get(self, meta: MetaBase):
        """
        根据KEY值获取缓存值
        """
        key = self.__get_key(meta)

        if self._redis_helper:
            # 如果Redis可用，从Redis读取
            try:
                redis_data = self._redis_helper.get(key, region="douban_cache")
                return redis_data or {}
            except Exception as e:
                logger.warning(f"从Redis获取豆瓣缓存失败: {e}")
        else:
            # Redis不可用时，从内存缓存读取
            with lock:
                info: dict = self._meta_data.get(key)
                if info:
                    # 检查过期时间
                    expire = info.get(CACHE_EXPIRE_TIMESTAMP_STR)
                    if not expire or int(time.time()) < expire:
                        info[CACHE_EXPIRE_TIMESTAMP_STR] = int(time.time()) + EXPIRE_TIMESTAMP
                        self._meta_data[key] = info
                    elif expire and self._douban_cache_expire:
                        self.delete(key)
                return info or {}
        return {}

    def delete(self, key: str) -> dict:
        """
        删除缓存信息
        @param key: 缓存key
        @return: 被删除的缓存内容
        """
        if self._redis_helper:
            # 如果Redis可用，删除Redis缓存
            try:
                self._redis_helper.delete(key, region="douban_cache")
                return {}
            except Exception as e:
                logger.warning(f"删除豆瓣Redis缓存失败: {e}")
                return {}
        else:
            # Redis不可用时，删除内存缓存
            with lock:
                return self._meta_data.pop(key, {})

    def modify(self, key: str, title: str) -> dict:
        """
        修改缓存信息
        @param key: 缓存key
        @param title: 标题
        @return: 被修改后缓存内容
        """
        if self._redis_helper:
            # 如果Redis可用，修改Redis缓存
            try:
                redis_data = self._redis_helper.get(key, region="douban_cache")
                if redis_data:
                    redis_data['title'] = title
                    self._redis_helper.set(key, redis_data, ttl=EXPIRE_TIMESTAMP, region="douban_cache")
                    return redis_data
            except Exception as e:
                logger.warning(f"修改豆瓣Redis缓存失败: {e}")
            return {}
        else:
            # Redis不可用时，修改内存缓存
            with lock:
                if self._meta_data.get(key):
                    self._meta_data[key]['title'] = title
                    self._meta_data[key][CACHE_EXPIRE_TIMESTAMP_STR] = int(time.time()) + EXPIRE_TIMESTAMP
                return self._meta_data.get(key)

    @staticmethod
    def __load(path: Path) -> dict:
        """
        从文件中加载缓存
        """
        try:
            if path.exists():
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                return data
            return {}
        except Exception as e:
            logger.error(f"加载缓存失败: {str(e)} - {traceback.format_exc()}")
            return {}

    def update(self, meta: MetaBase, info: dict) -> None:
        """
        新增或更新缓存条目
        """
        if info:
            # 缓存标题
            cache_title = info.get("title")
            # 缓存年份
            cache_year = info.get('year')
            # 类型
            if isinstance(info.get('media_type'), MediaType):
                mtype = info.get('media_type')
            elif info.get("type"):
                mtype = MediaType.MOVIE if info.get("type") == "movie" else MediaType.TV
            else:
                meta = MetaInfo(cache_title)
                if meta.begin_season:
                    mtype = MediaType.TV
                else:
                    mtype = MediaType.MOVIE
            # 海报
            poster_path = info.get("pic", {}).get("large")
            if not poster_path and info.get("cover_url"):
                poster_path = info.get("cover_url")
            if not poster_path and info.get("cover"):
                poster_path = info.get("cover").get("url")

            if self._redis_helper:
                # 如果Redis可用，保存到Redis
                cache_data = {
                    "id": info.get("id"),
                    "type": mtype,
                    "year": cache_year,
                    "title": cache_title,
                    "poster_path": poster_path
                }
                try:
                    self._redis_helper.set(self.__get_key(meta), cache_data, ttl=EXPIRE_TIMESTAMP,
                                           region="douban_cache")
                except Exception as e:
                    logger.warning(f"保存豆瓣缓存到Redis失败: {e}")
            else:
                # Redis不可用时，保存到内存缓存
                with lock:
                    cache_data = {
                        "id": info.get("id"),
                        "type": mtype,
                        "year": cache_year,
                        "title": cache_title,
                        "poster_path": poster_path,
                        CACHE_EXPIRE_TIMESTAMP_STR: int(time.time()) + EXPIRE_TIMESTAMP
                    }
                    self._meta_data[self.__get_key(meta)] = cache_data

        elif info is not None:
            # None时不缓存，此时代表网络错误，允许重复请求
            if self._redis_helper:
                try:
                    self._redis_helper.set(self.__get_key(meta), {'id': "0"}, ttl=EXPIRE_TIMESTAMP,
                                           region="douban_cache")
                except Exception as e:
                    logger.warning(f"保存豆瓣缓存到Redis失败: {e}")
            else:
                with lock:
                    self._meta_data[self.__get_key(meta)] = {'id': "0"}

    def save(self, force: Optional[bool] = False) -> None:
        """
        保存缓存数据到文件
        """
        # 如果Redis可用，不需要保存到本地文件
        if self._redis_helper:
            return

        # Redis不可用时，保存到本地文件
        meta_data = self.__load(self._meta_path)
        new_meta_data = {k: v for k, v in self._meta_data.items() if v.get("id")}

        if not force \
                and not self._random_sample(new_meta_data) \
                and meta_data.keys() == new_meta_data.keys():
            return

        with open(self._meta_path, 'wb') as f:
            pickle.dump(new_meta_data, f, pickle.HIGHEST_PROTOCOL)  # noqa

    def _random_sample(self, new_meta_data: dict) -> bool:
        """
        采样分析是否需要保存
        """
        ret = False
        if len(new_meta_data) < 25:
            keys = list(new_meta_data.keys())
            for k in keys:
                info = new_meta_data.get(k)
                expire = info.get(CACHE_EXPIRE_TIMESTAMP_STR)
                if not expire:
                    ret = True
                    info[CACHE_EXPIRE_TIMESTAMP_STR] = int(time.time()) + EXPIRE_TIMESTAMP
                elif int(time.time()) >= expire:
                    ret = True
                    if self._douban_cache_expire:
                        new_meta_data.pop(k)
        else:
            count = 0
            keys = random.sample(sorted(new_meta_data.keys()), 25)
            for k in keys:
                info = new_meta_data.get(k)
                expire = info.get(CACHE_EXPIRE_TIMESTAMP_STR)
                if not expire:
                    ret = True
                    info[CACHE_EXPIRE_TIMESTAMP_STR] = int(time.time()) + EXPIRE_TIMESTAMP
                elif int(time.time()) >= expire:
                    ret = True
                    if self._douban_cache_expire:
                        new_meta_data.pop(k)
                        count += 1
            if count >= 5:
                ret |= self._random_sample(new_meta_data)
        return ret

    def __del__(self):
        self.save()
