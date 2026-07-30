import pickle
import time
import traceback
from pathlib import Path
from threading import RLock
from typing import Any, Optional

from app.core.cache import TTLCache
from app.core.config import settings
from app.core.meta import MetaBase
from app.log import logger
from app.schemas.types import MediaType
from app.utils.singleton import WeakSingleton

lock = RLock()


class TmdbCache(metaclass=WeakSingleton):
    """
    TMDB缓存数据
    {
        "id": '',
        "title": '',
        "year": '',
        "type": MediaType
    }
    """
    # TMDB缓存过期
    _tmdb_cache_expire: bool = True
    # 条目写入时间字段，用于重启后按剩余时间恢复 TTL 而不是重新计时
    WRITE_TIME_FIELD = "__cached_at__"

    def __init__(self):
        """初始化 TMDB 识别缓存并恢复本地持久化数据。"""
        self.maxsize = settings.CONF.douban
        self.ttl = settings.CONF.meta
        self.region = "__tmdb_cache__"
        self._meta_filepath = settings.TEMP_PATH / self.region
        # 初始化缓存
        self._cache = TTLCache(region=self.region, maxsize=self.maxsize, ttl=self.ttl)
        # 非Redis加载本地缓存数据
        if not self._cache.is_redis():
            for key, value in self.__load(self._meta_filepath).items():
                # 按写入时间扣减剩余存活时间，否则落盘条目每次重启都会重新计时，
                # 相当于永不过期
                remaining = self.__remaining_ttl(value)
                if remaining is not None and remaining <= 0:
                    continue
                self._cache.set(key, value, ttl=remaining)

    def __remaining_ttl(self, value: Any) -> Optional[int]:
        """
        计算落盘条目的剩余存活时间。
        :param value: 缓存值
        :return: 剩余秒数；条目没有写入时间戳（旧版本落盘数据）时返回 None，按默认 TTL 处理
        """
        if not isinstance(value, dict):
            return None
        cached_at = value.get(self.WRITE_TIME_FIELD)
        if not cached_at:
            return None
        return int(self.ttl - (time.time() - cached_at))

    def clear(self):
        """
        清空所有TMDB缓存
        """
        with lock:
            self._cache.clear()
            self.save(force=True)

    def list_items(self) -> list[dict]:
        """
        返回可供管理界面展示的 TMDB 识别缓存列表。
        """
        with lock:
            cache_items = []
            for key, value in self._cache.items():
                if not isinstance(value, dict):
                    continue
                media_type = value.get("type")
                if not isinstance(media_type, MediaType):
                    try:
                        media_type = MediaType(media_type)
                    except (TypeError, ValueError):
                        media_type = None
                cache_items.append({
                    "key": key,
                    "tmdb_id": value.get("id") or 0,
                    "title": value.get("title") or "",
                    "year": value.get("year") or "",
                    "media_type": media_type.to_agent() if media_type else "unknown",
                    "poster_path": value.get("poster_path") or "",
                    "backdrop_path": value.get("backdrop_path") or "",
                })
            return sorted(cache_items, key=lambda item: item["key"])

    @staticmethod
    def __get_key(meta: MetaBase) -> str:
        """
        获取缓存KEY
        """
        return f"[{meta.type.value if meta.type else '未知'}][{settings.TMDB_LOCALE}]{meta.tmdbid or meta.name}-{meta.year}-{meta.begin_season}"

    @staticmethod
    def __is_type_conflicted(meta: MetaBase, media_type: Any, tmdb_id: Any) -> bool:
        """
        判断媒体类型是否与元数据声明的类型冲突。

        只有「元数据判定为电视剧、结果却是电影」才算冲突。反向不算：名称识别在
        电影分支查不到时会回退到电视剧查询，识别缓存正是用来记住这个纠正结果，
        一律要求 key 与 value 类型一致会让这类条目每次都被丢弃、反复回源。而电视
        剧分支恒定写入电视剧类型，`[电视剧]` 键下出现电影只可能来自 tmdbid 消歧
        或共享识别回填的脏写，会让整季剧集被当成电影反复整理失败。
        :param meta: 元数据
        :param media_type: 待校验的媒体类型
        :param tmdb_id: 对应的 TMDB ID，为空表示负缓存，不带类型信息
        :return: 是否冲突
        """
        if meta.type != MediaType.TV or not tmdb_id:
            return False
        if not isinstance(media_type, MediaType):
            try:
                media_type = MediaType(media_type)
            except (TypeError, ValueError):
                return False
        return media_type == MediaType.MOVIE

    def get(self, meta: MetaBase):
        """
        根据KEY值获取缓存值
        """
        key = self.__get_key(meta)

        with lock:
            cache_value = self._cache.get(key)
            if not cache_value or not isinstance(cache_value, dict):
                return {}
            if self.__is_type_conflicted(meta, cache_value.get("type"), cache_value.get("id")):
                # 脏条目不丢弃就会被无限期沿用，正确的识别逻辑永远没有执行机会
                logger.warn(f"识别缓存类型与元数据冲突，已丢弃并重新识别：{key} -> "
                            f"{cache_value.get('title')}({cache_value.get('type')})")
                self._cache.delete(key)
                return {}
            return cache_value

    def delete(self, key: str) -> dict:
        """
        删除缓存信息
        @param key: 缓存key
        @return: 被删除的缓存内容
        """
        with lock:
            redis_data = self._cache.get(key)
            if redis_data:
                self._cache.delete(key)
                self.save(force=True)
                return redis_data
            return {}

    def modify(self, key: str, title: str) -> dict:
        """
        修改缓存信息
        @param key: 缓存key
        @param title: 标题
        @return: 被修改后缓存内容
        """
        with lock:
            redis_data = self._cache.get(key)
            if redis_data:
                redis_data['title'] = title
                self._cache.set(key, redis_data)
                return redis_data
            return {}

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
        except Exception as e:
            logger.error(f'加载缓存失败：{str(e)} - {traceback.format_exc()}')
        return {}

    def update(self, meta: MetaBase, info: dict) -> None:
        """
        新增或更新缓存条目
        """
        key = self.__get_key(meta)
        if info:
            if self.__is_type_conflicted(meta, info.get("media_type"), info.get("id")):
                # 拒绝写入而不是改写键：识别结果照常返回，只是不把矛盾条目留给下一次
                logger.warn(f"识别结果类型与元数据冲突，不写入识别缓存：{key} -> "
                            f"{info.get('title')}({info.get('media_type')})")
                return
            # 缓存标题
            cache_title = info.get("title") \
                if info.get("media_type") == MediaType.MOVIE else info.get("name")
            # 缓存年份
            cache_year = info.get('release_date') \
                if info.get("media_type") == MediaType.MOVIE else info.get('first_air_date')
            if cache_year:
                cache_year = cache_year[:4]

            with lock:
                # 缓存数据
                cache_data = {
                    "id": info.get("id"),
                    "type": info.get("media_type"),
                    "year": cache_year,
                    "title": cache_title,
                    "poster_path": info.get("poster_path"),
                    "backdrop_path": info.get("backdrop_path"),
                    self.WRITE_TIME_FIELD: time.time()
                }
                self._cache.set(key, cache_data)

        elif info is not None:
            # None时不缓存，此时代表网络错误，允许重复请求
            with lock:
                self._cache.set(key, {"id": 0})

    def save(self, force: bool = False) -> None:
        """
        保存缓存数据到文件
        """
        # Redis不需要保存到本地文件
        if self._cache.is_redis():
            return

        # Redis不可用时，保存到本地文件
        meta_data = self.__load(self._meta_filepath)
        # 当前缓存，去除无法识别
        new_meta_data = {k: v for k, v in self._cache.items() if v.get("id")}

        if not force \
                and meta_data.keys() == new_meta_data.keys():
            return

        with open(self._meta_filepath, 'wb') as f:
            pickle.dump(new_meta_data, f, pickle.HIGHEST_PROTOCOL)  # type: ignore

    def __del__(self):
        """实例释放前保存非 Redis 缓存。"""
        self.save()
