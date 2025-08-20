import inspect
import threading
from abc import ABC, abstractmethod
from functools import wraps
from typing import Any, Dict, Optional

from cachetools import TTLCache as CacheToolsTTLCache
from cachetools.keys import hashkey

from app.core.config import settings
from app.helper.redis import RedisHelper
from app.log import logger

# 默认缓存区
DEFAULT_CACHE_REGION = "DEFAULT"

lock = threading.Lock()


class CacheBackend(ABC):
    """
    缓存后端基类，定义通用的缓存接口
    """

    @abstractmethod
    def set(self, key: str, value: Any, ttl: int, region: Optional[str] = DEFAULT_CACHE_REGION, **kwargs) -> None:
        """
        设置缓存

        :param key: 缓存的键
        :param value: 缓存的值
        :param ttl: 缓存的存活时间，单位秒
        :param region: 缓存的区
        :param kwargs: 其他参数
        """
        pass

    @abstractmethod
    def exists(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> bool:
        """
        判断缓存键是否存在

        :param key: 缓存的键
        :param region: 缓存的区
        :return: 存在返回 True，否则返回 False
        """
        pass

    @abstractmethod
    def get(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> Any:
        """
        获取缓存

        :param key: 缓存的键
        :param region: 缓存的区
        :return: 返回缓存的值，如果缓存不存在返回 None
        """
        pass

    @abstractmethod
    def delete(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> None:
        """
        删除缓存

        :param key: 缓存的键
        :param region: 缓存的区
        """
        pass

    @abstractmethod
    def clear(self, region: Optional[str] = None) -> None:
        """
        清除指定区域的缓存或全部缓存

        :param region: 缓存的区
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """
        关闭缓存连接
        """
        pass

    @staticmethod
    def get_region(region: Optional[str] = DEFAULT_CACHE_REGION):
        """
        获取缓存的区
        """
        return f"region:{region}" if region else "region:default"

    @staticmethod
    def get_cache_key(func, args, kwargs):
        """
        获取缓存的键，通过哈希函数对函数的参数进行处理
        :param func: 被装饰的函数
        :param args: 位置参数
        :param kwargs: 关键字参数
        :return: 缓存键
        """
        signature = inspect.signature(func)
        # 绑定传入的参数并应用默认值
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        # 忽略第一个参数，如果它是实例(self)或类(cls)
        parameters = list(signature.parameters.keys())
        if parameters and parameters[0] in ("self", "cls"):
            bound.arguments.pop(parameters[0], None)
        # 按照函数签名顺序提取参数值列表
        keys = [
            bound.arguments[param] for param in signature.parameters if param in bound.arguments
        ]
        # 使用有序参数生成缓存键
        return f"{func.__name__}_{hashkey(*keys)}"


class CacheToolsBackend(CacheBackend):
    """
    基于 `cachetools.TTLCache` 实现的缓存后端

    特性：
    - 支持动态设置缓存的 TTL（Time To Live，存活时间）和最大条目数（Maxsize）
    - 缓存实例按区域（region）划分，不同 region 拥有独立的缓存实例
    - 同一 region 共享相同的 TTL 和 Maxsize，设置时只能作用于整个 region

    限制：
    - 不支持按 `key` 独立隔离 TTL 和 Maxsize，仅支持作用于 region 级别
    """

    def __init__(self, maxsize: Optional[int] = 512, ttl: Optional[int] = 1800):
        """
        初始化缓存实例

        :param maxsize: 缓存的最大条目数
        :param ttl: 默认缓存存活时间，单位秒
        """
        self.maxsize = maxsize
        self.ttl = ttl
        # 存储各个 region 的缓存实例，region -> TTLCache
        self._region_caches: Dict[str, CacheToolsTTLCache] = {}

    def __get_region_cache(self, region: str) -> Optional[CacheToolsTTLCache]:
        """
        获取指定区域的缓存实例，如果不存在则返回 None
        """
        region = self.get_region(region)
        return self._region_caches.get(region)

    def set(self, key: str, value: Any, ttl: Optional[int] = None,
            region: Optional[str] = DEFAULT_CACHE_REGION, **kwargs) -> None:
        """
        设置缓存值支持每个 key 独立配置 TTL 和 Maxsize

        :param key: 缓存的键
        :param value: 缓存的值
        :param ttl: 缓存的存活时间，单位秒如果未传入则使用默认值
        :param region: 缓存的区
        :param kwargs: maxsize: 缓存的最大条目数如果未传入则使用默认值
        """
        ttl = ttl or self.ttl
        maxsize = kwargs.get("maxsize", self.maxsize)
        region = self.get_region(region)
        # 如果该 key 尚未有缓存实例，则创建一个新的 TTLCache 实例
        region_cache = self._region_caches.setdefault(region, CacheToolsTTLCache(maxsize=maxsize, ttl=ttl))
        # 设置缓存值
        with lock:
            region_cache[key] = value

    def exists(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> bool:
        """
        判断缓存键是否存在

        :param key: 缓存的键
        :param region: 缓存的区
        :return: 存在返回 True，否则返回 False
        """
        region_cache = self.__get_region_cache(region)
        if region_cache is None:
            return False
        return key in region_cache

    def get(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> Any:
        """
        获取缓存的值

        :param key: 缓存的键
        :param region: 缓存的区
        :return: 返回缓存的值，如果缓存不存在返回 None
        """
        region_cache = self.__get_region_cache(region)
        if region_cache is None:
            return None
        return region_cache.get(key)

    def delete(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION):
        """
        删除缓存

        :param key: 缓存的键
        :param region: 缓存的区
        """
        region_cache = self.__get_region_cache(region)
        if region_cache is None:
            return
        with lock:
            del region_cache[key]

    def clear(self, region: Optional[str] = None) -> None:
        """
        清除指定区域的缓存或全部缓存

        :param region: 缓存的区
        """
        if region:
            # 清理指定缓存区
            region_cache = self.__get_region_cache(region)
            if region_cache:
                with lock:
                    region_cache.clear()
                logger.info(f"Cleared cache for region: {region}")
        else:
            # 清除所有区域的缓存
            for region_cache in self._region_caches.values():
                with lock:
                    region_cache.clear()
            logger.info("Cleared all cache")

    def close(self) -> None:
        """
        内存缓存不需要关闭资源
        """
        pass


class RedisBackend(CacheBackend):
    """
    基于 Redis 实现的缓存后端，支持通过 Redis 存储缓存

    特性：
    - 支持动态设置缓存的 TTL（Time To Live，存活时间）
    - 支持分区域（region）管理缓存，不同的 region 采用独立的命名空间
    - 支持自定义最大内存限制（maxmemory）和内存淘汰策略（如 allkeys-lru）

    限制：
    - 由于 Redis 的分布式特性，写入和读取可能受到网络延迟的影响
    - Pickle 反序列化可能存在安全风险，需进一步重构调用来源，避免复杂对象缓存
    """

    def __init__(self, redis_url: Optional[str] = "redis://localhost", ttl: Optional[int] = 1800):
        """
        初始化 Redis 缓存实例

        :param redis_url: Redis 服务的 URL
        :param ttl: 缓存的存活时间，单位秒
        """
        self.ttl = ttl
        self._redis_helper = None
        try:
            self.redis_helper = RedisHelper(redis_url=redis_url)
        except RuntimeError as e:
            logger.warning(f"Redis缓存初始化失败: {e}")
            raise e

    def set(self, key: str, value: Any, ttl: Optional[int] = None,
            region: Optional[str] = DEFAULT_CACHE_REGION, **kwargs) -> None:
        """
        设置缓存

        :param key: 缓存的键
        :param value: 缓存的值
        :param ttl: 缓存的存活时间，单位秒如果未传入则使用默认值
        :param region: 缓存的区
        :param kwargs: kwargs
        """
        ttl = ttl or self.ttl
        self.redis_helper.set(key, value, ttl=ttl, region=region, **kwargs)

    def exists(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> bool:
        """
        判断缓存键是否存在

        :param key: 缓存的键
        :param region: 缓存的区
        :return: 存在返回 True，否则返回 False
        """
        return self.redis_helper.exists(key, region=region)

    def get(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> Optional[Any]:
        """
        获取缓存的值

        :param key: 缓存的键
        :param region: 缓存的区
        :return: 返回缓存的值，如果缓存不存在返回 None
        """
        return self.redis_helper.get(key, region=region)

    def delete(self, key: str, region: Optional[str] = DEFAULT_CACHE_REGION) -> None:
        """
        删除缓存

        :param key: 缓存的键
        :param region: 缓存的区
        """
        self.redis_helper.delete(key, region=region)

    def clear(self, region: Optional[str] = None) -> None:
        """
        清除指定区域的缓存或全部缓存

        :param region: 缓存的区
        """
        self.redis_helper.clear(region=region)

    def close(self) -> None:
        """
        关闭 Redis 客户端的连接池
        """
        self.redis_helper.close()


def get_cache_backend(maxsize: Optional[int] = 512, ttl: Optional[int] = 1800) -> CacheBackend:
    """
    根据配置获取缓存后端实例

    :param maxsize: 缓存的最大条目数
    :param ttl: 缓存的默认存活时间，单位秒
    :return: 返回缓存后端实例
    """
    cache_type = settings.CACHE_BACKEND_TYPE
    logger.debug(f"Cache backend type from settings: {cache_type}")

    if cache_type == "redis":
        redis_url = settings.CACHE_BACKEND_URL
        if redis_url:
            try:
                logger.debug(f"Attempting to use RedisBackend with URL: {redis_url}, TTL: {ttl}")
                return RedisBackend(redis_url=redis_url, ttl=ttl)
            except RuntimeError:
                logger.warning("Falling back to CacheToolsBackend due to Redis connection failure.")
        else:
            logger.debug("Cache backend type is redis, but no valid REDIS_URL found. "
                         "Falling back to CacheToolsBackend.")

    # 如果不是 Redis，回退到内存缓存
    logger.debug(f"Using CacheToolsBackend with default maxsize: {maxsize}, TTL: {ttl}")
    return CacheToolsBackend(maxsize=maxsize, ttl=ttl)


class TTLCache:
    """
    TTL缓存类，根据配置自动选择使用Redis或cachetools

    特性：
    - 提供与cachetools.TTLCache相同的接口
    - 根据配置自动选择缓存后端
    - 支持Redis和cachetools的切换
    """

    def __init__(self, maxsize: int = 128, ttl: int = 600):
        """
        初始化TTL缓存

        :param maxsize: 缓存的最大条目数
        :param ttl: 缓存的存活时间，单位秒
        """
        self.maxsize = maxsize
        self.ttl = ttl
        self._backend = get_cache_backend(maxsize=maxsize, ttl=ttl)

    def __getitem__(self, key):
        """
        获取缓存项
        """
        try:
            value = self._backend.get(str(key))
            if value is not None:
                return value
        except Exception as e:
            logger.warning(f"缓存获取失败: {e}")

        raise KeyError(key)

    def __setitem__(self, key, value):
        """
        设置缓存项
        """
        try:
            self._backend.set(str(key), value, ttl=self.ttl)
        except Exception as e:
            logger.warning(f"缓存设置失败: {e}")

    def __delitem__(self, key):
        """
        删除缓存项
        """
        try:
            self._backend.delete(str(key))
        except Exception as e:
            logger.warning(f"缓存删除失败: {e}")

    def __contains__(self, key):
        """
        检查键是否存在
        """
        try:
            return self._backend.exists(str(key))
        except Exception as e:
            logger.warning(f"缓存检查失败: {e}")
            return False

    def get(self, key, default=None):
        """
        获取缓存项，如果不存在返回默认值
        """
        try:
            value = self._backend.get(str(key))
            if value is not None:
                return value
        except Exception as e:
            logger.warning(f"缓存获取失败: {e}")

        return default

    def clear(self):
        """
        清空缓存
        """
        try:
            self._backend.clear()
        except Exception as e:
            logger.warning(f"缓存清空失败: {e}")

    def close(self):
        """
        关闭缓存连接
        """
        try:
            self._backend.close()
        except Exception as e:
            logger.warning(f"缓存关闭失败: {e}")


def cached(region: Optional[str] = None, maxsize: Optional[int] = 512, ttl: Optional[int] = 1800,
           skip_none: Optional[bool] = True, skip_empty: Optional[bool] = False):
    """
    自定义缓存装饰器，支持为每个 key 动态传递 maxsize 和 ttl

    :param region: 缓存的区
    :param maxsize: 缓存的最大条目数，默认值为 512
    :param ttl: 缓存的存活时间，单位秒，默认值为 1800
    :param skip_none: 跳过 None 缓存，默认为 True
    :param skip_empty: 跳过空值缓存（如 None, [], {}, "", set()），默认为 False
    :return: 装饰器函数
    """

    def should_cache(value: Any) -> bool:
        """
        判断是否应该缓存结果，如果返回值是 None 或空值则不缓存

        :param value: 要判断的缓存值
        :return: 是否缓存结果
        """
        if skip_none and value is None:
            return False
        # if skip_empty and value in [None, [], {}, "", set()]:
        if skip_empty and not value:
            return False
        return True

    def is_valid_cache_value(cache_key: str, cached_value: Any, cache_region: str) -> bool:
        """
        判断指定的值是否为一个有效的缓存值

        :param cache_key: 缓存的键
        :param cached_value: 缓存的值
        :param cache_region: 缓存的区
        :return: 若值是有效的缓存值返回 True，否则返回 False
        """
        # 如果 skip_none 为 False，且 value 为 None，需要判断缓存实际是否存在
        if not skip_none and cached_value is None:
            if not cache_backend.exists(key=cache_key, region=cache_region):
                return False
        return True

    def decorator(func):

        # 获取缓存区
        cache_region = region if region is not None else f"{func.__module__}.{func.__name__}"

        # 检查是否为异步函数
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            # 异步函数的缓存装饰器
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                # 获取缓存键
                cache_key = cache_backend.get_cache_key(func, args, kwargs)
                # 尝试获取缓存
                cached_value = cache_backend.get(cache_key, region=cache_region)
                if should_cache(cached_value) and is_valid_cache_value(cache_key, cached_value, cache_region):
                    return cached_value
                # 执行异步函数并缓存结果
                result = await func(*args, **kwargs)
                # 判断是否需要缓存
                if not should_cache(result):
                    return result
                # 设置缓存（如果有传入的 maxsize 和 ttl，则覆盖默认值）
                cache_backend.set(cache_key, result, ttl=ttl, maxsize=maxsize, region=cache_region)
                return result

            def cache_clear():
                """
                清理缓存区
                """
                cache_backend.clear(region=cache_region)

            async_wrapper.cache_region = cache_region
            async_wrapper.cache_clear = cache_clear
            return async_wrapper
        else:
            # 同步函数的缓存装饰器
            @wraps(func)
            def wrapper(*args, **kwargs):
                # 获取缓存键
                cache_key = cache_backend.get_cache_key(func, args, kwargs)
                # 尝试获取缓存
                cached_value = cache_backend.get(cache_key, region=cache_region)
                if should_cache(cached_value) and is_valid_cache_value(cache_key, cached_value, cache_region):
                    return cached_value
                # 执行函数并缓存结果
                result = func(*args, **kwargs)
                # 判断是否需要缓存
                if not should_cache(result):
                    return result
                # 设置缓存（如果有传入的 maxsize 和 ttl，则覆盖默认值）
                cache_backend.set(cache_key, result, ttl=ttl, maxsize=maxsize, region=cache_region)
                return result

            def cache_clear():
                """
                清理缓存区
                """
                cache_backend.clear(region=cache_region)

            wrapper.cache_region = cache_region
            wrapper.cache_clear = cache_clear
            return wrapper

    return decorator


# 缓存后端实例
cache_backend = get_cache_backend()


def close_cache() -> None:
    """
    关闭缓存后端连接并清理资源
    """
    try:
        if cache_backend:
            cache_backend.close()
            logger.info("Cache backend closed successfully.")
    except Exception as e:
        logger.info(f"Error while closing cache backend: {e}")
