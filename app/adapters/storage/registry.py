"""外部来源存储驱动注册表。

按 schema 标识收录内建之外的存储实现，供文件整理模块与内建存储合并成一份视图。

内建存储的 schema 集合由文件整理模块加载完内建实现后经 configure_builtin_schemas() 告知；
在此之前内建集合为空，重名判定只覆盖已注册的外部存储。
"""
import threading
from enum import Enum
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set

from app.modules.storages.base import StorageBase
from app.runtime.log import logger


class _StorageRegistration(NamedTuple):
    """一条外部存储注册记录"""

    owner: str
    storage_cls: type


_lock = threading.RLock()
_builtin_schemas: Set[str] = set()
_registered: Dict[str, _StorageRegistration] = {}


def storage_schema_value(storage: Any) -> Optional[str]:
    """
    取存储类或实例的 schema 标识字符串

    :param storage: 存储类或存储实例
    :return: 枚举成员取 value，字符串原样返回，其余返回 None
    """
    schema = getattr(storage, "schema", None)
    if isinstance(schema, Enum):
        schema = schema.value
    if isinstance(schema, str) and schema:
        return schema
    return None


def configure_builtin_schemas(schemas: Iterable[str]) -> None:
    """
    设置内建存储的 schema 标识集合，用于外部存储的重名判定

    :param schemas: 内建存储的 schema 标识
    """
    global _builtin_schemas
    with _lock:
        _builtin_schemas = {schema for schema in schemas if schema}


def register_storage(storage_cls: type, owner: str) -> bool:
    """
    注册一个外部来源声明的存储实现，通过契约校验后按 schema 标识上线

    schema 与内建存储或其它来源已注册的存储重名时拒绝注册，先到者胜；同一来源重复注册为幂等更新。

    :param storage_cls: 存储实现类，需继承 StorageBase 并声明可解析的 schema
    :param owner: 注册来源的实例键，用于按来源精确卸载
    :return: 是否被接受进注册表
    """
    if not owner:
        return False
    if not isinstance(storage_cls, type) or not issubclass(storage_cls, StorageBase):
        logger.warning(f"存储 {storage_cls}（owner={owner}）未通过契约校验，拒绝注册：未继承 StorageBase")
        return False
    abstracts = getattr(storage_cls, "__abstractmethods__", frozenset())
    if abstracts:
        logger.warning(f"存储 {storage_cls.__name__}（owner={owner}）未通过契约校验，拒绝注册："
                       f"抽象方法未实现：{sorted(abstracts)}")
        return False
    schema = storage_schema_value(storage_cls)
    if not schema:
        logger.warning(f"存储 {storage_cls.__name__}（owner={owner}）未通过契约校验，拒绝注册：schema 无效")
        return False
    with _lock:
        if schema in _builtin_schemas:
            logger.warning(f"存储注册冲突：{schema} 已存在（owner=builtin），拒绝来自 {owner} 的注册")
            return False
        registration = _registered.get(schema)
        if registration and registration.owner != owner:
            logger.warning(
                f"存储注册冲突：{schema} 已存在（owner={registration.owner}），"
                f"拒绝来自 {owner} 的注册")
            return False
        _registered[schema] = _StorageRegistration(owner=owner, storage_cls=storage_cls)
        return True


def unregister_storages(owner: str) -> List[str]:
    """
    卸载某来源注册的全部存储

    :param owner: 注册来源的实例键
    :return: 被移除的 schema 标识列表
    """
    if not owner:
        return []
    with _lock:
        removed = [schema for schema, registration in _registered.items() if registration.owner == owner]
        for schema in removed:
            _registered.pop(schema, None)
    return removed


def get_registered_storages() -> List[type]:
    """
    获取当前已注册的外部存储类列表
    """
    with _lock:
        return [registration.storage_cls for registration in _registered.values()]


def get_registered_storage_schemas() -> List[str]:
    """
    获取当前已注册的外部存储 schema 标识列表

    :return: schema 标识列表
    """
    with _lock:
        return list(_registered)
