"""插件数据库注册表在并发注册下的唯一性。

同一插件的多个实例会对同一插件标识各调用一次 register_plugin。注册表若按「先查后写」
无锁登记，并发调用会各建一个容器，只有最后写入的那个留在表内；被挤出去的容器已经交到
调用方手上并持有连接池与 scoped_session，dispose 与 drop_plugin 都回收不到它们。
"""
import threading
import time
from typing import List

import pytest

from app.db.plugin.registry import DbManager

PLUGIN_ID = "concurrent_registry_plugin"

# 并发注册的线程数
REGISTER_THREADS = 8

# 容器建立的模拟耗时，用于放大「先查后写」的窗口
BUILD_SECONDS = 0.05


class _RecordingBundle:
    """记录释放状态的数据库容器替身。"""

    def __init__(self, plugin_id: str):
        """按插件标识建立容器替身，初始为未释放。"""
        self.plugin_id = plugin_id
        self.disposed = False
        self.schema = None
        self.db_path = None
        self.metadata = None

    def dispose(self) -> None:
        """记录本容器已被释放。"""
        self.disposed = True


@pytest.fixture
def registry(monkeypatch):
    """构造与全局注册表隔离的管理器，容器建立替换为可感知耗时的替身。

    :return: (管理器, 已建立的容器列表)
    """
    created: List[_RecordingBundle] = []

    def build(plugin_id: str) -> _RecordingBundle:
        bundle = _RecordingBundle(plugin_id)
        time.sleep(BUILD_SECONDS)
        created.append(bundle)
        return bundle

    monkeypatch.setattr(DbManager, "_build_sqlite_bundle", staticmethod(build))
    monkeypatch.setattr(DbManager, "_build_postgresql_bundle", staticmethod(build))
    return DbManager(), created


def _register_concurrently(manager: DbManager, plugin_id: str) -> List[object]:
    """
    让多个线程同时注册同一个插件，返回各线程拿到的容器

    :param manager: 插件数据库管理器
    :param plugin_id: 插件唯一标识
    :return: 各线程拿到的容器列表
    """
    barrier = threading.Barrier(REGISTER_THREADS)
    results: List[object] = []

    def register() -> None:
        barrier.wait()
        results.append(manager.register_plugin(plugin_id))

    threads = [threading.Thread(target=register) for _ in range(REGISTER_THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def test_concurrent_registration_builds_one_container(registry):
    """并发注册同一插件只建立一个容器，全部调用方拿到同一个实例。"""
    manager, created = registry

    results = _register_concurrently(manager, PLUGIN_ID)

    assert len(created) == 1
    assert results and all(result is created[0] for result in results)
    assert manager.get(PLUGIN_ID) is created[0]


def test_dispose_reclaims_every_container_built_under_contention(registry):
    """并发注册后释放插件，建立过的容器不得有任何一个留在注册表之外。"""
    manager, created = registry
    _register_concurrently(manager, PLUGIN_ID)

    manager.dispose(PLUGIN_ID)

    assert [bundle.disposed for bundle in created] == [True]
    assert manager.get(PLUGIN_ID) is None


def test_registration_of_different_plugins_runs_in_parallel(registry):
    """不同插件的容器建立互不排队，注册不会被串行化成逐个等待。"""
    manager, created = registry
    plugin_ids = [f"{PLUGIN_ID}_{index}" for index in range(REGISTER_THREADS)]
    barrier = threading.Barrier(REGISTER_THREADS)

    def register(plugin_id: str) -> None:
        barrier.wait()
        manager.register_plugin(plugin_id)

    threads = [threading.Thread(target=register, args=(pid,)) for pid in plugin_ids]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started

    assert len(created) == REGISTER_THREADS
    assert elapsed < BUILD_SECONDS * REGISTER_THREADS
