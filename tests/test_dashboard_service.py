"""
S7f 抽取验证：app.service.dashboard 的 Chain 编排 + 聚合逻辑单测（mock Chain）。

把端点里的 Chain 编排下沉到 service 层后，通过 monkeypatch DashboardChain /
StorageChain / DirectoryHelper / SystemUtils 即可在 venv 内单测聚合逻辑，
无需真实下载器/媒体库/磁盘。
"""
from types import SimpleNamespace

from app import schemas
from app.service import dashboard as svc


# ---------- build_statistic ----------

def _patch_monthly_statistics(monkeypatch, result=(0, 0, 0, 0)):
    """把当月整理统计固定为给定值，隔离 DB 依赖。"""
    monkeypatch.setattr(
        svc.TransferHistory,
        "monthly_media_statistics",
        staticmethod(lambda db: result),
    )


def test_build_statistic_aggregates_counts(monkeypatch):
    stats = [
        schemas.Statistic(movie_count=10, tv_count=20, episode_count=3, user_count=2),
        schemas.Statistic(movie_count=1, tv_count=2, episode_count=6, user_count=1),
    ]
    monkeypatch.setattr(
        svc, "DashboardChain", lambda: SimpleNamespace(media_statistic=lambda name: stats)
    )
    _patch_monthly_statistics(monkeypatch, (4, 5, 6, 7))
    ret = svc.build_statistic(db=None)
    assert ret.movie_count == 11
    assert ret.tv_count == 22
    assert ret.user_count == 3
    assert ret.episode_count == 9
    assert ret.movie_count_month == 4
    assert ret.tv_count_month == 5
    assert ret.episode_count_month == 6


def test_build_statistic_episode_none_when_all_missing(monkeypatch):
    stats = [
        schemas.Statistic(movie_count=10, tv_count=20, episode_count=None, user_count=2),
        schemas.Statistic(movie_count=1, tv_count=2, episode_count=None, user_count=1),
    ]
    monkeypatch.setattr(
        svc, "DashboardChain", lambda: SimpleNamespace(media_statistic=lambda name: stats)
    )
    _patch_monthly_statistics(monkeypatch)
    ret = svc.build_statistic(db=None)
    assert ret.movie_count == 11
    assert ret.episode_count is None


def test_build_statistic_empty_returns_blank(monkeypatch):
    monkeypatch.setattr(
        svc, "DashboardChain", lambda: SimpleNamespace(media_statistic=lambda name: None)
    )
    _patch_monthly_statistics(monkeypatch)
    assert svc.build_statistic(db=None) == schemas.Statistic()


# ---------- build_storage ----------

def test_build_storage_sums_and_dedupes(monkeypatch):
    # 两个目录同属一个 storage -> set 去重为一次 storage_usage 调用
    dirs = [
        SimpleNamespace(library_storage="local"),
        SimpleNamespace(library_storage="local"),
    ]
    monkeypatch.setattr(
        svc, "DirectoryHelper", lambda: SimpleNamespace(get_dirs=lambda: dirs)
    )
    monkeypatch.setattr(
        svc,
        "StorageChain",
        lambda: SimpleNamespace(storage_usage=lambda s: SimpleNamespace(total=100, available=40)),
    )
    ret = svc.build_storage()
    assert ret.total_storage == 100
    assert ret.used_storage == 60  # total - available


def test_build_storage_no_dirs(monkeypatch):
    monkeypatch.setattr(
        svc, "DirectoryHelper", lambda: SimpleNamespace(get_dirs=lambda: [])
    )
    ret = svc.build_storage()
    assert ret.total_storage == 0
    assert ret.used_storage == 0


# ---------- build_downloader ----------

def test_build_downloader_aggregates(monkeypatch):
    infos = [
        SimpleNamespace(download_speed=1.0, upload_speed=2.0, download_size=10, upload_size=20),
        SimpleNamespace(download_speed=3.0, upload_speed=4.0, download_size=30, upload_size=40),
    ]
    monkeypatch.setattr(
        svc,
        "DirectoryHelper",
        lambda: SimpleNamespace(
            get_local_download_dirs=lambda: [SimpleNamespace(download_path="/tmp/dl")]
        ),
    )
    monkeypatch.setattr(
        svc, "DashboardChain", lambda: SimpleNamespace(downloader_info=lambda name: infos)
    )
    monkeypatch.setattr(svc.SystemUtils, "space_usage", staticmethod(lambda paths, **kw: (0, 999)))
    ret = svc.build_downloader()
    assert ret.download_speed == 4.0
    assert ret.upload_speed == 6.0
    assert ret.download_size == 40
    assert ret.upload_size == 60
    assert ret.free_space == 999
