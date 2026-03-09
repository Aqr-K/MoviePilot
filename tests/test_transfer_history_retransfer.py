from types import ModuleType, SimpleNamespace
import sys

# The endpoint import pulls in a wide plugin/helper graph. Some optional modules are
# not present in this test environment, so stub them before importing the endpoint.
sys.modules.setdefault("app.helper.sites", ModuleType("app.helper.sites"))
setattr(sys.modules["app.helper.sites"], "SitesHelper", object)

from app.api.endpoints.transfer import manual_transfer
from app.schemas import ManualTransferItem


def test_manual_transfer_from_history_preserves_download_context(monkeypatch):
    history = SimpleNamespace(
        status=0,
        mode="copy",
        src_fileitem={"storage": "local", "path": "/downloads/test.mkv", "name": "test.mkv", "type": "file"},
        dest_fileitem=None,
        downloader="qbittorrent",
        download_hash="abc123",
        type="电视剧",
        tmdbid="100",
        doubanid="200",
        seasons="S01",
        episodes="E01-E02",
        episode_group="WEB-DL",
    )

    captured = {}

    def fake_get(_db, logid):
        assert logid == 1
        return history

    class FakeTransferChain:
        def manual_transfer(self, **kwargs):
            captured.update(kwargs)
            return True, ""

    monkeypatch.setattr("app.api.endpoints.transfer.TransferHistory.get", fake_get)
    monkeypatch.setattr("app.api.endpoints.transfer.TransferChain", FakeTransferChain)

    resp = manual_transfer(
        transer_item=ManualTransferItem(logid=1, from_history=True),
        background=True,
        db=object(),
        _="token",
    )

    assert resp.success is True
    assert captured["downloader"] == "qbittorrent"
    assert captured["download_hash"] == "abc123"
    assert captured["episode_group"] == "WEB-DL"
    assert captured["season"] == 1
