from types import SimpleNamespace
from unittest.mock import patch

from app.modules.filemanager.storages.u115 import U115Pan
from app.schemas import FileItem


def test_upload_returns_target_fileitem_when_uploaded_metadata_is_delayed(tmp_path):
    """
    115 上传完成后目录索引暂不可见时，应返回可落库的目标文件项。
    """
    local_file = tmp_path / "Test.Show.S01E01.mkv"
    local_file.write_bytes(b"movie")

    target_dir = FileItem(
        storage="u115",
        path="/library/Test Show (2026)/Season 1",
        type="dir",
        name="Season 1",
        fileid="100",
    )
    storage = object.__new__(U115Pan)
    storage._calc_sha1 = lambda *_args, **_kwargs: "sha1"
    storage.get_item = lambda _path: None

    def fake_request_api(_method, endpoint, *_args, **_kwargs):
        """
        模拟 115 初始化、凭证和断点续传接口。
        """
        if endpoint == "/open/upload/init":
            return {
                "state": True,
                "data": {
                    "bucket": "bucket",
                    "object": "object",
                    "callback": {"callback": "callback", "callback_var": "var"},
                    "pick_code": "pickcode",
                    "status": 1,
                },
            }
        if endpoint == "/open/upload/get_token":
            return {
                "endpoint": "endpoint",
                "AccessKeyId": "access_key_id",
                "AccessKeySecret": "access_key_secret",
                "SecurityToken": "security_token",
            }
        if endpoint == "/open/upload/resume":
            return None
        return None

    class FakeBucket:
        """
        模拟 OSS 分片上传客户端。
        """

        def __init__(self, *_args, **_kwargs):
            pass

        def init_multipart_upload(self, *_args, **_kwargs):
            """
            返回固定 upload_id。
            """
            return SimpleNamespace(upload_id="upload_id")

        def upload_part(self, *_args, **_kwargs):
            """
            返回固定分片 etag。
            """
            return SimpleNamespace(etag="etag")

        def complete_multipart_upload(self, *_args, **_kwargs):
            """
            模拟 OSS 完成分片上传成功。
            """
            response = SimpleNamespace(json=lambda: {"state": True})
            return SimpleNamespace(
                status=200, resp=SimpleNamespace(response=response)
            )

    storage._request_api = fake_request_api

    with patch(
        "app.modules.filemanager.storages.u115.oss2.StsAuth",
        return_value=object(),
    ), patch(
        "app.modules.filemanager.storages.u115.oss2.Bucket",
        FakeBucket,
    ), patch(
        "app.modules.filemanager.storages.u115.transfer_process",
        return_value=lambda _progress: None,
    ):
        uploaded_item = storage.upload(target_dir, local_file)

    assert uploaded_item is not None
    assert uploaded_item.storage == "u115"
    assert uploaded_item.path == "/library/Test Show (2026)/Season 1/Test.Show.S01E01.mkv"
    assert uploaded_item.type == "file"
    assert uploaded_item.size == local_file.stat().st_size
