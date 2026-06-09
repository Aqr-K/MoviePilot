from pathlib import Path

from lxml import etree

from app.core.context import Context, TorrentInfo
from app.modules.subtitle import SubtitleModule
from app.schemas.file import FileItem


class _FakeStorageChain:
    """
    模拟字幕下载使用的存储链，记录目录查询与创建行为。
    """

    def __init__(self):
        """
        初始化调用记录。
        """
        self.file_item_paths = []
        self.created_paths = []
        self.uploaded_files = []

    def get_file_item(self, storage, path):
        """
        记录文件项查询，模拟目标目录和字幕文件都不存在。
        """
        self.file_item_paths.append((storage, path))
        return None

    def get_folder(self, storage, path):
        """
        记录递归创建目录请求，并返回创建后的目录项。
        """
        self.created_paths.append((storage, path))
        return FileItem(storage=storage, type="dir", path=path.as_posix(), name=path.name)

    def upload_file(self, fileitem, path):
        """
        记录上传请求，并返回上传后的文件项。
        """
        self.uploaded_files.append((fileitem, path))
        return FileItem(
            storage=fileitem.storage,
            type="file",
            path=(path.parent / path.name).as_posix(),
            name=path.name,
        )


class _FakeResponse:
    """
    构造字幕下载响应对象。
    """

    status_code = 200
    content = b"subtitle"
    headers = {"Content-Disposition": 'attachment; filename="example.srt"'}


def test_parse_subtitle_links_filters_detail_page_action_links():
    """
    详情页解析字幕链接时应过滤上传和外部搜索动作链接。
    """
    html_text = """
    <tr>
      <td class="rowhead" valign="top">字幕</td>
      <td class="rowfollow" align="left" valign="top">
        <table border="0" cellspacing="0">
          <tbody>
            <tr>
              <td class="embedded">
                <img border="0" src="pic/flag/china.gif" alt="简体中文" title="简体中文">
              </td>
              <td class="embedded">
                <a href="downloadsubs.php?torrentid=621182&amp;subid=2148">
                  <u>[雪飘+白恋] 光之美少女 All Stars NewStage：未来的朋友</u>
                </a>
              </td>
            </tr>
          </tbody>
        </table>
        <form method="post" action="subtitles.php">
          <a href="javascript:void(0)" onclick="this.closest(&quot;form&quot;).submit()">上传字幕</a>
        </form>
        <form method="get" action="http://shooter.cn/sub/" target="_blank">
          <a href="javascript:void(0)" onclick="this.closest(&quot;form&quot;).submit()">搜索射手网</a>
        </form>
        <form method="get" action="https://www.opensubtitles.org/en/search2/" target="_blank">
          <a href="javascript:void(0)" onclick="this.closest('form').submit()">搜索Opensubtitles</a>
        </form>
      </td>
    </tr>
    """
    html = etree.HTML(html_text)

    links = SubtitleModule._parse_subtitle_links(
        html, "https://audiences.me/details.php?id=599860&hit=1"
    )

    assert links == [
        "https://audiences.me/downloadsubs.php?torrentid=621182&subid=2148"
    ]


def test_download_added_creates_missing_target_directory(monkeypatch):
    """
    下载字幕时目标目录不存在，应按完整下载目录自动创建后再保存字幕。
    """
    storage_chain = _FakeStorageChain()
    module = SubtitleModule()
    context = Context(
        torrent_info=TorrentInfo(
            page_url="https://example.test/details.php?id=1",
            site_cookie="cookie",
            site_ua="ua",
        )
    )

    monkeypatch.setattr("app.modules.subtitle.StorageChain", lambda: storage_chain)
    monkeypatch.setattr(
        "app.modules.subtitle.TorrentHelper.get_fileinfo_from_torrent_content",
        lambda self, content: ("Example Folder", []),
    )
    monkeypatch.setattr(
        "app.modules.subtitle.TorrentHelper.get_url_filename",
        lambda response, url: "example.srt",
    )
    monkeypatch.setattr(
        "app.modules.subtitle.RequestUtils",
        lambda **kwargs: type(
            "FakeRequest",
            (),
            {"get_res": lambda self, url: _FakeResponse()},
        )(),
    )
    monkeypatch.setattr("app.modules.subtitle.time.sleep", lambda seconds: None)
    monkeypatch.setattr(module, "_get_subtitle_links", lambda torrent: ["https://example.test/subtitle.srt"])

    module.download_added(
        context=context,
        download_dir=Path("/downloads"),
        torrent_content=b"torrent",
    )

    assert storage_chain.created_paths == [("local", Path("/downloads/Example Folder"))]
    assert storage_chain.uploaded_files
