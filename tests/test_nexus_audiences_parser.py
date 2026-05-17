# -*- coding: utf-8 -*-
from app.modules.indexer.parser.nexus_audiences import NexusAudiencesSiteUserInfo
from app.utils.string import StringUtils


def test_audiences_userbar_metrics_override_generic_nexus_regex():
    parser = NexusAudiencesSiteUserInfo(
        site_name="Audiences",
        url="https://audiences.me/",
        site_cookie="",
        apikey=None,
        token=None,
    )
    html_text = """
    <html>
      <body>
        <div
          data-uploader-label="jxxghp"
          data-uploader-url="userdetails.php?id=18978"
          data-uploader-badge="(江湖儿女)Elite User"
          data-uploader-stats='[
            {"label":"上传量：","value":"10.150 TB","tone":"uploaded"},
            {"label":"爆米花：","value":"1,973,896.2","tone":"bonus"},
            {"label":"下载量：","value":"3.624 TB","tone":"downloaded"},
            {"label":"活跃","value":"↑ 355 / ↓ 7","tone":"active"}
          ]'>
        </div>
        <span class="site-userbar__compact-metric site-userbar__compact-metric--ratio">
          <i></i><span>2.801</span>
        </span>
      </body>
    </html>
    """

    # Audiences 新版用户栏把流量数据放在 data 属性中，通用 NexusPHP 正则无法稳定识别。
    parser._parse_user_traffic_info(html_text)

    assert parser.userid == "18978"
    assert parser.username == "jxxghp"
    assert parser.user_level == "(江湖儿女)Elite User"
    assert parser.upload == StringUtils.num_filesize("10.150 TB")
    assert parser.download == StringUtils.num_filesize("3.624 TB")
    assert parser.ratio == 2.801
    assert parser.bonus == 1973896.2
    assert parser.seeding == 355
    assert parser.leeching == 7


def test_audiences_inbox_total_unread_badge_uses_unread_part():
    parser = NexusAudiencesSiteUserInfo(
        site_name="Audiences",
        url="https://audiences.me/",
        site_cookie="",
        apikey=None,
        token=None,
    )
    html_text = """
    <html>
      <body>
        <div class="site-userbar__compact-actions">
          <a class="site-userbar__compact-tool site-userbar__compact-tool--has-unread"
             href="messages.php"
             title="收件箱 1749/172"
             aria-label="收件箱 1749/172">
            <i class="fas fa-inbox" aria-hidden="true"></i>
            <strong>收件箱</strong>
            <span class="site-userbar__compact-tool-badge site-userbar__compact-tool-badge--unread">1749/172</span>
          </a>
          <a class="site-userbar__compact-tool"
             href="messages.php?action=viewmailbox&amp;box=-1"
             title="发件箱 0"
             aria-label="发件箱 0">
            <strong>发件箱</strong>
            <span class="site-userbar__compact-tool-badge">0</span>
          </a>
        </div>
      </body>
    </html>
    """

    parser._parse_message_unread(html_text)

    assert parser.message_unread == 172


def test_audiences_table_unread_links_ignore_content_rows():
    parser = NexusAudiencesSiteUserInfo(
        site_name="Audiences",
        url="https://audiences.me/",
        site_cookie="",
        apikey=None,
        token=None,
    )
    html_text = """
    <html>
      <body>
        <table>
          <tr>
            <td class="rowfollow" align="center">
              <img class="unreadpm" src="pic/trans.gif" alt="Unread" title="未读">
            </td>
            <td class="rowfollow" align="left">
              <a href="messages.php?action=viewmessage&amp;id=4318225">种子被删除</a>
            </td>
            <td class="rowfollow" align="left">系统</td>
            <td class="rowfollow" nowrap=""><span title="2026-05-07 23:01:58">8天17时前</span></td>
            <td class="rowfollow"><input class="checkbox" type="checkbox" name="messages[]" value="4318225"></td>
          </tr>
          <tr>
            <td colspan="5" style="padding: 8px;">消息摘要内容</td>
          </tr>
          <tr>
            <td class="rowfollow" align="center">
              <img class="readpm" src="pic/trans.gif" alt="Read" title="已读">
            </td>
            <td class="rowfollow" align="left">
              <a href="messages.php?action=viewmessage&amp;id=4318000">已读消息</a>
            </td>
            <td class="rowfollow" align="left">系统</td>
            <td class="rowfollow" nowrap=""><span title="2026-05-07 23:01:58">8天17时前</span></td>
            <td class="rowfollow"><input class="checkbox" type="checkbox" name="messages[]" value="4318000"></td>
          </tr>
          <tr>
            <td class="rowfollow" align="center">
              <img class="readpm" src="pic/trans.gif" title="已读">
            </td>
            <td class="rowfollow" align="left">
              <a href="messages.php?action=viewmessage&amp;id=4317999">无英文 alt 的已读消息</a>
            </td>
            <td class="rowfollow" align="left">系统</td>
            <td class="rowfollow" nowrap=""><span title="2026-05-07 23:01:58">8天17时前</span></td>
            <td class="rowfollow"><input class="checkbox" type="checkbox" name="messages[]" value="4317999"></td>
          </tr>
          <tr>
            <td class="rowfollow" align="center"></td>
            <td class="rowfollow" align="left">
              <a href="messages.php?action=viewmessage&amp;id=4317998">无状态图标消息</a>
            </td>
            <td class="rowfollow" align="left">系统</td>
            <td class="rowfollow" nowrap=""><span title="2026-05-07 23:01:58">8天17时前</span></td>
            <td class="rowfollow"><input class="checkbox" type="checkbox" name="messages[]" value="4317998"></td>
          </tr>
        </table>
      </body>
    </html>
    """
    msg_links = []

    next_page = parser._parse_message_unread_links(html_text, msg_links)

    assert msg_links == ["messages.php?action=viewmessage&id=4318225"]
    assert next_page is None


def test_audiences_readpm_row_is_not_unread_message():
    parser = NexusAudiencesSiteUserInfo(
        site_name="Audiences",
        url="https://audiences.me/",
        site_cookie="",
        apikey=None,
        token=None,
    )
    html_text = """
    <html>
      <body>
        <table>
          <tr>
            <td class="rowfollow" align="center">
              <img class="readpm" src="pic/trans.gif" alt="Read" title="已读">
            </td>
            <td class="rowfollow" align="left">
              <a href="messages.php?action=viewmessage&amp;id=4318000">已读消息</a>
            </td>
          </tr>
        </table>
      </body>
    </html>
    """
    msg_links = []

    parser._parse_message_unread_links(html_text, msg_links)

    assert msg_links == []
