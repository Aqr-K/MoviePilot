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
