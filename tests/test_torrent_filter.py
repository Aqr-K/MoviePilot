import unittest
from types import SimpleNamespace

from app.core.context import TorrentInfo
from app.helper.torrent import TorrentHelper
from app.modules.filter import FilterModule


class _RuleHelper:
    """
    过滤模块测试用的轻量规则仓库，避免依赖真实系统配置。
    """

    def __init__(self, groups):
        self._groups = groups

    def get_rule_group_by_media(self, media=None, group_names=None):  # noqa: ARG002
        if not group_names:
            return self._groups
        return [group for group in self._groups if group.name in group_names]


def _build_filter_module(rule_string: str, rule_set: dict) -> FilterModule:
    module = FilterModule()
    module.rulehelper = _RuleHelper(
        [SimpleNamespace(name="test", rule_string=rule_string)]
    )
    module.rule_set = rule_set
    return module


class TorrentFilterTest(unittest.TestCase):

    def test_filter_torrents_keeps_priority_and_boolean_rule_semantics(self):
        module = _build_filter_module(
            rule_string="HDR & !BLU > DV",
            rule_set={
                "HDR": {"include": "HDR"},
                "DV": {"include": "DOVI"},
                "BLU": {"include": "BluRay"},
            },
        )
        torrents = [
            TorrentInfo(title="Movie HDR WEB-DL", description=""),
            TorrentInfo(title="Movie DOVI", description=""),
            TorrentInfo(title="Movie HDR BluRay", description=""),
        ]

        filtered = module.filter_torrents(rule_groups=["test"], torrent_list=torrents)

        self.assertEqual(torrents[:2], filtered)
        self.assertEqual(100, filtered[0].pri_order)
        self.assertEqual(99, filtered[1].pri_order)

    def test_filter_torrents_keeps_lazy_priority_level_parsing(self):
        module = _build_filter_module(
            rule_string="KEEP > (",
            rule_set={"KEEP": {"include": "Movie"}},
        )
        torrent = TorrentInfo(title="Movie", description="")

        filtered = module.filter_torrents(rule_groups=["test"], torrent_list=[torrent])

        self.assertEqual([torrent], filtered)
        self.assertEqual(100, torrent.pri_order)

    def test_filter_torrent_keeps_extra_filter_semantics(self):
        torrent = TorrentInfo(
            title="Movie 1080p HDR",
            description="中字",
            labels=["free"],
            size=3 * 1024 * 1024 * 1024,
            uploadvolumefactor=1,
            downloadvolumefactor=0,
        )

        self.assertTrue(
            TorrentHelper.filter_torrent(
                torrent_info=torrent,
                filter_params={
                    "include": "中字|free",
                    "exclude": "BluRay",
                    "resolution": "1080p",
                    "effect": "HDR",
                    "size": "1000-4000",
                },
            )
        )
        self.assertFalse(
            TorrentHelper.filter_torrent(
                torrent_info=torrent,
                filter_params={"exclude": "HDR"},
            )
        )
        self.assertFalse(
            TorrentHelper.filter_torrent(
                torrent_info=torrent,
                filter_params={"size": "<1000"},
            )
        )


if __name__ == "__main__":
    unittest.main()
