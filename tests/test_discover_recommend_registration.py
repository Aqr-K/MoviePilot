# -*- coding: utf-8 -*-
"""
推荐/发现数据源（Discover/Recommend 域）声明式开放注册回归：

  1. get_plugin_provided_discover_sources / get_plugin_provided_recommend_sources
     聚合器按 owner 归集插件经 provides_*_sources() 声明的数据对象，跳过未启用插件；
  2. /api/discover/source 与 /api/recommend/source 端点合并「插件声明式源」与
     「事件扩展源（ChainEventType）」，并按 api_path 去重（声明式优先、向后兼容事件）。

与消息渠道/媒体服务器（模块类注册）不同，发现/推荐是【数据对象】注册（DiscoverMediaSource /
RecommendMediaSource），仿 provides_channel_capabilities 范式，仅在 /source 端点聚合枚举，
不进入 run_module 分发。
"""
from unittest import TestCase
from unittest.mock import MagicMock, patch

from app import schemas
from app.helper.plugin_metadata import (
    get_plugin_provided_discover_sources,
    get_plugin_provided_recommend_sources,
)


def _disc(name, path):
    return schemas.DiscoverMediaSource(name=name, mediaid_prefix=name, api_path=path)


def _rec(name, path):
    return schemas.RecommendMediaSource(name=name, api_path=path, type="movie")


class TestDiscoverRecommendAggregators(TestCase):
    def test_discover_aggregator_collects_enabled(self):
        src = _disc("p", "/plugin/p/discover")

        class _P:
            def get_state(self):
                return True

            def provides_discover_sources(self):
                return [src]

        self.assertEqual(get_plugin_provided_discover_sources({"p": _P()}), {"p": [src]})

    def test_discover_aggregator_skips_disabled(self):
        class _P:
            def get_state(self):
                return False

            def provides_discover_sources(self):
                return [_disc("p", "/x")]

        self.assertEqual(get_plugin_provided_discover_sources({"p": _P()}), {})

    def test_recommend_aggregator_collects_enabled(self):
        src = _rec("p", "/plugin/p/recommend")

        class _P:
            def get_state(self):
                return True

            def provides_recommend_sources(self):
                return [src]

        self.assertEqual(get_plugin_provided_recommend_sources({"p": _P()}), {"p": [src]})

    def test_recommend_aggregator_skips_disabled(self):
        class _P:
            def get_state(self):
                return False

            def provides_recommend_sources(self):
                return [_rec("p", "/x")]

        self.assertEqual(get_plugin_provided_recommend_sources({"p": _P()}), {})


class TestDiscoverSourceEndpointMerge(TestCase):
    def test_merges_plugin_and_event_dedup_by_api_path(self):
        from app.api.endpoints import discover as discover_ep

        plugin_src = _disc("plug", "/plugin/p/discover")
        dup_event_src = _disc("plug-dup", "/plugin/p/discover")  # 同 api_path → 去重
        uniq_event_src = _disc("evt", "/plugin/e/discover")

        pm = MagicMock()
        pm.get_plugin_provided_discover_sources.return_value = {"p": [plugin_src]}

        event = MagicMock()
        event.event_data = MagicMock()
        event.event_data.extra_sources = [dup_event_src, uniq_event_src]

        with patch.object(discover_ep, "PluginManager", return_value=pm), \
                patch.object(discover_ep.eventmanager, "send_event", return_value=event):
            result = discover_ep.source()

        # 声明式源优先 + 唯一事件源；同 api_path 的事件源被去重
        self.assertEqual([s.api_path for s in result],
                         ["/plugin/p/discover", "/plugin/e/discover"])
        self.assertEqual([s.name for s in result], ["plug", "evt"])


class TestRecommendSourceEndpointMerge(TestCase):
    def test_merges_plugin_and_event_dedup_by_api_path(self):
        from app.api.endpoints import recommend as recommend_ep

        plugin_src = _rec("plug", "/plugin/p/recommend")
        dup_event_src = _rec("plug-dup", "/plugin/p/recommend")
        uniq_event_src = _rec("evt", "/plugin/e/recommend")

        pm = MagicMock()
        pm.get_plugin_provided_recommend_sources.return_value = {"p": [plugin_src]}

        event = MagicMock()
        event.event_data = MagicMock()
        event.event_data.extra_sources = [dup_event_src, uniq_event_src]

        with patch.object(recommend_ep, "PluginManager", return_value=pm), \
                patch.object(recommend_ep.eventmanager, "send_event", return_value=event):
            result = recommend_ep.source()

        self.assertEqual([s.api_path for s in result],
                         ["/plugin/p/recommend", "/plugin/e/recommend"])
        self.assertEqual([s.name for s in result], ["plug", "evt"])


class TestDiscoverSourceEndpointSkipsMalformed(TestCase):
    def test_sources_without_api_path_are_skipped_not_collapsed(self):
        # 畸形源（无 api_path）应逐个跳过，而非把 None 塞进去重集吞掉后续合法源
        from types import SimpleNamespace

        from app.api.endpoints import discover as discover_ep

        good = _disc("good", "/plugin/p/discover")
        bad1 = SimpleNamespace(name="bad1")  # 无 api_path
        bad2 = SimpleNamespace(name="bad2")  # 无 api_path

        pm = MagicMock()
        pm.get_plugin_provided_discover_sources.return_value = {"p": [bad1, good, bad2]}
        event = MagicMock()
        event.event_data = MagicMock()
        event.event_data.extra_sources = []

        with patch.object(discover_ep, "PluginManager", return_value=pm), \
                patch.object(discover_ep.eventmanager, "send_event", return_value=event):
            result = discover_ep.source()

        self.assertEqual([s.name for s in result], ["good"])
