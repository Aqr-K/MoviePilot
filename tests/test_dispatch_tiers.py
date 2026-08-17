"""三级分发的语义与代价。

    广播  通知，不求答案     必须触达全体，O(n) 是固有代价，不优化
    多播  圈定一类，收全部答案  查注册表 → O(1) 命中 + O(k) 调用
    单播  最终只要一个答案     与多播共用同一张表，只多一层仲裁与短路

广播不查表：它的语义就是遍历全体，把它索引化等于引入订阅表，那时它已经是多播了。
多播与单播是查询，只关心「这一类里谁能回答」，因此走 (族类, 能力) 注册表。
"""
import sys
import unittest
from types import ModuleType as _PyModuleType
from unittest.mock import Mock

sys.modules.setdefault("qbittorrentapi", _PyModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", _PyModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)

from app.chain import ChainBase  # noqa: E402
from app.schemas import RateLimitExceededException  # noqa: E402
from app.schemas.types import ModuleType  # noqa: E402


class RecordingModule:
    """记录调用顺序的模块替身"""

    def __init__(self, name: str, calls: list, result=None, priority: int = 1,
                 module_type=None):
        """
        :param name: 模块名，同时作为调用记录的标识
        :param calls: 共享的调用记录
        :param result: 能力方法的返回值
        :param priority: 模块优先级
        :param module_type: 所属族类
        """
        self._name = name
        self._calls = calls
        self._result = result
        self._priority = priority
        self._type = module_type

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_type(self):
        """模块族类"""
        return self._type

    def get_priority(self) -> int:
        """模块优先级"""
        return self._priority

    def notify(self, payload=None, **kwargs):
        """能力方法"""
        self._calls.append(self._name)
        return self._result


class FailingModule(RecordingModule):
    """执行时抛错的模块替身"""

    def notify(self, payload=None, **kwargs):
        """能力方法"""
        self._calls.append(self._name)
        raise RuntimeError("提供者不可用")


class RateLimitedModule(RecordingModule):
    """执行时命中本地限流的模块替身"""

    def notify(self, payload=None, **kwargs):
        """能力方法"""
        self._calls.append(self._name)
        raise RateLimitExceededException("[notify] 限流期间，跳过调用")


def build_chain(*modules):
    """
    构造与真实模块、插件运行态隔离的 ChainBase

    广播读全体运行模块，多播与单播读 (族类, 能力) 注册表，两条路径分别记录访问次数。

    :param modules: 运行态模块替身
    :return: (链基类实例, 访问计数器)
    """
    counters = {"broadcast_scans": 0, "index_lookups": 0}

    def running_modules(method):
        """广播路径：遍历全体"""
        counters["broadcast_scans"] += 1
        return iter([m for m in modules if callable(getattr(m, method, None))])

    def providers_for(module_type, method):
        """查询路径：按族类与能力查表"""
        counters["index_lookups"] += 1
        return tuple(sorted(
            (m for m in modules
             if m.get_type() == module_type and callable(getattr(m, method, None))),
            key=lambda m: m.get_priority(),
        ))

    chain = ChainBase()
    chain.pluginmanager = Mock()
    chain.pluginmanager.running_plugins = {}
    chain.modulemanager = Mock()
    chain.modulemanager.get_running_modules.side_effect = running_modules
    chain.modulemanager.providers_for.side_effect = providers_for
    chain.messagehelper = Mock()
    chain.eventmanager = Mock()
    return chain, counters


class BroadcastTierTest(unittest.TestCase):
    """广播：通知全体，不求答案，遍历是语义不是缺陷"""

    def test_every_provider_is_notified_even_after_one_returns_a_value(self):
        """某个提供者返回了值也不中止，其余照常收到通知。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("first", calls, result="handled"),
            RecordingModule("second", calls),
            RecordingModule("third", calls),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["first", "second", "third"], calls)

    def test_it_returns_nothing_even_when_providers_answer(self):
        """不求答案：提供者返回了值也不向调用方交出。"""
        calls = []
        chain, _ = build_chain(RecordingModule("only", calls, result="handled"))

        self.assertIsNone(chain.broadcast("notify", payload="x"))

    def test_it_walks_every_module_and_never_consults_the_index(self):
        """广播走全体遍历，不查注册表——索引化会把它变成多播。"""
        calls = []
        chain, counters = build_chain(
            RecordingModule("a", calls, module_type=ModuleType.MediaServer),
            RecordingModule("b", calls, module_type=ModuleType.Downloader),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["a", "b"], calls)
        self.assertEqual(1, counters["broadcast_scans"])
        self.assertEqual(0, counters["index_lookups"])

    def test_a_failing_provider_does_not_stop_the_notification(self):
        """一个提供者抛错时其余照常收到通知，并按系统模块错误上报。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("first", calls),
            FailingModule("boom", calls),
            RecordingModule("third", calls),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["first", "boom", "third"], calls)
        chain.messagehelper.put.assert_called_once()

    def test_rate_limiting_is_skipped_without_an_error_report(self):
        """命中本地限流时跳过该提供者，不产生系统错误告警。"""
        calls = []
        chain, _ = build_chain(
            RateLimitedModule("limited", calls),
            RecordingModule("third", calls),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["limited", "third"], calls)
        chain.messagehelper.put.assert_not_called()


class MulticastTierTest(unittest.TestCase):
    """多播：圈定一类，收集所有答案，经注册表查表"""

    def test_it_collects_an_answer_from_every_provider_in_the_family(self):
        """该族类下每个提供者的答案都被收集。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("plex", calls, result="plex", module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby", "plex"], answers)

    def test_it_queries_the_index_instead_of_walking_every_module(self):
        """查询走注册表，不再遍历全体模块。"""
        calls = []
        chain, counters = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(1, counters["index_lookups"])
        self.assertEqual(0, counters["broadcast_scans"])

    def test_providers_outside_the_family_are_not_touched(self):
        """圈外的模块一个都不被调用，即使它实现了同名方法。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        self.assertEqual(["emby"], calls)

    def test_empty_answers_are_dropped(self):
        """只收集有效答案，返回 None 的提供者不进结果。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("silent", calls, result=None, module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        self.assertEqual(["emby", "silent"], calls)

    def test_a_failing_provider_does_not_lose_the_other_answers(self):
        """一个提供者抛错时其余答案照常收集。"""
        calls = []
        chain, _ = build_chain(
            FailingModule("boom", calls, module_type=ModuleType.MediaServer),
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        chain.messagehelper.put.assert_called_once()

    def test_an_empty_family_yields_no_answers(self):
        """族类下无提供者时返回空列表，不回落到广播。"""
        calls = []
        chain, counters = build_chain(
            RecordingModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        self.assertEqual([], chain.multicast(ModuleType.MediaServer, "notify"))
        self.assertEqual([], calls)
        self.assertEqual(0, counters["broadcast_scans"])


class UnicastTierTest(unittest.TestCase):
    """单播：与多播共用同一张表，只多一层仲裁与短路"""

    def test_the_highest_priority_provider_answers(self):
        """族类内按优先级择一，数字小的先答，其余不执行。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("low", calls, result="low", priority=9,
                            module_type=ModuleType.MediaServer),
            RecordingModule("high", calls, result="high", priority=1,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("high", answer)
        self.assertEqual(["high"], calls)

    def test_it_queries_the_same_index_as_multicast(self):
        """单播与多播查同一张表，单播只是在其上仲裁。"""
        calls = []
        chain, counters = build_chain(
            RecordingModule("emby", calls, result="emby", priority=1,
                            module_type=ModuleType.MediaServer),
            RecordingModule("plex", calls, result="plex", priority=2,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(1, counters["index_lookups"])
        self.assertEqual(0, counters["broadcast_scans"])
        self.assertEqual("emby", answer)

    def test_it_falls_through_when_a_provider_declines(self):
        """优先级高的提供者不认领时继续问下一个，直到拿到答案。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("declines", calls, result=None, priority=1,
                            module_type=ModuleType.MediaServer),
            RecordingModule("answers", calls, result="answers", priority=2,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("answers", answer)
        self.assertEqual(["declines", "answers"], calls)

    def test_a_failing_provider_falls_through_to_the_next(self):
        """提供者抛错时按错误上报并继续问下一个。"""
        calls = []
        chain, _ = build_chain(
            FailingModule("boom", calls, priority=1, module_type=ModuleType.MediaServer),
            RecordingModule("emby", calls, result="emby", priority=2,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("emby", answer)
        chain.messagehelper.put.assert_called_once()

    def test_it_returns_none_when_nobody_answers(self):
        """族类内都不认领时返回 None。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("a", calls, result=None, module_type=ModuleType.MediaServer),
            RecordingModule("b", calls, result=None, module_type=ModuleType.MediaServer),
        )

        self.assertIsNone(chain.unicast(ModuleType.MediaServer, "notify"))
        self.assertEqual(["a", "b"], calls)

    def test_an_empty_family_returns_none_without_falling_back_to_broadcast(self):
        """族类内无提供者时返回 None，不回落到广播。"""
        calls = []
        chain, counters = build_chain(
            RecordingModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        self.assertIsNone(chain.unicast(ModuleType.MediaServer, "notify"))
        self.assertEqual([], calls)
        self.assertEqual(0, counters["broadcast_scans"])

    def test_unicast_answer_is_the_first_of_the_multicast_answers(self):
        """单播是多播的下游：它的答案就是多播答案里优先级最高的那个。"""
        calls = []
        modules = (
            RecordingModule("emby", calls, result="emby", priority=1,
                            module_type=ModuleType.MediaServer),
            RecordingModule("plex", calls, result="plex", priority=2,
                            module_type=ModuleType.MediaServer),
        )
        multicast_chain, _ = build_chain(*modules)
        unicast_chain, _ = build_chain(*modules)

        all_answers = multicast_chain.multicast(ModuleType.MediaServer, "notify")
        one_answer = unicast_chain.unicast(ModuleType.MediaServer, "notify")

        self.assertEqual(["emby", "plex"], all_answers)
        self.assertEqual(all_answers[0], one_answer)


class _Stat:
    """媒体统计替身"""

    def __init__(self, movie_count, tv_count, music_count):
        """
        :param movie_count: 电影数
        :param tv_count: 电视剧数
        :param music_count: 音乐数
        """
        self.movie_count = movie_count
        self.tv_count = tv_count
        self.music_count = music_count


class _StubModule:
    """按指定方法名返回固定结果的模块替身"""

    def __init__(self, name: str, method: str, result):
        """
        :param name: 模块名
        :param method: 提供的能力方法名
        :param result: 该能力的返回值
        """
        self._name = name
        setattr(self, method, lambda *a, **k: result)

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_priority(self) -> int:
        """模块优先级"""
        return 1


class MediaServerQueryMigrationTest(unittest.TestCase):
    """媒体服务器族的业务能力查询走查表路径，不再借广播扫全体"""

    @staticmethod
    def build_mediaserver_chain(answers_by_method):
        """
        构造与真实运行态隔离的 MediaServerChain

        :param answers_by_method: {能力方法名: [各提供者的答案]}
        :return: (链实例, 访问计数器)
        """
        from app.chain.mediaserver import MediaServerChain
        counters = {"broadcast_scans": 0, "index_lookups": 0}

        def running_modules(method):
            """广播路径，迁移后不应再被查询命中"""
            counters["broadcast_scans"] += 1
            return iter(())

        def providers_for(module_type, method):
            """查询路径：按族类与能力查表"""
            counters["index_lookups"] += 1
            return tuple(
                _StubModule(f"srv{i}", method, answer)
                for i, answer in enumerate(answers_by_method.get(method, []))
            )

        chain = MediaServerChain()
        chain.pluginmanager = Mock()
        chain.pluginmanager.running_plugins = {}
        chain.modulemanager = Mock()
        chain.modulemanager.get_running_modules.side_effect = running_modules
        chain.modulemanager.providers_for.side_effect = providers_for
        chain.messagehelper = Mock()
        chain.eventmanager = Mock()
        return chain, counters

    def test_iteminfo_takes_a_single_answer_from_the_index(self):
        """取项目信息只要一个答案，走单播查表。"""
        chain, counters = self.build_mediaserver_chain(
            {"mediaserver_iteminfo": ["item-1"]},
        )

        result = chain.iteminfo("emby", "1")

        self.assertEqual("item-1", result)
        self.assertEqual(1, counters["index_lookups"])
        self.assertEqual(0, counters["broadcast_scans"])

    def test_episodes_takes_a_single_answer_from_the_index(self):
        """取剧集信息只要一个答案，走单播查表。"""
        chain, counters = self.build_mediaserver_chain(
            {"mediaserver_tv_episodes": [["season-1"]]},
        )

        result = chain.episodes("emby", "1")

        self.assertEqual(["season-1"], result)
        self.assertEqual(0, counters["broadcast_scans"])

    def test_play_url_takes_a_single_answer_from_the_index(self):
        """取播放地址只要一个答案，走单播查表。"""
        chain, counters = self.build_mediaserver_chain(
            {"mediaserver_play_url": ["http://play/1"]},
        )

        result = chain.get_play_url("emby", "1")

        self.assertEqual("http://play/1", result)
        self.assertEqual(0, counters["broadcast_scans"])

    def test_media_count_collects_from_every_server_in_the_family(self):
        """媒体数量统计要全族答案，走多播查表并把各服务器的结果合并。"""
        chain, counters = self.build_mediaserver_chain(
            {"media_statistic": [[_Stat(1, 2, 3)], [_Stat(10, 20, 30)]]},
        )

        total = chain.media_count("emby")

        self.assertEqual(66, total)
        self.assertEqual(1, counters["index_lookups"])
        self.assertEqual(0, counters["broadcast_scans"])


if __name__ == "__main__":
    unittest.main()
