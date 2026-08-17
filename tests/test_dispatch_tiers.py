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

import pytest

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


class NoCapabilityModule(RecordingModule):
    """不提供该能力的模块替身"""

    notify = None


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

    def providers_for(method):
        """查询路径：按能力查表"""
        counters["index_lookups"] += 1
        return tuple(sorted(
            (m for m in modules if callable(getattr(m, method, None))),
            key=lambda m: m.get_priority(),
        ))

    chain = ChainBase()
    chain.pluginmanager = Mock()
    chain.pluginmanager.running_plugins = {}
    # 默认无插件注入；需要插件参与的用例各自覆盖
    chain.pluginmanager.get_plugin_modules.return_value = {}
    chain.modulemanager = Mock()
    chain.modulemanager.get_running_modules.side_effect = running_modules
    chain.modulemanager.providers_for.side_effect = providers_for
    chain.messagehelper = Mock()
    chain.eventmanager = Mock()
    return chain, counters


class BroadcastTierTest(unittest.TestCase):
    """广播：通知全体，不求答案，遍历是语义不是缺陷"""

    def test_plugin_injected_providers_are_notified_too(self):
        """插件经 get_module() 注入的方法同样要收到通知。

        广播若只遍历运行态模块，把方法从 run_module 迁过来就会让挂在其上的插件静默
        失效——与多播、单播必须一致。
        """
        calls = []
        chain, _ = build_chain(RecordingModule("emby", calls))
        chain.pluginmanager.get_plugin_modules.return_value = {
            ("Hijacker", "插件"): {"notify": lambda **kw: calls.append("plugin")},
        }

        chain.broadcast("notify", payload="x")

        self.assertEqual(["plugin", "emby"], calls)

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

        answers = chain.multicast("notify", payload="x")

        self.assertEqual(["emby", "plex"], answers)

    def test_it_queries_the_index_instead_of_walking_every_module(self):
        """查询走注册表，不再遍历全体模块。"""
        calls = []
        chain, counters = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        chain.multicast("notify", payload="x")

        self.assertEqual(1, counters["index_lookups"])
        self.assertEqual(0, counters["broadcast_scans"])

    def test_modules_without_the_capability_are_not_touched(self):
        """不提供该能力的模块一个都不被调用。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            NoCapabilityModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        answers = chain.multicast("notify", payload="x")

        self.assertEqual(["emby"], answers)
        self.assertEqual(["emby"], calls)

    def test_empty_answers_are_dropped(self):
        """只收集有效答案，返回 None 的提供者不进结果。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("silent", calls, result=None, module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast("notify", payload="x")

        self.assertEqual(["emby"], answers)
        self.assertEqual(["emby", "silent"], calls)

    def test_a_failing_provider_does_not_lose_the_other_answers(self):
        """一个提供者抛错时其余答案照常收集。"""
        calls = []
        chain, _ = build_chain(
            FailingModule("boom", calls, module_type=ModuleType.MediaServer),
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast("notify", payload="x")

        self.assertEqual(["emby"], answers)
        chain.messagehelper.put.assert_called_once()

    def test_an_unprovided_capability_yields_no_answers(self):
        """无人提供该能力时返回空列表，不回落到广播。"""
        calls = []
        chain, counters = build_chain(
            NoCapabilityModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        self.assertEqual([], chain.multicast("notify"))
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

        answer = chain.unicast("notify", payload="x")

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

        answer = chain.unicast("notify", payload="x")

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

        answer = chain.unicast("notify", payload="x")

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

        answer = chain.unicast("notify", payload="x")

        self.assertEqual("emby", answer)
        chain.messagehelper.put.assert_called_once()

    def test_it_returns_none_when_nobody_answers(self):
        """族类内都不认领时返回 None。"""
        calls = []
        chain, _ = build_chain(
            RecordingModule("a", calls, result=None, module_type=ModuleType.MediaServer),
            RecordingModule("b", calls, result=None, module_type=ModuleType.MediaServer),
        )

        self.assertIsNone(chain.unicast("notify"))
        self.assertEqual(["a", "b"], calls)

    def test_an_unprovided_capability_returns_none_without_falling_back_to_broadcast(self):
        """无人提供该能力时返回 None，不回落到广播。"""
        calls = []
        chain, counters = build_chain(
            NoCapabilityModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
        )

        self.assertIsNone(chain.unicast("notify"))
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

        all_answers = multicast_chain.multicast("notify")
        one_answer = unicast_chain.unicast("notify")

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

        def providers_for(method):
            """查询路径：按族类与能力查表"""
            counters["index_lookups"] += 1
            return tuple(
                _StubModule(f"srv{i}", method, answer)
                for i, answer in enumerate(answers_by_method.get(method, []))
            )

        chain = MediaServerChain()
        chain.pluginmanager = Mock()
        chain.pluginmanager.running_plugins = {}
        chain.pluginmanager.get_plugin_modules.return_value = {}
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


class PluginProviderTest(unittest.TestCase):
    """插件经 get_module() 注入的方法同样是提供者

    迁移的前提是行为等价：run_module 会先执行插件注入的同名方法，多播与单播若看不见
    它们，把一个方法从广播迁过来就会让挂在其上的插件静默失效。
    """

    @staticmethod
    def build(modules, plugin_methods):
        """
        构造同时提供系统模块与插件注入方法的链

        :param modules: 运行态模块替身
        :param plugin_methods: {(插件ID, 插件名): {方法名: 函数}}
        :return: (链实例, 计数器)
        """
        chain, counters = build_chain(*modules)
        chain.pluginmanager.get_plugin_modules.return_value = plugin_methods
        return chain, counters

    def test_multicast_collects_plugin_answers_too(self):
        """多播同时收集插件与系统模块的答案，插件在前。"""
        calls = []
        chain, _ = self.build(
            [RecordingModule("emby", calls, result="emby",
                             module_type=ModuleType.MediaServer)],
            {("Hijacker", "插件"): {"notify": lambda **kw: "plugin"}},
        )

        answers = chain.multicast("notify", payload="x")

        self.assertEqual(["plugin", "emby"], answers)

    def test_unicast_lets_the_plugin_answer_first(self):
        """单播里插件优先，插件认领后系统模块不再执行。"""
        calls = []
        chain, _ = self.build(
            [RecordingModule("emby", calls, result="emby",
                             module_type=ModuleType.MediaServer)],
            {("Hijacker", "插件"): {"notify": lambda **kw: "plugin"}},
        )

        answer = chain.unicast("notify", payload="x")

        self.assertEqual("plugin", answer)
        self.assertEqual([], calls)

    def test_unicast_falls_through_when_the_plugin_declines(self):
        """插件返回空表示不认领，仲裁继续下移到系统模块。"""
        calls = []
        chain, _ = self.build(
            [RecordingModule("emby", calls, result="emby",
                             module_type=ModuleType.MediaServer)],
            {("Hijacker", "插件"): {"notify": lambda **kw: None}},
        )

        answer = chain.unicast("notify", payload="x")

        self.assertEqual("emby", answer)

    def test_a_failing_plugin_is_reported_as_a_plugin_error(self):
        """插件抛错按插件错误上报，且不阻断系统提供者。"""
        calls = []

        def boom(**kwargs):
            """抛错的插件方法"""
            raise RuntimeError("插件不可用")

        chain, _ = self.build(
            [RecordingModule("emby", calls, result="emby",
                             module_type=ModuleType.MediaServer)],
            {("Hijacker", "插件"): {"notify": boom}},
        )

        answer = chain.unicast("notify", payload="x")

        self.assertEqual("emby", answer)
        self.assertEqual("plugin", chain.messagehelper.put.call_args.kwargs["role"])


@pytest.mark.asyncio
async def test_async_broadcast_notifies_every_provider():
    """异步广播同样触达全体，不因谁返回了值而中止。"""
    calls = []
    chain, counters = build_chain(
        RecordingModule("first", calls, result="handled"),
        RecordingModule("second", calls),
    )
    chain.pluginmanager.get_plugin_modules.return_value = {}

    result = await chain.async_broadcast("notify", payload="x")

    assert calls == ["first", "second"]
    assert result is None
    assert counters["index_lookups"] == 0


@pytest.mark.asyncio
async def test_async_multicast_collects_every_answer_from_the_index():
    """异步多播经注册表查表，收集族类内全部答案。"""
    calls = []
    chain, counters = build_chain(
        RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
        RecordingModule("plex", calls, result="plex", module_type=ModuleType.MediaServer),
        NoCapabilityModule("qb", calls, result="qb", module_type=ModuleType.Downloader),
    )
    chain.pluginmanager.get_plugin_modules.return_value = {}

    answers = await chain.async_multicast("notify")

    assert answers == ["emby", "plex"]
    assert counters["index_lookups"] == 1
    assert counters["broadcast_scans"] == 0


@pytest.mark.asyncio
async def test_async_unicast_arbitrates_on_the_same_index():
    """异步单播在同一张表上仲裁，取优先级最高且认领的答案。"""
    calls = []
    chain, counters = build_chain(
        RecordingModule("low", calls, result="low", priority=9,
                        module_type=ModuleType.MediaServer),
        RecordingModule("high", calls, result="high", priority=1,
                        module_type=ModuleType.MediaServer),
    )
    chain.pluginmanager.get_plugin_modules.return_value = {}

    answer = await chain.async_unicast("notify")

    assert answer == "high"
    assert calls == ["high"]


@pytest.mark.asyncio
async def test_async_dispatch_awaits_coroutine_providers():
    """提供者是协程函数时被 await，而非返回协程对象。"""

    class AsyncModule(RecordingModule):
        """协程实现的模块替身"""

        async def notify(self, payload=None, **kwargs):
            """异步能力方法"""
            self._calls.append(self._name)
            return self._result

    calls = []
    chain, _ = build_chain(
        AsyncModule("async_emby", calls, result="awaited",
                    module_type=ModuleType.MediaServer),
    )
    chain.pluginmanager.get_plugin_modules.return_value = {}

    answer = await chain.async_unicast("notify")

    assert answer == "awaited"
    assert calls == ["async_emby"]


class HookModule:
    """实现通知钩子的模块替身"""

    def __init__(self, name: str, calls: list, result=None):
        """
        :param name: 模块名
        :param calls: 共享的调用记录
        :param result: 钩子的返回值
        """
        self._name = name
        self._calls = calls
        self._result = result

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_priority(self) -> int:
        """模块优先级"""
        return 1

    def clear_cache(self, **kwargs):
        """响应清理缓存"""
        self._calls.append(self._name)
        return self._result

    def scheduler_job(self, **kwargs):
        """响应定时调度"""
        self._calls.append(self._name)
        return self._result

    def register_commands(self, commands=None, **kwargs):
        """响应命令注册"""
        self._calls.append(self._name)
        return self._result


class NotificationHookMigrationTest(unittest.TestCase):
    """定时、清缓存、注册命令是通知，不是查询

    这三个钩子都声明返回 None，语义是「模块实现该接口以响应」。它们此前走 run_module，
    一旦某个模块返回了非空非列表的值就 break，排在后面的模块收不到通知——对通知语义
    这是缺陷而非优化。改走广播后全体必达。
    """

    def test_clear_cache_reaches_every_module_even_after_one_answers(self):
        """清理缓存必达全体：某个模块返回了值也不中止其余模块。"""
        calls = []
        chain, _ = build_chain(
            HookModule("first", calls, result="done"),
            HookModule("second", calls),
            HookModule("third", calls),
        )

        chain.clear_cache()

        self.assertEqual(["first", "second", "third"], calls)

    def test_scheduler_job_reaches_every_module_even_after_one_answers(self):
        """定时任务必达全体：某个模块返回了值也不中止其余模块。"""
        calls = []
        chain, _ = build_chain(
            HookModule("first", calls, result="done"),
            HookModule("second", calls),
        )

        chain.scheduler_job()

        self.assertEqual(["first", "second"], calls)

    def test_register_commands_reaches_every_module_even_after_one_answers(self):
        """注册命令必达全体：某个模块返回了值也不中止其余模块。"""
        calls = []
        chain, _ = build_chain(
            HookModule("first", calls, result="done"),
            HookModule("second", calls),
        )

        chain.register_commands({})

        self.assertEqual(["first", "second"], calls)

    def test_these_hooks_never_consult_the_index(self):
        """通知走全体遍历，不查注册表。"""
        calls = []
        chain, counters = build_chain(HookModule("only", calls))

        chain.clear_cache()

        self.assertEqual(0, counters["index_lookups"])


class RecognizeFamilyMigrationTest(unittest.TestCase):
    """媒体识别是查询：依次试、首个非空胜出，正是单播的语义"""

    def test_native_recognize_queries_the_recognize_family(self):
        """原生识别经识别族查表取单一答案，不再扫全体模块。"""
        chain, counters = build_chain()
        chain.modulemanager.providers_for.side_effect = (
            lambda method: (_StubModule("tmdb", method, "media-info"),)
        )

        result = chain._run_native_media_recognize({"meta": None}, cache=True)

        self.assertEqual("media-info", result)
        self.assertEqual(0, counters["broadcast_scans"])


@pytest.mark.asyncio
async def test_async_native_recognize_queries_the_recognize_family():
    """异步原生识别同样经识别族查表，不再扫全体模块。"""
    chain, counters = build_chain()
    chain.modulemanager.providers_for.side_effect = (
        lambda method: (_StubModule("tmdb", method, "media-info"),)
    )

    result = await chain._async_run_native_media_recognize({"meta": None}, cache=True)

    assert result == "media-info"
    assert counters["broadcast_scans"] == 0


if __name__ == "__main__":
    unittest.main()
