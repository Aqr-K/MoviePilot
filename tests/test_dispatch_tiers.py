"""分发三级流水线。

广播、多播、单播不是三选一的平行选项，而是同一条选择流水线上的三级过滤：

    全体运行模块
      → [scope 圈定] ──────────────── 多播的作用域
          → [能力过滤] ───────────── 有该方法且已实现的提供者
              → [仲裁] ───────────── 单播的唯一答案

三者语义各自封闭：广播只通知不求答案，多播圈定一类收集全部答案，单播在多播圈出的
子集上再叠加优先级仲裁取唯一。单播因此是多播的下游，不是与之并列的另一套选择逻辑。
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
                 module_type=None, subtype=None):
        """
        :param name: 模块名，同时作为调用记录的标识
        :param calls: 共享的调用记录
        :param result: notify 的返回值
        :param priority: 模块优先级
        :param module_type: 模块类型，多播圈定用
        :param subtype: 模块子类型
        """
        self._name = name
        self._calls = calls
        self._result = result
        self._priority = priority
        self._type = module_type
        self._subtype = subtype

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_type(self):
        """模块类型"""
        return self._type

    def get_subtype(self):
        """模块子类型"""
        return self._subtype

    def get_priority(self) -> int:
        """模块优先级"""
        return self._priority

    def notify(self, payload=None, **kwargs):
        """接收通知"""
        self._calls.append(self._name)
        return self._result


def build_chain(*modules) -> ChainBase:
    """
    构造与真实模块、插件运行态隔离的 ChainBase

    模块管理器的三个选择器都按同一份运行态模块作答，使三级流水线共用一份事实。

    :param modules: 运行态模块替身
    :return: 链基类实例
    """
    chain = ChainBase()
    chain.pluginmanager = Mock()
    chain.pluginmanager.running_plugins = {}
    chain.modulemanager = Mock()
    chain.modulemanager.get_running_modules.side_effect = \
        lambda method: iter([m for m in modules if callable(getattr(m, method, None))])
    chain.modulemanager.get_running_type_modules.side_effect = \
        lambda module_type: iter([m for m in modules if m.get_type() == module_type])
    chain.modulemanager.get_running_subtype_module.side_effect = \
        lambda subtype: iter([m for m in modules if m.get_subtype() == subtype])
    chain.messagehelper = Mock()
    chain.eventmanager = Mock()
    return chain


class FailingModule(RecordingModule):
    """接收通知时抛错的模块替身"""

    def notify(self, payload=None, **kwargs):
        """接收通知"""
        self._calls.append(self._name)
        raise RuntimeError("提供者不可用")


class RateLimitedModule(RecordingModule):
    """接收通知时命中本地限流的模块替身"""

    def notify(self, payload=None, **kwargs):
        """接收通知"""
        self._calls.append(self._name)
        raise RateLimitExceededException("[notify] 限流期间，跳过调用")


class BroadcastTierTest(unittest.TestCase):
    """广播层：通知全体，不求答案"""

    def test_every_provider_is_notified_even_after_one_returns_a_value(self):
        """某个提供者返回了非空值也不中止，其余提供者照常收到通知。"""
        calls = []
        chain = build_chain(
            RecordingModule("first", calls, result="handled"),
            RecordingModule("second", calls),
            RecordingModule("third", calls),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["first", "second", "third"], calls)

    def test_it_returns_nothing_even_when_providers_answer(self):
        """不求答案：提供者返回了值也不向调用方交出。"""
        calls = []
        chain = build_chain(RecordingModule("only", calls, result="handled"))

        self.assertIsNone(chain.broadcast("notify", payload="x"))

    def test_a_failing_provider_does_not_stop_the_notification(self):
        """一个提供者抛错时其余提供者照常收到通知。"""
        calls = []
        chain = build_chain(
            RecordingModule("first", calls),
            FailingModule("boom", calls),
            RecordingModule("third", calls),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["first", "boom", "third"], calls)

    def test_a_failing_provider_is_reported(self):
        """提供者抛错按系统模块错误上报，不静默吞掉。"""
        calls = []
        chain = build_chain(FailingModule("boom", calls))

        chain.broadcast("notify", payload="x")

        chain.messagehelper.put.assert_called_once()

    def test_rate_limiting_is_skipped_without_an_error_report(self):
        """命中本地限流时跳过该提供者，不产生系统错误告警。"""
        calls = []
        chain = build_chain(
            RateLimitedModule("limited", calls),
            RecordingModule("third", calls),
        )

        chain.broadcast("notify", payload="x")

        self.assertEqual(["limited", "third"], calls)
        chain.messagehelper.put.assert_not_called()


class NoMethodModule(RecordingModule):
    """圈内但未实现目标方法的模块替身"""

    notify = None


class MulticastTierTest(unittest.TestCase):
    """多播层：圈定一类，收集所有答案"""

    def test_it_collects_an_answer_from_every_provider_in_the_scope(self):
        """圈定的一类里每个提供者都被调用，答案按序收集。"""
        calls = []
        chain = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("plex", calls, result="plex", module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby", "plex"], answers)
        self.assertEqual(["emby", "plex"], calls)

    def test_providers_outside_the_scope_are_not_touched(self):
        """圈外的模块一个都不被调用，即使它实现了同名方法。"""
        calls = []
        chain = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("qbittorrent", calls, result="qb", module_type=ModuleType.Downloader),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        self.assertEqual(["emby"], calls)

    def test_empty_answers_are_dropped(self):
        """只收集有效答案，返回 None 的提供者不进结果。"""
        calls = []
        chain = build_chain(
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
            RecordingModule("silent", calls, result=None, module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        self.assertEqual(["emby", "silent"], calls)

    def test_a_provider_without_the_capability_is_filtered_out(self):
        """圈内但未实现该方法的模块被能力过滤挡掉，不报错。"""
        calls = []
        chain = build_chain(
            NoMethodModule("legacy", calls, module_type=ModuleType.MediaServer),
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        chain.messagehelper.put.assert_not_called()

    def test_a_failing_provider_does_not_lose_the_other_answers(self):
        """一个提供者抛错时其余答案照常收集。"""
        calls = []
        chain = build_chain(
            FailingModule("boom", calls, module_type=ModuleType.MediaServer),
            RecordingModule("emby", calls, result="emby", module_type=ModuleType.MediaServer),
        )

        answers = chain.multicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["emby"], answers)
        chain.messagehelper.put.assert_called_once()

    def test_an_empty_scope_yields_no_answers(self):
        """圈内没有提供者时返回空列表，不回落到广播。"""
        calls = []
        chain = build_chain(
            RecordingModule("qbittorrent", calls, result="qb", module_type=ModuleType.Downloader),
        )

        self.assertEqual([], chain.multicast(ModuleType.MediaServer, "notify", payload="x"))
        self.assertEqual([], calls)


class UnicastTierTest(unittest.TestCase):
    """单播层：在多播圈出的子集上仲裁，最终只要一个答案"""

    def test_the_highest_priority_provider_answers(self):
        """圈内按优先级择一，数字小的先答。"""
        calls = []
        chain = build_chain(
            RecordingModule("low", calls, result="low", priority=9,
                            module_type=ModuleType.MediaServer),
            RecordingModule("high", calls, result="high", priority=1,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("high", answer)
        self.assertEqual(["high"], calls)

    def test_it_stops_at_the_first_answer(self):
        """拿到答案即停，后续提供者不被执行。"""
        calls = []
        chain = build_chain(
            RecordingModule("first", calls, result="first", priority=1,
                            module_type=ModuleType.MediaServer),
            RecordingModule("second", calls, result="second", priority=2,
                            module_type=ModuleType.MediaServer),
        )

        chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual(["first"], calls)

    def test_it_falls_through_when_a_provider_declines(self):
        """优先级高的提供者不认领时继续问下一个，直到拿到答案。"""
        calls = []
        chain = build_chain(
            RecordingModule("declines", calls, result=None, priority=1,
                            module_type=ModuleType.MediaServer),
            RecordingModule("answers", calls, result="answers", priority=2,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("answers", answer)
        self.assertEqual(["declines", "answers"], calls)

    def test_providers_outside_the_scope_never_arbitrate(self):
        """圈外的提供者不参与仲裁，即使优先级更高。"""
        calls = []
        chain = build_chain(
            RecordingModule("qbittorrent", calls, result="qb", priority=0,
                            module_type=ModuleType.Downloader),
            RecordingModule("emby", calls, result="emby", priority=5,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("emby", answer)
        self.assertEqual(["emby"], calls)

    def test_a_failing_provider_falls_through_to_the_next(self):
        """提供者抛错时按错误上报并继续问下一个。"""
        calls = []
        chain = build_chain(
            FailingModule("boom", calls, priority=1, module_type=ModuleType.MediaServer),
            RecordingModule("emby", calls, result="emby", priority=2,
                            module_type=ModuleType.MediaServer),
        )

        answer = chain.unicast(ModuleType.MediaServer, "notify", payload="x")

        self.assertEqual("emby", answer)
        chain.messagehelper.put.assert_called_once()

    def test_it_returns_none_when_nobody_answers(self):
        """圈内都不认领时返回 None。"""
        calls = []
        chain = build_chain(
            RecordingModule("a", calls, result=None, module_type=ModuleType.MediaServer),
            RecordingModule("b", calls, result=None, module_type=ModuleType.MediaServer),
        )

        self.assertIsNone(chain.unicast(ModuleType.MediaServer, "notify", payload="x"))
        self.assertEqual(["a", "b"], calls)

    def test_an_empty_scope_returns_none_without_falling_back_to_broadcast(self):
        """圈内无提供者时返回 None，不回落到广播。"""
        calls = []
        chain = build_chain(
            RecordingModule("qbittorrent", calls, result="qb", module_type=ModuleType.Downloader),
        )

        self.assertIsNone(chain.unicast(ModuleType.MediaServer, "notify", payload="x"))
        self.assertEqual([], calls)

    def test_it_reuses_the_multicast_scope(self):
        """单播的候选集与多播圈出的子集是同一个，只是多了仲裁与短路。"""
        calls = []
        modules = (
            RecordingModule("emby", calls, result="emby", priority=1,
                            module_type=ModuleType.MediaServer),
            RecordingModule("plex", calls, result="plex", priority=2,
                            module_type=ModuleType.MediaServer),
        )
        multicast_chain = build_chain(*modules)
        unicast_chain = build_chain(*modules)

        all_answers = multicast_chain.multicast(ModuleType.MediaServer, "notify")
        one_answer = unicast_chain.unicast(ModuleType.MediaServer, "notify")

        self.assertEqual(["emby", "plex"], all_answers)
        self.assertEqual(all_answers[0], one_answer)


if __name__ == "__main__":
    unittest.main()
