"""消息发送主干的分发语义。

post_message 的全部发送点都汇入消息队列，由队列回调落到分发层。这条主干是多播：
认领的渠道都要发出，任何短路都会让消息只到达第一个渠道。
"""
import sys
import unittest
from types import ModuleType as _PyModuleType
from unittest.mock import Mock, patch

sys.modules.setdefault("qbittorrentapi", _PyModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", _PyModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)

from app.chain import ChainBase  # noqa: E402
from app.chain import dispatch as chain_dispatch  # noqa: E402


class ChannelModule:
    """渠道模块替身，post_message 返回 None，与全部真实渠道实现一致"""

    def __init__(self, name: str, calls: list, priority: int = 1, result=None):
        """
        :param name: 渠道名，同时作为调用记录的标识
        :param calls: 共享的调用记录
        :param priority: 模块优先级
        :param result: post_message 的返回值
        """
        self._name = name
        self._calls = calls
        self._priority = priority
        self._result = result

    def get_name(self) -> str:
        """模块名称"""
        return self._name

    def get_priority(self) -> int:
        """模块优先级"""
        return self._priority

    def post_message(self, message=None, **kwargs):
        """发送消息"""
        self._calls.append(self._name)
        return self._result


def build_chain(*modules):
    """
    构造与真实模块、插件运行态隔离的 ChainBase，并分别记录两条分发路径的访问次数

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
    chain.pluginmanager.get_plugin_modules.return_value = {}
    chain.modulemanager = Mock()
    chain.modulemanager.get_running_modules.side_effect = running_modules
    chain.modulemanager.providers_for.side_effect = providers_for
    chain.messagehelper = Mock()
    chain.eventmanager = Mock()
    # 队列是单例，回调只在首个 ChainBase 构造时绑定，此处重绑到本实例
    chain.messagequeue.send_callback = chain.multicast
    return chain, counters


class PostMessageTrunkTest(unittest.TestCase):
    """消息主干：队列回调经能力索引分发到每一个认领的渠道"""

    def test_init_wires_queue_callback_to_multicast(self):
        """ChainBase 构造时把队列回调接到默认分发器的多播原语。

        队列是单例，回调只在首个实例构造时绑定，因此这条接线无法由行为用例覆盖，
        单独锁定。回调是分发器函数而非链实例方法，队列不持有任何链实例。
        """
        with patch("app.chain.MessageQueueManager") as queue_cls:
            ChainBase()

        callback = queue_cls.call_args.kwargs["send_callback"]
        self.assertIs(callback, chain_dispatch.multicast)

    def test_queue_callback_dispatches_via_capability_index(self):
        """队列回调查能力索引，不再回落到全体遍历。

        渠道是一个族类，「谁能发消息」是查询而非通知，因此代价应为 O(k) 而不是 O(n)。
        """
        calls = []
        chain, counters = build_chain(
            ChannelModule("wechat", calls),
            ChannelModule("telegram", calls, priority=2),
        )

        chain.messagequeue._send("post_message", message=None)

        self.assertEqual(sorted(calls), ["telegram", "wechat"])
        self.assertGreater(counters["index_lookups"], 0)
        self.assertEqual(counters["broadcast_scans"], 0)

    def test_every_channel_receives_even_when_one_answers(self):
        """某个渠道返回了非空值，其余渠道仍须收到。

        锁死多播语义：单播在首个非空答案处短路，用在这里会让消息只发出一份。
        """
        calls = []
        chain, _ = build_chain(
            ChannelModule("wechat", calls, priority=1, result="sent"),
            ChannelModule("telegram", calls, priority=2),
            ChannelModule("slack", calls, priority=3),
        )

        chain.messagequeue._send("post_message", message=None)

        self.assertEqual(calls, ["wechat", "telegram", "slack"])

    def test_failing_channel_does_not_block_the_rest(self):
        """单个渠道抛错不影响其余渠道发出"""
        calls = []

        class BrokenChannel(ChannelModule):
            """发送时抛错的渠道替身"""

            def post_message(self, message=None, **kwargs):
                """发送消息"""
                self._calls.append(self._name)
                raise RuntimeError("渠道不可用")

        chain, _ = build_chain(
            BrokenChannel("broken", calls, priority=1),
            ChannelModule("telegram", calls, priority=2),
        )

        chain.messagequeue._send("post_message", message=None)

        self.assertEqual(calls, ["broken", "telegram"])


if __name__ == "__main__":
    unittest.main()
