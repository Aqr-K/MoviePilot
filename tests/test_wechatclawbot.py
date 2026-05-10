import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.modules.wechatclawbot import WechatClawBotModule
from app.modules.wechatclawbot.wechatclawbot import ILinkClient


class WechatClawBotTest(unittest.TestCase):
    def test_ilink_parse_incoming_uses_seq_as_message_id_fallback(self):
        client = ILinkClient(base_url="https://ilinkai.weixin.qq.com")

        message = client._parse_incoming(
            {
                "seq": 123456,
                "from_user_id": "wxid_user_1",
                "item_list": [{"type": 1, "text_item": {"text": "你好"}}],
            }
        )

        self.assertIsNotNone(message)
        self.assertEqual(message.message_id, "123456")
        self.assertEqual(message.text, "你好")

    def test_wechatclawbot_message_parser_deduplicates_message_id(self):
        module = WechatClawBotModule()
        body = json.dumps(
            {
                "__channel__": "wechatclawbot",
                "userid": "wxid_user_1",
                "username": "tester",
                "message_id": "msg-1001",
                "text": "刷新订阅",
            }
        )

        with patch.object(
            module,
            "get_config",
            return_value=SimpleNamespace(name="wechatclawbot-test", config={}),
        ):
            first = module.message_parser(
                source="wechatclawbot-test",
                body=body,
                form={},
                args={},
            )
            second = module.message_parser(
                source="wechatclawbot-test",
                body=body,
                form={},
                args={},
            )

        self.assertIsNotNone(first)
        self.assertEqual(first.message_id, "msg-1001")
        self.assertIsNone(second)


if __name__ == "__main__":
    unittest.main()
