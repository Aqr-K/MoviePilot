import sys
import asyncio
import json
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import ANY, MagicMock, patch


sys.modules.setdefault("psutil", ModuleType("psutil"))
sys.modules.setdefault("cn2an", ModuleType("cn2an"))
sys.modules.setdefault("dateparser", ModuleType("dateparser"))
sys.modules.setdefault("zhconv", ModuleType("zhconv"))

if "Pinyin2Hanzi" not in sys.modules:
    pinyin_module = ModuleType("Pinyin2Hanzi")
    setattr(pinyin_module, "is_pinyin", lambda value: False)
    sys.modules["Pinyin2Hanzi"] = pinyin_module

from app.modules.feishu import FeishuModule
from app.modules.feishu.feishu import Feishu
from app.schemas import Notification
from app.schemas.types import MessageChannel


class TestFeishu(unittest.TestCase):
    @staticmethod
    def _build_client(**kwargs) -> Feishu:
        with patch.object(Feishu, "_build_api_client", return_value=MagicMock()), patch.object(
            Feishu, "_start_ws_client"
        ):
            return Feishu(
                FEISHU_APP_ID="cli_test_app_id",
                FEISHU_APP_SECRET="cli_test_app_secret",
                name="feishu-test",
                **kwargs,
            )

    @staticmethod
    def _success_response(message_id="om_test", chat_id="oc_test"):
        response = MagicMock()
        response.success.return_value = True
        response.data = SimpleNamespace(message_id=message_id, chat_id=chat_id)
        return response

    @staticmethod
    def _build_message_api(create_response=None, patch_response=None):
        message_api = SimpleNamespace(
            create=MagicMock(return_value=create_response),
            patch=MagicMock(return_value=patch_response),
            update=MagicMock(),
        )
        api_client = SimpleNamespace(im=SimpleNamespace(v1=SimpleNamespace(message=message_api)))
        return api_client, message_api

    def test_parse_message_returns_callback_message(self):
        client = self._build_client()

        result = client.parse_message(
            {
                "type": "cardAction",
                "callback_data": "approve",
                "message_id": "om_123",
                "chat_id": "oc_123",
                "sender": {
                    "open_id": "ou_user_1",
                    "user_id": "u_user_1",
                    "name": "tester",
                },
            }
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.channel, MessageChannel.Feishu)
        self.assertEqual(result.userid, "ou_user_1")
        self.assertEqual(result.text, "CALLBACK:approve")
        self.assertTrue(result.is_callback)
        self.assertEqual(result.chat_id, "oc_123")

    def test_parse_message_blocks_non_admin_command(self):
        client = self._build_client(FEISHU_ADMINS="ou_admin")

        with patch.object(client, "send_text", return_value={"success": True}) as send_text:
            result = client.parse_message(
                {
                    "type": "message",
                    "text": "/help",
                    "chat_id": "oc_chat_1",
                    "sender": {
                        "open_id": "ou_user_2",
                        "user_id": "u_user_2",
                        "name": "tester",
                    },
                }
            )

        self.assertIsNone(result)
        send_text.assert_called_once_with(
            "只有管理员才有权限执行此命令",
            userid="ou_user_2",
            chat_id="oc_chat_1",
            receive_id_type="open_id",
        )

    def test_send_notification_uses_direct_card_content(self):
        client = self._build_client()
        client._api_client, message_api = self._build_message_api(
            create_response=self._success_response()
        )

        result = client.send_notification(
            Notification(
                title="测试标题",
                text="测试正文",
                buttons=[[{"text": "确认", "callback_data": "confirm"}]],
            ),
            userid="ou_user_3",
        )

        self.assertTrue(result["success"])
        request = message_api.create.call_args.args[0]
        self.assertEqual(request.receive_id_type, "open_id")
        self.assertEqual(request.request_body.msg_type, "interactive")

        content = json.loads(request.request_body.content)
        self.assertNotIn("card", content)
        self.assertEqual(content["elements"][0]["tag"], "markdown")

    def test_send_notification_supports_user_id_target(self):
        client = self._build_client()
        client._api_client, message_api = self._build_message_api(
            create_response=self._success_response()
        )

        client.send_notification(
            Notification(title="测试标题", text="测试正文"),
            userid="u_user_4",
            receive_id_type="user_id",
        )

        request = message_api.create.call_args.args[0]
        self.assertEqual(request.receive_id_type, "user_id")

    def test_edit_message_uses_patch_api_for_cards(self):
        client = self._build_client()
        client._api_client, message_api = self._build_message_api(
            patch_response=self._success_response()
        )

        success = client.edit_message(
            message_id="om_456",
            title="测试标题",
            text="测试正文",
            buttons=[[{"text": "确认", "callback_data": "confirm"}]],
        )

        self.assertTrue(success)
        message_api.patch.assert_called_once()
        message_api.update.assert_not_called()

        request = message_api.patch.call_args.args[0]
        self.assertEqual(request.message_id, "om_456")
        content = json.loads(request.request_body.content)
        self.assertNotIn("card", content)
        self.assertEqual(content["elements"][0]["tag"], "markdown")

    def test_module_send_direct_message_prefers_open_id_target(self):
        module = FeishuModule()
        module._channel = MessageChannel.Feishu
        conf = SimpleNamespace(name="feishu-main")
        client = MagicMock()
        client.send_notification.return_value = {
            "success": True,
            "message_id": "om_789",
            "chat_id": "oc_789",
        }

        with patch.object(module, "get_configs", return_value={"feishu-main": conf}), patch.object(
            module, "check_message", return_value=True
        ), patch.object(module, "get_instance", return_value=client):
            response = module.send_direct_message(
                Notification(
                    targets={
                        "feishu_userid": "u_target",
                        "feishu_openid": "ou_target",
                    }
                )
            )

        client.send_notification.assert_called_once_with(
            message=ANY,
            userid="ou_target",
            chat_id=None,
            receive_id_type="open_id",
        )
        self.assertTrue(response.success)
        self.assertEqual(response.message_id, "om_789")
        self.assertEqual(response.chat_id, "oc_789")

    def test_run_ws_client_binds_thread_local_event_loop(self):
        client = self._build_client()
        original_loop = object()
        fake_ws_client = MagicMock()
        created_loops = []
        real_new_event_loop = asyncio.new_event_loop

        def _new_loop():
            loop = real_new_event_loop()
            created_loops.append(loop)
            return loop

        with patch("app.modules.feishu.feishu.lark_ws_client_module.loop", original_loop), patch(
            "app.modules.feishu.feishu.lark_ws_client_module._select",
            new=MagicMock(return_value=None),
        ), patch("app.modules.feishu.feishu.asyncio.new_event_loop", side_effect=_new_loop), patch(
            "app.modules.feishu.feishu.lark.ws.Client", return_value=fake_ws_client
        ), patch.object(
            fake_ws_client, "start", side_effect=lambda: None
        ) as mock_start:
            client._run_ws_client()

        self.assertIsNone(client._ws_loop)
        mock_start.assert_called_once()
        self.assertEqual(len(created_loops), 1)
        self.assertTrue(created_loops[0].is_closed())

    def test_stop_disconnects_ws_client_via_threadsafe_loop(self):
        client = self._build_client()
        stop_loop = MagicMock()
        stop_loop.is_running.return_value = True
        client._ws_loop = stop_loop
        client._ws_client = MagicMock()
        client._ws_thread = MagicMock()
        client._ws_thread.is_alive.return_value = False

        future = MagicMock()
        future.result.return_value = None

        with patch("app.modules.feishu.feishu.asyncio.run_coroutine_threadsafe", return_value=future) as runner:
            client.stop()

        runner.assert_called_once()
        future.result.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
