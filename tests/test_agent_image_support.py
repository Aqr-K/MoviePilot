import base64
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.agent.tools.impl.send_message import SendMessageInput
from app.chain.message import MessageChain
from app.core.config import settings
from app.modules.slack import SlackModule
from app.modules.telegram.telegram import Telegram
from app.modules.telegram import TelegramModule
from app.schemas import CommingMessage
from app.schemas.types import MessageChannel


class AgentImageSupportTest(unittest.TestCase):
    def test_telegram_extract_images_returns_prefixed_file_ids(self):
        images = TelegramModule._extract_images(
            {
                "photo": [{"file_id": "small"}, {"file_id": "large"}],
                "document": {"file_id": "doc-image", "mime_type": "image/png"},
            }
        )

        self.assertEqual(
            images,
            ["tg://file_id/large", "tg://file_id/doc-image"],
        )

    def test_telegram_message_parser_accepts_double_encoded_body(self):
        module = TelegramModule()
        body = json.dumps(
            json.dumps(
                {
                    "message": {
                        "from": {"id": 10001, "username": "tester"},
                        "chat": {"id": 10001, "type": "private"},
                        "photo": [{"file_id": "small"}, {"file_id": "large"}],
                    }
                }
            )
        )

        with patch.object(
            module,
            "get_config",
            return_value=SimpleNamespace(name="telegram-test", config={}),
        ), patch.object(
            module,
            "get_instance",
            return_value=SimpleNamespace(bot_username=None),
        ):
            message = module.message_parser(
                source="telegram-test", body=body, form={}, args={}
            )

        self.assertIsNotNone(message)
        self.assertEqual(message.images, ["tg://file_id/large"])

    def test_telegram_forward_payload_uses_dict_not_json_string(self):
        payload = Telegram._serialize_update_payload(
            SimpleNamespace(
                to_dict=lambda: {
                    "text": "hi",
                    "photo": [{"file_id": "image-1"}],
                }
            )
        )

        self.assertEqual(
            payload,
            {"text": "hi", "photo": [{"file_id": "image-1"}]},
        )

    def test_process_allows_image_only_message(self):
        chain = MessageChain()
        message = CommingMessage(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            userid="10001",
            username="tester",
            images=["tg://file_id/image-1"],
        )

        with patch.object(chain, "message_parser", return_value=message), patch.object(
            chain, "handle_message"
        ) as handle_message:
            chain.process(body="{}", form={}, args={"source": "telegram-test"})

        handle_kwargs = handle_message.call_args.kwargs
        self.assertEqual(handle_kwargs["text"], "")
        self.assertEqual(handle_kwargs["images"], ["tg://file_id/image-1"])

    def test_image_message_routes_to_agent_even_when_global_agent_is_disabled(self):
        chain = MessageChain()

        with patch.object(chain, "load_cache", return_value={}), patch.object(
            chain.messagehelper, "put"
        ), patch.object(chain.messageoper, "add"), patch.object(
            chain, "_handle_ai_message"
        ) as handle_ai_message, patch.object(
            settings, "AI_AGENT_ENABLE", True
        ), patch.object(
            settings, "AI_AGENT_GLOBAL", False
        ):
            chain.handle_message(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                text="",
                images=["tg://file_id/image-1"],
            )

        handle_ai_message.assert_called_once()

    def test_slack_images_use_authenticated_data_url_download(self):
        chain = MessageChain()

        with patch.object(
            chain,
            "run_module",
            return_value="data:image/png;base64,abc123",
        ) as run_module:
            images = chain._download_images_to_base64(
                images=["https://files.slack.com/files-pri/T1-F1/test.png"],
                channel=MessageChannel.Slack,
                source="slack-test",
            )

        self.assertEqual(images, ["data:image/png;base64,abc123"])
        run_module.assert_called_once_with(
            "download_file_to_data_url",
            file_url="https://files.slack.com/files-pri/T1-F1/test.png",
            source="slack-test",
        )

    def test_slack_module_download_file_to_data_url(self):
        module = SlackModule()
        client = Mock()
        client.download_file.return_value = (b"png-binary", "image/png")

        with patch.object(
            module, "get_config", return_value=SimpleNamespace(name="slack-test")
        ), patch.object(module, "get_instance", return_value=client):
            data_url = module.download_file_to_data_url(
                "https://files.slack.com/files-pri/T1-F1/test.png",
                "slack-test",
            )

        self.assertEqual(
            data_url,
            f"data:image/png;base64,{base64.b64encode(b'png-binary').decode()}",
        )

    def test_send_message_input_accepts_image_only_payload(self):
        payload = SendMessageInput(
            explanation="send poster image",
            image_url="https://example.com/poster.png",
        )

        self.assertEqual(payload.image_url, "https://example.com/poster.png")

if __name__ == "__main__":
    unittest.main()
