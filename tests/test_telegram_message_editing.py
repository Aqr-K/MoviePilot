import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from app.modules.telegram.telegram import Telegram


class TestTelegramMessageEditing(unittest.TestCase):
    def _build_telegram(self) -> Telegram:
        telegram = Telegram.__new__(Telegram)
        telegram._bot = Mock()
        telegram._telegram_token = "token-123"
        telegram._telegram_chat_id = "456"
        telegram._message_payload_cache = {}
        telegram._typing_tasks = {}
        telegram._typing_stop_flags = {}
        telegram._user_chat_mapping = {}
        return telegram

    def test_edit_msg_skips_duplicate_payload_after_initial_send(self):
        telegram = self._build_telegram()
        telegram._bot.send_message.return_value = SimpleNamespace(
            message_id=11, chat=SimpleNamespace(id="456")
        )

        result = telegram.send_msg(title="", text="abc")
        self.assertTrue(result["success"])

        edited = telegram.edit_msg(chat_id="456", message_id=11, text="abc  ")

        self.assertTrue(edited)
        telegram._bot.edit_message_text.assert_not_called()

    def test_edit_msg_treats_message_not_modified_as_success(self):
        telegram = self._build_telegram()
        telegram._bot.edit_message_text.side_effect = Exception(
            "A request to the Telegram API was unsuccessful. "
            "Error code: 400. Description: Bad Request: message is not modified: "
            "specified new message content and reply markup are exactly the same as "
            "a current content and reply markup of the message"
        )

        first = telegram.edit_msg(chat_id="456", message_id=12, text="abc")
        second = telegram.edit_msg(chat_id="456", message_id=12, text="abc")

        self.assertTrue(first)
        self.assertTrue(second)
        telegram._bot.edit_message_text.assert_called_once()


if __name__ == "__main__":
    unittest.main()
