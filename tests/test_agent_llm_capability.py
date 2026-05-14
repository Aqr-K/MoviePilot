import sys
import unittest
import importlib.util
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.modules.setdefault("psutil", Mock())
sys.modules.setdefault("pyquery", Mock())

from app.core.config import settings

module_path = Path(__file__).resolve().parents[1] / "app" / "agent" / "llm" / "capability.py"
spec = importlib.util.spec_from_file_location("test_agent_llm_capability_module", module_path)
capability_module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = capability_module
spec.loader.exec_module(capability_module)

AgentCapabilityManager = capability_module.AgentCapabilityManager
MiMoAudioProvider = capability_module.MiMoAudioProvider
OpenAIChatAudioProvider = capability_module.OpenAIChatAudioProvider
OpenAIAudioProvider = capability_module.OpenAIAudioProvider


class AgentCapabilityManagerTest(unittest.TestCase):
    def test_registered_audio_providers_contains_builtin_providers(self):
        self.assertIn("openai", AgentCapabilityManager.get_registered_audio_providers())
        self.assertIn(
            "openai_chat_audio", AgentCapabilityManager.get_registered_audio_providers()
        )
        self.assertIn("mimo", AgentCapabilityManager.get_registered_audio_providers())

    def test_get_audio_provider_uses_separate_input_and_output_settings(self):
        with patch.object(settings, "AUDIO_INPUT_PROVIDER", "openai"), patch.object(
            settings, "AUDIO_OUTPUT_PROVIDER", "mimo"
        ):
            self.assertIsInstance(
                AgentCapabilityManager.get_audio_provider("input"), OpenAIAudioProvider
            )
            self.assertIsInstance(
                AgentCapabilityManager.get_audio_provider("output"), MiMoAudioProvider
            )

    def test_chat_audio_provider_keeps_arbitrary_compatible_models(self):
        provider = OpenAIChatAudioProvider()

        with patch.object(
            settings, "AUDIO_INPUT_MODEL", "vendor-omni-audio"
        ), patch.object(settings, "AUDIO_OUTPUT_MODEL", "vendor-tts-audio"):
            self.assertEqual(provider._normalize_stt_model(), "vendor-omni-audio")
            self.assertEqual(provider._normalize_tts_model(), "vendor-tts-audio")

    def test_chat_audio_provider_uses_openai_audio_payload_shape(self):
        provider = OpenAIChatAudioProvider()
        fake_client = Mock()
        fake_client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="你好"))]
        )

        with patch.object(provider, "_build_client", return_value=fake_client), patch.object(
            settings, "AUDIO_INPUT_MODEL", "gpt-4o-audio-preview"
        ), patch.object(settings, "AUDIO_INPUT_LANGUAGE", "zh"), patch.object(
            settings, "AUDIO_INPUT_API_KEY", "sk-test"
        ), patch.object(settings, "AUDIO_INPUT_BASE_URL", "https://example.com/v1"):
            result = provider.transcribe_audio(b"audio-bytes", filename="input.wav")

        self.assertEqual(result, "你好")
        request = fake_client.chat.completions.create.call_args.kwargs
        content = request["messages"][0]["content"]
        self.assertEqual(
            content[0]["input_audio"],
            {"data": b64encode(b"audio-bytes").decode("utf-8"), "format": "wav"},
        )

    def test_chat_audio_provider_requests_audio_modality_for_tts(self):
        provider = OpenAIChatAudioProvider()
        fake_client = Mock()
        audio_data = b64encode(b"wav-bytes").decode("utf-8")
        fake_client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(audio={"data": audio_data}))]
        )

        with TemporaryDirectory() as temp_dir, patch.object(
            provider, "_build_client", return_value=fake_client
        ), patch.object(
            capability_module,
            "settings",
            SimpleNamespace(
                TEMP_PATH=Path(temp_dir),
                AUDIO_OUTPUT_MODEL="gpt-4o-audio-preview",
                AUDIO_OUTPUT_VOICE="alloy",
                AUDIO_OUTPUT_API_KEY="sk-test",
                AUDIO_OUTPUT_BASE_URL="https://example.com/v1",
            ),
        ), patch.object(provider, "_convert_wav_to_opus", return_value=None):
            output_path = provider.synthesize_speech("你好")

        self.assertIsNotNone(output_path)
        request = fake_client.chat.completions.create.call_args.kwargs
        self.assertEqual(request["messages"][0]["role"], "user")
        self.assertEqual(request["modalities"], ["text", "audio"])
        self.assertEqual(request["audio"], {"format": "wav", "voice": "alloy"})

    def test_audio_input_and_output_switches_are_independent(self):
        provider = Mock()
        provider.is_available_for_audio_input.return_value = True
        provider.is_available_for_audio_output.return_value = True

        with patch.object(
            settings, "LLM_SUPPORT_AUDIO_INPUT", True
        ), patch.object(
            settings, "LLM_SUPPORT_AUDIO_OUTPUT", False
        ), patch.object(
            AgentCapabilityManager, "get_audio_provider", return_value=provider
        ):
            self.assertTrue(AgentCapabilityManager.is_audio_input_available())
            self.assertFalse(AgentCapabilityManager.is_audio_output_available())

        with patch.object(
            settings, "LLM_SUPPORT_AUDIO_INPUT", False
        ), patch.object(
            settings, "LLM_SUPPORT_AUDIO_OUTPUT", True
        ), patch.object(
            AgentCapabilityManager, "get_audio_provider", return_value=provider
        ):
            self.assertFalse(AgentCapabilityManager.is_audio_input_available())
            self.assertTrue(AgentCapabilityManager.is_audio_output_available())

    def test_transcribe_audio_routes_to_input_provider(self):
        provider = Mock()
        provider.is_available_for_audio_input.return_value = True
        provider.transcribe_audio.return_value = "你好"

        with patch.object(settings, "LLM_SUPPORT_AUDIO_INPUT", True), patch.object(
            AgentCapabilityManager, "get_audio_provider", return_value=provider
        ):
            result = AgentCapabilityManager.transcribe_audio(b"audio")

        self.assertEqual(result, "你好")
        provider.transcribe_audio.assert_called_once()

    def test_synthesize_speech_routes_to_output_provider(self):
        provider = Mock()
        provider.is_available_for_audio_output.return_value = True
        provider.synthesize_speech.return_value = Path("/tmp/reply.opus")

        with patch.object(settings, "LLM_SUPPORT_AUDIO_OUTPUT", True), patch.object(
            AgentCapabilityManager, "get_audio_provider", return_value=provider
        ):
            result = AgentCapabilityManager.synthesize_speech("你好")

        self.assertEqual(result, Path("/tmp/reply.opus"))
        provider.synthesize_speech.assert_called_once_with(text="你好")

    def test_mimo_tts_uses_chat_completions_audio_payload(self):
        provider = MiMoAudioProvider()
        fake_client = Mock()
        audio_data = b64encode(b"wav-bytes").decode("utf-8")
        fake_client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(audio={"data": audio_data}))]
        )

        with TemporaryDirectory() as temp_dir, patch.object(
            provider, "_build_client", return_value=fake_client
        ), patch.object(
            capability_module,
            "settings",
            SimpleNamespace(
                TEMP_PATH=Path(temp_dir),
                AUDIO_OUTPUT_MODEL="mimo-v2.5-tts",
                AUDIO_OUTPUT_VOICE="冰糖",
                AUDIO_OUTPUT_API_KEY="sk-test",
                AUDIO_OUTPUT_BASE_URL="https://api.xiaomimimo.com/v1",
            ),
        ), patch.object(provider, "_convert_wav_to_opus", return_value=None):
            output_path = provider.synthesize_speech("你好")
            output_bytes = output_path.read_bytes() if output_path else None

        self.assertIsNotNone(output_path)
        self.assertEqual(output_bytes, b"wav-bytes")
        fake_client.chat.completions.create.assert_called_once()
        request = fake_client.chat.completions.create.call_args.kwargs
        self.assertEqual(request["model"], "mimo-v2.5-tts")
        self.assertEqual(request["messages"][0]["role"], "assistant")
        self.assertEqual(request["messages"][0]["content"], "你好")
        self.assertEqual(request["audio"], {"format": "wav", "voice": "冰糖"})

    def test_mimo_tts_rejects_voice_design_and_clone_models(self):
        provider = MiMoAudioProvider()

        with patch.object(
            settings, "AUDIO_OUTPUT_MODEL", "mimo-v2.5-tts-voiceclone"
        ), patch.object(provider, "_build_client") as build_client:
            result = provider.synthesize_speech("你好")

        self.assertIsNone(result)
        build_client.assert_not_called()

    def test_mimo_stt_rejects_non_audio_mimo_models_by_falling_back(self):
        provider = MiMoAudioProvider()

        with patch.object(settings, "AUDIO_INPUT_MODEL", "mimo-v2.5-pro"):
            self.assertEqual(provider._normalize_stt_model(), "mimo-v2.5")

    def test_mimo_stt_uses_base64_audio_input(self):
        provider = MiMoAudioProvider()
        fake_client = Mock()
        fake_client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="你好"))]
        )

        with patch.object(provider, "_build_client", return_value=fake_client), patch.object(
            settings, "AUDIO_INPUT_MODEL", "mimo-v2.5"
        ), patch.object(settings, "AUDIO_INPUT_LANGUAGE", "zh"), patch.object(
            settings, "AUDIO_INPUT_API_KEY", "sk-test"
        ), patch.object(
            settings, "AUDIO_INPUT_BASE_URL", "https://api.xiaomimimo.com/v1"
        ):
            result = provider.transcribe_audio(b"audio-bytes", filename="input.wav")

        self.assertEqual(result, "你好")
        request = fake_client.chat.completions.create.call_args.kwargs
        content = request["messages"][0]["content"]
        self.assertEqual(request["model"], "mimo-v2.5")
        self.assertTrue(
            content[0]["input_audio"]["data"].startswith("data:audio/wav;base64,")
        )
        self.assertIn("只输出转写结果", content[1]["text"])


if __name__ == "__main__":
    unittest.main()
