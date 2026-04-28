import unittest
from unittest.mock import patch

from app.agent.middleware.memory import MEMORY_ONBOARDING_PROMPT
from app.agent.prompt import prompt_manager
from app.core.config import settings


class TestAgentPromptStyle(unittest.TestCase):
    def test_agent_prompt_enforces_concise_professional_style(self):
        prompt = prompt_manager.get_agent_prompt()

        self.assertIn("professional, concise, restrained", prompt)
        self.assertIn("Do NOT flatter the user", prompt)
        self.assertIn("NO praise, emotional cushioning", prompt)

    def test_agent_prompt_defines_tv_subscription_default_season_rule(self):
        prompt = prompt_manager.get_agent_prompt()

        self.assertIn(
            "omitting `season` means subscribe to season 1 only",
            prompt,
        )
        self.assertIn(
            "call `add_subscribe` separately for each season",
            prompt,
        )

    def test_prompt_uses_root_runtime_sections(self):
        prompt = prompt_manager.get_agent_prompt()

        self.assertIn("<agent_profile>", prompt)
        self.assertIn("<agent_workflow>", prompt)
        self.assertIn("Active persona: `default`", prompt)

    def test_non_verbose_prompt_requires_silence_until_all_tools_finish(self):
        with patch.object(settings, "AI_AGENT_VERBOSE", False):
            prompt = prompt_manager.get_agent_prompt()

        self.assertIn(
            "[Important Instruction] STRICTLY ENFORCED:",
            prompt,
        )
        self.assertIn(
            "DO NOT output any conversational text, explanations, progress updates, or acknowledgements before the first tool call or between tool calls",
            prompt,
        )
        self.assertIn(
            "Only then may you send one final user-facing reply",
            prompt,
        )

    def test_verbose_prompt_does_not_inject_silence_until_tools_finish_rule(self):
        with patch.object(settings, "AI_AGENT_VERBOSE", True):
            prompt = prompt_manager.get_agent_prompt()

        self.assertNotIn(
            "DO NOT output any conversational text, explanations, progress updates, or acknowledgements before the first tool call or between tool calls",
            prompt,
        )

    def test_memory_onboarding_does_not_force_warm_intro(self):
        self.assertIn("Do NOT interrupt the current task", MEMORY_ONBOARDING_PROMPT)
        self.assertIn("Do NOT proactively greet warmly", MEMORY_ONBOARDING_PROMPT)
        self.assertNotIn("greet the user warmly", MEMORY_ONBOARDING_PROMPT)


if __name__ == "__main__":
    unittest.main()
