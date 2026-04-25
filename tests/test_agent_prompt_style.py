import unittest

from app.agent.middleware.memory import MEMORY_ONBOARDING_PROMPT
from app.agent.prompt import prompt_manager


class TestAgentPromptStyle(unittest.TestCase):
    def test_agent_prompt_enforces_concise_professional_style(self):
        prompt = prompt_manager.get_agent_prompt()

        self.assertIn("professional, concise, restrained", prompt)
        self.assertIn("Do NOT flatter the user", prompt)
        self.assertIn("NO praise, emotional cushioning", prompt)

    def test_memory_onboarding_does_not_force_warm_intro(self):
        self.assertIn("Do NOT interrupt the current task", MEMORY_ONBOARDING_PROMPT)
        self.assertIn("Do NOT proactively greet warmly", MEMORY_ONBOARDING_PROMPT)
        self.assertNotIn("greet the user warmly", MEMORY_ONBOARDING_PROMPT)


if __name__ == "__main__":
    unittest.main()
