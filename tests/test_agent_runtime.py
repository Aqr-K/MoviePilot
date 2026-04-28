import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path

from app.agent.runtime import AgentRuntimeConfigError, AgentRuntimeManager


class TestAgentRuntimeConfig(unittest.TestCase):
    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.temp_root = Path(self._tempdir.name)
        self.agent_root = self.temp_root / "agent"
        self.bundled_root = (
            Path(__file__).resolve().parents[1] / "app" / "agent" / "runtime_defaults"
        )

    def _manager(self) -> AgentRuntimeManager:
        return AgentRuntimeManager(
            agent_root_dir=self.agent_root,
            bundled_runtime_dir=self.bundled_root,
        )

    def test_load_runtime_config_syncs_defaults_and_parses_sections(self):
        manager = self._manager()

        runtime_config = manager.load_runtime_config()

        self.assertEqual(runtime_config.active_persona, "default")
        self.assertIn("professional, concise, restrained", runtime_config.profile_text)
        self.assertIn(
            "omitting `season` means subscribe to season 1 only",
            runtime_config.workflow_text,
        )
        self.assertTrue((self.agent_root / "runtime" / "CURRENT_PERSONA.md").exists())

    def test_legacy_root_markdown_is_migrated_to_memory_directory(self):
        self.agent_root.mkdir(parents=True, exist_ok=True)
        legacy_memory = self.agent_root / "MEMORY.md"
        legacy_memory.write_text("# Legacy Memory\n", encoding="utf-8")
        legacy_persona = self.agent_root / "CURRENT_PERSONA.md"
        legacy_persona.write_text(
            textwrap.dedent(
                """\
                ---
                active_persona: default
                profile: personas/default/AGENT_PROFILE.md
                workflow: personas/default/AGENT_WORKFLOW.md
                hooks: personas/default/AGENT_HOOKS.md
                system_tasks: system_tasks/SYSTEM_TASKS.md
                user_preferences: USER_PREFERENCES.md
                ---
                """
            ),
            encoding="utf-8",
        )

        manager = self._manager()
        manager.ensure_layout()

        self.assertFalse(legacy_memory.exists())
        self.assertTrue((self.agent_root / "memory" / "MEMORY.md").exists())
        self.assertFalse(legacy_persona.exists())
        self.assertTrue((self.agent_root / "runtime" / "CURRENT_PERSONA.md").exists())

    def test_render_system_task_message_uses_unified_system_tasks_definition(self):
        manager = self._manager()
        runtime_config = manager.load_runtime_config()

        message = runtime_config.render_system_task_message("heartbeat")

        self.assertIn("[System Heartbeat]", message)
        self.assertIn("List all jobs with status 'pending' or 'in_progress'.", message)
        self.assertIn("Do NOT include greetings, explanations, or conversational text.", message)
        self.assertIn("If no jobs were executed, output nothing.", message)

    def test_render_system_task_message_renders_template_context(self):
        manager = self._manager()
        runtime_config = manager.load_runtime_config()

        message = runtime_config.render_system_task_message(
            "transfer_failed_retry",
            template_context={
                "history_ids_csv": "7",
                "history_count": 1,
                "history_id": 7,
            },
        )

        self.assertIn("Failed transfer history record IDs: 7", message)
        self.assertIn("Total failed records: 1", message)
        self.assertIn("history_id=7", message)

    def test_missing_template_context_raises_clear_error(self):
        manager = self._manager()
        runtime_config = manager.load_runtime_config()

        with self.assertRaises(AgentRuntimeConfigError):
            runtime_config.render_system_task_message("transfer_failed_retry")

    def test_invalid_user_runtime_config_falls_back_to_bundled_defaults(self):
        manager = self._manager()
        manager.ensure_layout()
        invalid_current = self.agent_root / "runtime" / "CURRENT_PERSONA.md"
        invalid_current.write_text(
            textwrap.dedent(
                """\
                ---
                active_persona: broken
                profile: personas/default/AGENT_PROFILE.md
                hooks: personas/default/AGENT_HOOKS.md
                system_tasks: system_tasks/SYSTEM_TASKS.md
                ---
                """
            ),
            encoding="utf-8",
        )
        manager.invalidate_cache()

        runtime_config = manager.load_runtime_config()

        self.assertTrue(runtime_config.used_fallback)
        self.assertEqual(runtime_config.active_persona, "default")
        self.assertIn("已回退到内置默认配置", runtime_config.warnings[0])

    def test_deprecated_phrase_warning_is_reported(self):
        self.agent_root.mkdir(parents=True, exist_ok=True)
        runtime_root = self.agent_root / "runtime"
        shutil.copytree(self.bundled_root, runtime_root)
        current_persona = runtime_root / "CURRENT_PERSONA.md"
        current_persona.write_text(
            textwrap.dedent(
                """\
                ---
                version: 1
                active_persona: default
                profile: personas/default/AGENT_PROFILE.md
                workflow: personas/default/AGENT_WORKFLOW.md
                hooks: personas/default/AGENT_HOOKS.md
                user_preferences: USER_PREFERENCES.md
                system_tasks: system_tasks/SYSTEM_TASKS.md
                extra_context_files: []
                deprecated_phrases:
                  - professional, concise, restrained
                ---
                """
            ),
            encoding="utf-8",
        )

        manager = self._manager()
        manager.invalidate_cache()
        runtime_config = manager.load_runtime_config()

        self.assertTrue(
            any("professional, concise, restrained" in warning for warning in runtime_config.warnings)
        )

    def test_outdated_system_tasks_definition_falls_back_to_bundled_defaults(self):
        self.agent_root.mkdir(parents=True, exist_ok=True)
        runtime_root = self.agent_root / "runtime"
        shutil.copytree(self.bundled_root, runtime_root)
        system_tasks = runtime_root / "system_tasks" / "SYSTEM_TASKS.md"
        system_tasks.write_text(
            textwrap.dedent(
                """\
                ---
                version: 1
                shared_rules:
                  - legacy system tasks
                task_types:
                  heartbeat:
                    header: "[Legacy Heartbeat]"
                    objective: "legacy"
                ---
                """
            ),
            encoding="utf-8",
        )

        manager = self._manager()
        manager.invalidate_cache()
        runtime_config = manager.load_runtime_config()

        self.assertTrue(runtime_config.used_fallback)
        self.assertEqual(runtime_config.system_tasks.version, 2)


if __name__ == "__main__":
    unittest.main()
