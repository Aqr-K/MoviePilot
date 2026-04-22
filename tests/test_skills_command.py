import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

sys.modules.setdefault("qbittorrentapi", ModuleType("qbittorrentapi"))
setattr(sys.modules["qbittorrentapi"], "TorrentFilesList", list)
sys.modules.setdefault("transmission_rpc", ModuleType("transmission_rpc"))
setattr(sys.modules["transmission_rpc"], "File", object)
sys.modules.setdefault("psutil", ModuleType("psutil"))

from app.chain.message import MessageChain
from app.chain.skills import SkillsChain, skills_interaction_manager
from app.helper.skill import SkillHelper, SkillInfo
from app.schemas.types import MessageChannel


def _build_skill_zip(skill_dir: str, skill_name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            f"demo-main/{skill_dir}/SKILL.md",
            (
                f"---\n"
                f"name: {skill_name}\n"
                f"version: 1\n"
                f"description: demo skill\n"
                f"---\n\n"
                f"# {skill_name}\n"
            ),
        )
        zf.writestr(f"demo-main/{skill_dir}/scripts/example.py", "print('ok')\n")
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, payload=None, content: bytes = b"", status_code: int = 200):
        self._payload = payload
        self.content = content
        self.status_code = status_code

    def json(self):
        return self._payload


class TestSkillsCommand(unittest.TestCase):
    def tearDown(self):
        skills_interaction_manager.clear()

    def test_message_routes_text_reply_to_skills_interaction_before_ai(self):
        chain = MessageChain()
        skills_interaction_manager.create_or_replace(
            user_id="10001",
            channel=MessageChannel.Wechat,
            source="wechat-test",
            username="tester",
        )

        with patch.object(chain, "_record_user_message"), patch(
            "app.chain.message.SkillsChain.handle_text_interaction",
            return_value=True,
        ) as handle_text, patch.object(chain, "_handle_ai_message") as handle_ai:
            chain.handle_message(
                channel=MessageChannel.Wechat,
                source="wechat-test",
                userid="10001",
                username="tester",
                text="2",
            )

        handle_text.assert_called_once()
        handle_ai.assert_not_called()

    def test_callback_routes_to_skills_chain(self):
        chain = MessageChain()
        request = skills_interaction_manager.create_or_replace(
            user_id="10001",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            username="tester",
        )

        with patch(
            "app.chain.message.SkillsChain.handle_callback_interaction",
            return_value=True,
        ) as handle_callback:
            chain._handle_callback(
                text=f"CALLBACK:skills:{request.request_id}:market",
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
            )

        handle_callback.assert_called_once()

    def test_skillhelper_install_and_remove_market_skill(self):
        helper = SkillHelper()
        skill = SkillInfo(
            id="demo-skill",
            name="demo-skill",
            description="demo",
            source_type="market",
            source_label="市场 · acme/demo",
            repo_url="https://github.com/acme/demo",
            repo_name="acme/demo",
            skill_path="skills/demo-skill",
        )
        zip_bytes = _build_skill_zip("skills/demo-skill", "demo-skill")

        with tempfile.TemporaryDirectory() as tempdir:
            user_root = Path(tempdir) / "user-skills"
            bundled_root = Path(tempdir) / "bundled-skills"
            user_root.mkdir(parents=True, exist_ok=True)
            bundled_root.mkdir(parents=True, exist_ok=True)

            with patch.object(
                SkillHelper, "get_user_skills_dir", return_value=user_root
            ), patch.object(
                SkillHelper, "get_bundled_skills_dir", return_value=bundled_root
            ), patch.object(
                helper, "_download_repo_archive", return_value=zip_bytes
            ):
                success, message = helper.install_market_skill(skill)
                self.assertTrue(success, message)
                self.assertTrue((user_root / "demo-skill" / "SKILL.md").exists())
                self.assertTrue(
                    (user_root / "demo-skill" / ".moviepilot-skill-source.json").exists()
                )

                local_skills = helper.list_local_skills()
                self.assertEqual(len(local_skills), 1)
                self.assertEqual(local_skills[0].source_type, "market")
                self.assertTrue(local_skills[0].removable)

                removed, remove_message = helper.remove_local_skill("demo-skill")
                self.assertTrue(removed, remove_message)
                self.assertFalse((user_root / "demo-skill").exists())

                bundled_skill_dir = bundled_root / "builtin-skill"
                bundled_skill_dir.mkdir(parents=True, exist_ok=True)
                (bundled_skill_dir / "SKILL.md").write_text(
                    "---\nname: builtin-skill\ndescription: builtin\n---\n",
                    encoding="utf-8",
                )
                installed_builtin = user_root / "builtin-skill"
                installed_builtin.mkdir(parents=True, exist_ok=True)
                (installed_builtin / "SKILL.md").write_text(
                    "---\nname: builtin-skill\ndescription: builtin\n---\n",
                    encoding="utf-8",
                )

                removed, remove_message = helper.remove_local_skill("builtin-skill")
                self.assertFalse(removed)
                self.assertIn("内置技能", remove_message)

    def test_skillhelper_lists_clawhub_registry_skills(self):
        helper = SkillHelper()
        response = _FakeResponse(
            payload={
                "items": [
                    {
                        "slug": "weather-forecast",
                        "name": "Weather Forecast",
                        "summary": "Forecast weather from ClawHub",
                        "owner": {"handle": "openclaw"},
                    }
                ]
            }
        )

        with patch.object(helper, "_request_registry", return_value=response):
            skills = helper._list_market_source_skills("https://clawhub.ai")

        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0].id, "weather-forecast")
        self.assertEqual(skills[0].source_type, "registry")
        self.assertEqual(skills[0].registry_name, "ClawHub")
        self.assertEqual(skills[0].source_label, "社区注册表 · ClawHub")
        self.assertIn("/openclaw/weather-forecast", skills[0].path)

    def test_skillhelper_installs_registry_skill(self):
        helper = SkillHelper()
        skill = SkillInfo(
            id="registry-demo",
            name="Registry Demo",
            description="registry demo",
            source_type="registry",
            source_label="注册表 · ClawHub",
            registry_url="https://clawhub.ai",
            registry_name="ClawHub",
            registry_slug="registry-demo",
            download_url="https://clawhub.ai/api/v1/download?slug=registry-demo",
        )
        zip_bytes = _build_skill_zip("package", "registry-demo")

        with tempfile.TemporaryDirectory() as tempdir:
            user_root = Path(tempdir) / "user-skills"
            bundled_root = Path(tempdir) / "bundled-skills"
            user_root.mkdir(parents=True, exist_ok=True)
            bundled_root.mkdir(parents=True, exist_ok=True)

            with patch.object(
                SkillHelper, "get_user_skills_dir", return_value=user_root
            ), patch.object(
                SkillHelper, "get_bundled_skills_dir", return_value=bundled_root
            ), patch.object(
                helper, "_request_registry", return_value=_FakeResponse(content=zip_bytes)
            ):
                success, message = helper.install_market_skill(skill)
                self.assertTrue(success, message)
                self.assertTrue((user_root / "registry-demo" / "SKILL.md").exists())
                self.assertTrue(
                    (
                        user_root
                        / "registry-demo"
                        / ".moviepilot-skill-source.json"
                    ).exists()
                )

                local_skills = helper.list_local_skills()
                self.assertEqual(len(local_skills), 1)
                self.assertEqual(local_skills[0].source_type, "registry")
                self.assertEqual(local_skills[0].registry_name, "ClawHub")
                self.assertEqual(local_skills[0].source_label, "社区注册表 · ClawHub")

    def test_skills_chain_market_view_marks_clawhub_as_community_source(self):
        chain = SkillsChain()
        request = skills_interaction_manager.create_or_replace(
            user_id="10001",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            username="tester",
        )
        request.view = "market"

        with patch.object(
            chain.skillhelper,
            "list_market_skills",
            return_value=[
                SkillInfo(
                    id="weather-forecast",
                    name="Weather Forecast",
                    description="Forecast weather from ClawHub",
                    source_type="registry",
                    source_label="社区注册表 · ClawHub",
                    registry_name="ClawHub",
                    registry_url="https://clawhub.ai",
                    registry_slug="weather-forecast",
                )
            ],
        ):
            title, text, _buttons = chain._build_market_view(request=request)

        self.assertEqual(title, "技能市场")
        self.assertIn("社区注册表 · ClawHub", text)
        self.assertIn("社区源，安装前请自行甄别安全性", text)
        self.assertIn("ClawHub 属于社区注册表", text)

    def test_skills_chain_root_view_uses_friendly_source_labels(self):
        chain = SkillsChain()
        request = skills_interaction_manager.create_or_replace(
            user_id="10001",
            channel=MessageChannel.Telegram,
            source="telegram-test",
            username="tester",
        )

        with patch.object(chain.skillhelper, "list_local_skills", return_value=[]), patch.object(
            chain.skillhelper, "list_market_skills", return_value=[]
        ), patch.object(
            chain.skillhelper,
            "get_market_sources",
            return_value=["https://clawhub.ai", "https://github.com/openai/skills"],
        ):
            title, text, _buttons = chain._build_root_view(request=request)

        self.assertEqual(title, "技能管理")
        self.assertIn("社区注册表 · ClawHub", text)
        self.assertIn("官方仓库 · openai/skills", text)

    def test_skills_chain_updates_buttons_via_edit_message(self):
        chain = SkillsChain()
        buttons = [[{"text": "安装 1", "callback_data": "skills:req:install:1"}]]

        with patch.object(chain, "edit_message", return_value=True) as edit_message, patch.object(
            chain, "post_message"
        ) as post_message:
            chain._update_or_post_message(
                channel=MessageChannel.Telegram,
                source="telegram-test",
                userid="10001",
                username="tester",
                title="技能市场",
                text="请选择技能",
                buttons=buttons,
                original_message_id=123,
                original_chat_id="456",
            )

        edit_message.assert_called_once_with(
            channel=MessageChannel.Telegram,
            source="telegram-test",
            message_id=123,
            chat_id="456",
            title="技能市场",
            text="请选择技能",
            buttons=buttons,
        )
        post_message.assert_not_called()


if __name__ == "__main__":
    unittest.main()
