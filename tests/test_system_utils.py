import subprocess
import tempfile
from unittest import TestCase
from unittest.mock import patch

from app.helper.system import SystemHelper
from app.core.config import settings
from app.utils.system import SystemUtils


class SystemUtilsTest(TestCase):

    def test_execute_with_subprocess_keeps_stdout_when_command_fails(self):
        """
        命令失败时如果原因只写入 stdout，也需要回传给调用方用于错误提示。
        """
        error = subprocess.CalledProcessError(
            returncode=1,
            cmd=["pip", "check"],
            output="demo requires pkg>=2, but you have pkg 1\n",
            stderr="",
        )

        with patch("app.utils.system.subprocess.run", side_effect=error):
            success, message = SystemUtils.execute_with_subprocess(["pip", "check"])

        self.assertFalse(success)
        self.assertIn("返回码：1", message)
        self.assertIn("标准输出：demo requires pkg>=2, but you have pkg 1", message)

    def test_execute_with_subprocess_reports_empty_failure_output(self):
        """
        命令失败且没有任何输出时，给出明确占位信息，避免错误原因看起来被截断。
        """
        error = subprocess.CalledProcessError(
            returncode=2,
            cmd=["pip", "check"],
            output="",
            stderr="",
        )

        with patch("app.utils.system.subprocess.run", side_effect=error):
            success, message = SystemUtils.execute_with_subprocess(["pip", "check"])

        self.assertFalse(success)
        self.assertIn("返回码：2", message)
        self.assertIn("无标准输出或错误输出", message)


class SystemHelperRestartTest(TestCase):

    def test_docker_restart_policy_marks_intent_before_sigterm(self):
        """
        Docker 内置重启走优雅退出时，应写入意图标记，避免 entrypoint 误进入 doctor 保活。
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            original_config_dir = settings.CONFIG_DIR
            original_intent_file = SystemHelper._SystemHelper__docker_restart_intent_file
            settings.CONFIG_DIR = temp_dir
            SystemHelper._SystemHelper__docker_restart_intent_file = (
                settings.TEMP_PATH / "moviepilot.intentional_restart"
            )
            try:
                with patch("app.helper.system.SystemUtils.is_docker", return_value=True), \
                        patch.object(SystemHelper, "_check_restart_policy", return_value=True), \
                        patch.object(SystemHelper, "_start_graceful_shutdown_monitor"), \
                        patch("app.helper.system.os.kill") as kill_mock:
                    ret, msg = SystemHelper.restart()

                self.assertTrue(ret)
                self.assertEqual(msg, "")
                self.assertTrue((settings.TEMP_PATH / "moviepilot.intentional_restart").exists())
                kill_mock.assert_called_once()
            finally:
                SystemHelper._SystemHelper__docker_restart_intent_file = original_intent_file
                settings.CONFIG_DIR = original_config_dir
