import subprocess
from unittest import TestCase
from unittest.mock import patch

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
