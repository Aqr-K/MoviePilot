from unittest import TestCase
from unittest.mock import patch

from app.core.meta.customization import CustomizationMatcher


class CustomizationMatcherTest(TestCase):
    def test_match_uses_latest_customization_setting(self):
        """自定义占位符修改后，下一次识别应直接使用新配置。"""
        matcher = CustomizationMatcher()
        values = [["GROUP"], ["TEAM"]]

        with patch.object(
            matcher.systemconfig,
            "get",
            side_effect=lambda _: values[0],
        ):
            self.assertEqual(matcher.match("[GROUP][TEAM] Movie"), "GROUP")
            values[0] = ["TEAM"]
            self.assertEqual(matcher.match("[GROUP][TEAM] Movie"), "TEAM")
