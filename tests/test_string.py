from unittest import TestCase

from app.utils.string import StringUtils


class StringUtilsTest(TestCase):

    def test_is_media_title_like_true(self):
        self.assertTrue(StringUtils.is_media_title_like("盗梦空间"))
        self.assertTrue(StringUtils.is_media_title_like("The Lord of the Rings"))
        self.assertTrue(StringUtils.is_media_title_like("庆余年 第2季"))

    def test_is_media_title_like_false(self):
        self.assertFalse(StringUtils.is_media_title_like("#推荐电影"))
        self.assertFalse(StringUtils.is_media_title_like("请帮我推荐一部电影"))
        self.assertFalse(StringUtils.is_media_title_like("盗梦空间怎么样？"))
        self.assertFalse(StringUtils.is_media_title_like("我想看盗梦空间"))
        self.assertFalse(StringUtils.is_media_title_like("继续"))
