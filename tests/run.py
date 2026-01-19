import unittest

from tests.test_bluray import BluRayTest
from tests.test_metainfo import MetaInfoTest
from tests.test_object import ObjectUtilsTest


if __name__ == '__main__':
    suite = unittest.TestSuite()

    # 测试名称识别
    suite.addTest(MetaInfoTest('test_metainfo'))
    suite.addTest(MetaInfoTest('test_emby_format_ids'))
    suite.addTest(ObjectUtilsTest('test_check_method'))

    # 测试自定义识别词功能
    suite.addTest(MetaInfoTest('test_metainfopath_with_custom_words'))
    suite.addTest(MetaInfoTest('test_metainfopath_without_custom_words'))
    suite.addTest(MetaInfoTest('test_metainfopath_with_empty_custom_words'))
    suite.addTest(MetaInfoTest('test_custom_words_apply_words_recording'))

    # 测试蓝光目录识别
    suite.addTest(BluRayTest())

    # 运行测试
    runner = unittest.TextTestRunner()
    runner.run(suite)
