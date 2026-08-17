"""人物作品的统一契约。

与人物详情同一形态：四个源各占一套方法名，数据源被编进了方法名。但这批的签名并不
整齐，契约要把差异吸收掉：

    douban    (person_id, page=1)
    bangumi   (person_id)                   —— 不分页
    anilist   (person_id, page=1, count=20) —— 多一个每页条数
    tmdb      (person_id, page=1)

契约取并集 person_credits(source, person_id, page, count)，各源实现时只把自己认得的
参数往下传：bangumi 不接收 page，传了会 TypeError；anilist 需要 count。这类差异必须
留在各源的契约实现里，不能让调用方去记哪个源支持什么。
"""
import unittest
from unittest.mock import Mock

from app.schemas.types import MediaSource


class PersonCreditsContractTest(unittest.TestCase):
    """各源实现同一个契约，并按来源自认领"""

    def test_douban_answers_only_for_its_own_source(self):
        """豆瓣只应答豆瓣来源的请求。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_person_credits = Mock(return_value=["作品"])

        self.assertEqual(["作品"], module.person_credits(MediaSource.Douban, 1))
        self.assertIsNone(module.person_credits(MediaSource.TMDB, 1))

    def test_bangumi_answers_only_for_its_own_source(self):
        """Bangumi 只应答 Bangumi 来源的请求。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_person_credits = Mock(return_value=["作品"])

        self.assertEqual(["作品"], module.person_credits(MediaSource.Bangumi, 1))
        self.assertIsNone(module.person_credits(MediaSource.Douban, 1))

    def test_anilist_answers_only_for_its_own_source(self):
        """AniList 只应答 AniList 来源的请求。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_person_credits = Mock(return_value=["作品"])

        self.assertEqual(["作品"], module.person_credits(MediaSource.AniList, 1))
        self.assertIsNone(module.person_credits(MediaSource.Bangumi, 1))

    def test_themoviedb_answers_only_for_its_own_source(self):
        """TheMovieDb 只应答 TMDB 来源的请求。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_person_credits = Mock(return_value=["作品"])

        self.assertEqual(["作品"], module.person_credits(MediaSource.TMDB, 1))
        self.assertIsNone(module.person_credits(MediaSource.AniList, 1))

    def test_a_source_without_paging_is_not_handed_a_page(self):
        """Bangumi 的作品接口不分页，契约不能把 page 传下去。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_person_credits = Mock(return_value=[])

        module.person_credits(MediaSource.Bangumi, 7, page=3)

        module.bangumi_person_credits.assert_called_once_with(person_id=7)

    def test_a_source_with_a_page_size_receives_it(self):
        """AniList 的作品接口有每页条数，契约要把它传下去。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_person_credits = Mock(return_value=[])

        module.person_credits(MediaSource.AniList, 7, page=2, count=50)

        module.anilist_person_credits.assert_called_once_with(
            person_id=7, page=2, count=50)

    def test_paging_reaches_a_source_that_supports_it(self):
        """支持分页的源照常收到页码。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_person_credits = Mock(return_value=[])

        module.person_credits(MediaSource.Douban, 7, page=4)

        module.douban_person_credits.assert_called_once_with(person_id=7, page=4)


class AsyncPersonCreditsContractTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_async_contract_routes_by_source(self):
        """异步契约同样按来源自认领。"""
        from app.modules.douban import DoubanModule

        async def credits(person_id=None, page=1):
            """异步人物作品"""
            return ["作品"]

        module = object.__new__(DoubanModule)
        module.async_douban_person_credits = credits

        self.assertEqual(["作品"],
                         await module.async_person_credits(MediaSource.Douban, 1))
        self.assertIsNone(await module.async_person_credits(MediaSource.TMDB, 1))


if __name__ == "__main__":
    unittest.main()
