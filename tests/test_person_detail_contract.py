"""人物详情的统一契约。

四个数据源各有一套方法名——douban_person_detail、bangumi_person_detail、
anilist_person_detail、tmdb_person_detail——签名却完全相同：

    (person_id: int) -> Optional[MediaPerson]

数据源被编进了方法名，于是新增一个源要在 chain 里加一组新方法，而不是实现一个已有
契约。归一为单一契约后，源成为参数而非方法名的一部分：

    person_detail(source, person_id)

分发沿用识别侧的既有模式：按能力单播 + 模块按 source 自检，不是本源就返回 None。
契约实现必须委托给各源原有方法，缓存与限流都挂在那条路径上，重写会让接缝错位。
"""
import unittest
from unittest.mock import Mock

from app import schemas
from app.schemas.types import MediaSource


def _person(name: str) -> schemas.MediaPerson:
    """构造一个人物详情"""
    return schemas.MediaPerson(source="test", id=1, name=name)


class PersonDetailContractTest(unittest.TestCase):
    """各源实现同一个契约，并按来源自认领"""

    def test_douban_answers_only_for_its_own_source(self):
        """豆瓣只应答豆瓣来源的请求。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_person_detail = Mock(return_value=_person("豆瓣人物"))

        self.assertEqual("豆瓣人物",
                         module.person_detail(MediaSource.Douban, 1).name)
        self.assertIsNone(module.person_detail(MediaSource.TMDB, 1))

    def test_bangumi_answers_only_for_its_own_source(self):
        """Bangumi 只应答 Bangumi 来源的请求。"""
        from app.modules.bangumi import BangumiModule

        module = object.__new__(BangumiModule)
        module.bangumi_person_detail = Mock(return_value=_person("Bangumi人物"))

        self.assertEqual("Bangumi人物",
                         module.person_detail(MediaSource.Bangumi, 1).name)
        self.assertIsNone(module.person_detail(MediaSource.Douban, 1))

    def test_anilist_answers_only_for_its_own_source(self):
        """AniList 只应答 AniList 来源的请求。"""
        from app.modules.anilist import AniListModule

        module = object.__new__(AniListModule)
        module.anilist_person_detail = Mock(return_value=_person("AniList人物"))

        self.assertEqual("AniList人物",
                         module.person_detail(MediaSource.AniList, 1).name)
        self.assertIsNone(module.person_detail(MediaSource.Bangumi, 1))

    def test_themoviedb_answers_only_for_its_own_source(self):
        """TheMovieDb 只应答 TMDB 来源的请求。"""
        from app.modules.themoviedb import TheMovieDbModule

        module = object.__new__(TheMovieDbModule)
        module.tmdb_person_detail = Mock(return_value=_person("TMDB人物"))

        self.assertEqual("TMDB人物",
                         module.person_detail(MediaSource.TMDB, 1).name)
        self.assertIsNone(module.person_detail(MediaSource.AniList, 1))

    def test_the_contract_delegates_to_the_existing_method(self):
        """契约委托给原有方法，不另起实现——缓存与限流都挂在那条路径上。"""
        from app.modules.douban import DoubanModule

        module = object.__new__(DoubanModule)
        module.douban_person_detail = Mock(return_value=_person("豆瓣人物"))

        module.person_detail(MediaSource.Douban, 42)

        module.douban_person_detail.assert_called_once_with(person_id=42)


class AsyncPersonDetailContractTest(unittest.IsolatedAsyncioTestCase):
    """异步契约与同步契约语义一致"""

    async def test_douban_async_answers_only_for_its_own_source(self):
        """异步契约同样按来源自认领。"""
        from app.modules.douban import DoubanModule

        async def detail(person_id=None):
            """异步人物详情"""
            return _person("豆瓣人物")

        module = object.__new__(DoubanModule)
        module.async_douban_person_detail = detail

        result = await module.async_person_detail(MediaSource.Douban, 1)
        self.assertEqual("豆瓣人物", result.name)
        self.assertIsNone(await module.async_person_detail(MediaSource.TMDB, 1))


if __name__ == "__main__":
    unittest.main()
