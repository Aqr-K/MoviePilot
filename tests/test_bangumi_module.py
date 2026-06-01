import asyncio

from app.modules.bangumi import BangumiModule


class _FakeBangumiApi:
    """
    测试用Bangumi API客户端。
    """

    def __init__(self, personinfo: dict):
        """
        初始化测试用人物详情数据。
        :param personinfo: 人物详情接口返回数据
        """
        self.personinfo = personinfo

    def person_detail(self, person_id: int) -> dict:
        """
        返回同步人物详情数据。
        :param person_id: 人物ID
        :return: 人物详情接口返回数据
        """
        return self.personinfo

    async def async_person_detail(self, person_id: int) -> dict:
        """
        返回异步人物详情数据。
        :param person_id: 人物ID
        :return: 人物详情接口返回数据
        """
        return self.personinfo


def test_bangumi_person_detail_normalizes_numeric_birthday():
    """
    Bangumi同步人物详情应兼容数字生日字段。
    """
    module = BangumiModule()
    module.bangumiapi = _FakeBangumiApi({
        "id": 1001,
        "name": "测试人物",
        "images": {"large": "https://example.com/person.jpg"},
        "summary": "测试简介",
        "birth_day": 22,
        "gender": 1,
    })

    person = module.bangumi_person_detail(1001)

    assert person.birthday == "22"


def test_async_bangumi_person_detail_normalizes_numeric_birthday():
    """
    Bangumi异步人物详情应兼容数字生日字段。
    """
    module = BangumiModule()
    module.bangumiapi = _FakeBangumiApi({
        "id": 1002,
        "name": "测试异步人物",
        "images": {"large": "https://example.com/async-person.jpg"},
        "summary": "测试异步简介",
        "birth_day": 19,
        "gender": 2,
    })

    person = asyncio.run(module.async_bangumi_person_detail(1002))

    assert person.birthday == "19"
