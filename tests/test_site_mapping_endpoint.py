"""站点域名映射端点的异步查询路径契约测试。"""

import asyncio

from app.api.endpoints import site as site_endpoint
from app.schemas.site import Site


class _AsyncOnlyQuery:
    """只暴露异步查询方法的桩，确保端点不再退化到同步查询。"""

    def __init__(self, sites: list[Site]) -> None:
        self._sites = sites

    async def list_ordered(self) -> list[Site]:
        return self._sites


def test_site_mapping_uses_async_query_without_blocking_event_loop():
    """站点域名映射必须走异步查询服务，不能在事件循环内调用同步查询。"""
    sites = [
        Site(domain="a.example", name="站点A"),
        Site(domain="b.example", name="站点B"),
    ]
    query = _AsyncOnlyQuery(sites)

    response = asyncio.run(site_endpoint.site_mapping(query=query, _=None))

    assert response.success is True
    assert response.data == {"a.example": "站点A", "b.example": "站点B"}
