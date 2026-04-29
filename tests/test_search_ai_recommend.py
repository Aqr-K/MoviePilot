import asyncio
import sys
import unittest
from types import SimpleNamespace
from types import ModuleType
from unittest.mock import AsyncMock, patch


def _stub_module(name: str, **attrs):
    module = sys.modules.get(name)
    if module is None:
        module = ModuleType(name)
        sys.modules[name] = module
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


_stub_module("qbittorrentapi", TorrentFilesList=list)
_stub_module("transmission_rpc", File=object)

from app.chain.search import SearchChain
from app.core.config import settings


def _make_result(title: str, size: int, seeders: int):
    return SimpleNamespace(
        torrent_info=SimpleNamespace(title=title, size=size, seeders=seeders)
    )


class SearchChainAIRecommendTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SearchChain._ai_recommend_running = False
        SearchChain._ai_recommend_task = None
        SearchChain._current_recommend_request_hash = None
        SearchChain._ai_recommend_result = None
        SearchChain._ai_recommend_error = None

    async def asyncTearDown(self):
        task = SearchChain._ai_recommend_task
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        SearchChain._ai_recommend_running = False
        SearchChain._ai_recommend_task = None
        SearchChain._current_recommend_request_hash = None
        SearchChain._ai_recommend_result = None
        SearchChain._ai_recommend_error = None

    @staticmethod
    def _make_chain() -> SearchChain:
        chain = object.__new__(SearchChain)
        chain.load_cache = lambda _filename: None
        chain.save_cache = lambda _cache, _filename: None
        chain.remove_cache = lambda _filename: None
        return chain

    async def test_start_recommend_task_restores_original_indices(self):
        chain = self._make_chain()
        saved = []
        chain.save_cache = lambda cache, filename: saved.append((filename, cache))
        results = [_make_result(f"item-{index}", 1024 * (index + 1), index) for index in range(7)]

        with (
            patch.object(settings, "AI_AGENT_ENABLE", True, create=True),
            patch.object(settings, "AI_RECOMMEND_ENABLED", True, create=True),
            patch.object(settings, "AI_RECOMMEND_MAX_ITEMS", 50, create=True),
            patch.object(
                settings,
                "AI_RECOMMEND_USER_PREFERENCE",
                "Prefer high seeders",
                create=True,
            ),
            patch.object(
                SearchChain,
                "_invoke_recommend_llm",
                new=AsyncMock(return_value='[1, 0, 1, "bad", 9]'),
            ),
        ):
            chain.start_recommend_task(
                filtered_indices=[2, 4, 6],
                search_results_count=len(results),
                results=results,
            )
            self.assertIsNotNone(SearchChain._ai_recommend_task)
            await SearchChain._ai_recommend_task

        self.assertEqual([4, 2], SearchChain._ai_recommend_result)
        self.assertEqual(
            [("__ai_recommend_indices__", [4, 2])],
            saved,
        )
        self.assertFalse(SearchChain._ai_recommend_running)
        self.assertIsNone(SearchChain._ai_recommend_task)

    def test_search_by_title_clears_previous_recommend_state_when_caching(self):
        chain = self._make_chain()
        removed = []
        cached = []
        chain.remove_cache = lambda filename: removed.append(filename)
        chain.save_cache = lambda cache, filename: cached.append((filename, cache))
        chain._SearchChain__search_all_sites = lambda keyword, sites, page: [
            SimpleNamespace(title="Test Title", description="Test Desc")
        ]

        SearchChain._current_recommend_request_hash = "stale-hash"
        SearchChain._ai_recommend_result = [3, 1]
        SearchChain._ai_recommend_error = "stale-error"

        results = chain.search_by_title("keyword", cache_local=True)

        self.assertEqual(1, len(results))
        self.assertEqual(["__ai_recommend_indices__"], removed)
        self.assertEqual("__search_result__", cached[0][0])
        self.assertIsNone(SearchChain._current_recommend_request_hash)
        self.assertIsNone(SearchChain._ai_recommend_result)
        self.assertIsNone(SearchChain._ai_recommend_error)


if __name__ == "__main__":
    unittest.main()
