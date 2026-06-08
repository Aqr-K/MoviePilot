import asyncio
import hashlib
import json
import random
import re
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from datetime import datetime
from typing import AsyncIterator, Any, Dict, Tuple
from typing import List, Optional

from fastapi.concurrency import run_in_threadpool

from app.chain import ChainBase
from app.core.config import global_vars, settings
from app.core.context import Context
from app.core.context import MediaInfo, SubtitleInfo, TorrentInfo
from app.core.event import eventmanager, Event
from app.core.metainfo import MetaInfo
from app.db.systemconfig_oper import SystemConfigOper
from app.helper.progress import ProgressHelper
from app.helper.sites import SitesHelper  # noqa
from app.helper.torrent import TorrentHelper
from app.log import logger
from app.schemas import NotExistMediaInfo
from app.schemas.types import MediaType, ProgressKey, SystemConfigKey, EventType
from app.utils.string import StringUtils


class SearchChain(ChainBase):
    """
    站点资源搜索处理链
    """

    __result_temp_file = "__search_result__"
    __subtitle_result_temp_file = "__subtitle_search_result__"
    __search_params_temp_file = "__search_params__"
    __ai_indices_cache_file = "__ai_recommend_indices__"

    _ai_recommend_running = False
    _ai_recommend_task: Optional[asyncio.Task] = None
    _current_recommend_request_hash: Optional[str] = None
    _ai_recommend_result: Optional[List[int]] = None
    _ai_recommend_error: Optional[str] = None

    @staticmethod
    def _get_search_resource_pages() -> int:
        """
        获取搜索资源需要抓取的页数。

        settings 可能被环境变量写成字符串，这里统一兜底为 1，避免异常配置导致搜索中断。
        """
        pages = settings.SEARCH_RESOURCE_PAGES
        try:
            pages = int(pages)
        except (TypeError, ValueError):
            return 1
        return max(pages, 1)

    @classmethod
    def _build_search_pages(cls, page: Optional[int] = 0) -> List[int]:
        """
        根据起始页和配置页数生成需要请求的页码列表。
        """
        try:
            start_page = int(page or 0)
        except (TypeError, ValueError):
            start_page = 0
        start_page = max(start_page, 0)
        return list(range(start_page, start_page + cls._get_search_resource_pages()))

    def _should_continue_search_pages(self, site: dict, page_results: Optional[List[Any]],
                                      keyword: Optional[str] = None) -> bool:
        """
        判断是否继续抓取下一页；少于站点单页容量时视为当前站点已到末页。
        """
        page_size = self.get_search_page_size(site=site, keyword=keyword)
        return page_size is not None and len(page_results or []) >= page_size

    @staticmethod
    def _should_continue_subtitle_search_pages(site: dict, page_results: Optional[List[Any]]) -> bool:
        """
        判断字幕搜索是否继续抓取下一页。
        """
        subtitle_conf = (site or {}).get("subtitles") or {}
        try:
            page_size = int(subtitle_conf.get("result_num") or site.get("result_num") or 100)
        except (TypeError, ValueError):
            page_size = 100
        return page_size > 0 and len(page_results or []) >= page_size

    @property
    def is_ai_recommend_enabled(self) -> bool:
        """
        检查AI推荐功能是否已启用。
        """
        return settings.AI_AGENT_ENABLE and settings.AI_RECOMMEND_ENABLED

    @staticmethod
    def _calculate_recommend_request_hash(
            filtered_indices: Optional[List[int]], search_results_count: int
    ) -> str:
        """
        计算当前推荐请求哈希，用于识别筛选条件是否变化。
        """
        request_data = {
            "filtered_indices": filtered_indices or [],
            "search_results_count": search_results_count,
        }
        return hashlib.md5(
            json.dumps(request_data, sort_keys=True).encode()
        ).hexdigest()

    def _build_ai_recommend_status(self) -> Dict[str, Any]:
        """
        构建AI推荐状态字典。
        """
        state = type(self)
        if not self.is_ai_recommend_enabled:
            return {"status": "disabled"}

        if state._ai_recommend_running:
            return {"status": "running"}

        if state._ai_recommend_result is None:
            cached_indices = self.load_cache(self.__ai_indices_cache_file)
            if cached_indices is not None:
                state._ai_recommend_result = cached_indices

        if state._ai_recommend_result is not None:
            return {"status": "completed", "results": state._ai_recommend_result}

        if state._ai_recommend_error is not None:
            return {"status": "error", "error": state._ai_recommend_error}

        return {"status": "idle"}

    def get_current_recommend_status_only(self) -> Dict[str, Any]:
        """
        获取当前推荐状态，不校验请求是否变化。
        """
        return self._build_ai_recommend_status()

    def get_recommend_status(
            self, filtered_indices: Optional[List[int]], search_results_count: int
    ) -> Dict[str, Any]:
        """
        获取AI推荐状态，并在筛选条件变化时返回 idle。
        """
        state = type(self)
        request_hash = self._calculate_recommend_request_hash(
            filtered_indices, search_results_count
        )
        if request_hash != state._current_recommend_request_hash:
            return {"status": "idle"} if self.is_ai_recommend_enabled else {"status": "disabled"}
        return self._build_ai_recommend_status()

    def cancel_ai_recommend(self):
        """
        取消当前AI推荐任务并清空缓存状态。
        """
        state = type(self)
        if state._ai_recommend_task and not state._ai_recommend_task.done():
            state._ai_recommend_task.cancel()
        state._ai_recommend_running = False
        state._ai_recommend_task = None
        state._current_recommend_request_hash = None
        state._ai_recommend_result = None
        state._ai_recommend_error = None
        self.remove_cache(self.__ai_indices_cache_file)

    @staticmethod
    def _build_search_keyword(
            tmdbid: Optional[int] = None, doubanid: Optional[str] = None
    ) -> str:
        """
        根据媒体ID生成可重放的搜索关键字。
        """
        if tmdbid is not None:
            return f"tmdb:{tmdbid}"
        if doubanid:
            return f"douban:{doubanid}"
        return ""

    @staticmethod
    def _stringify_sites(sites: Optional[List[int]]) -> str:
        """
        将站点ID列表转换为前端可直接复用的查询字符串。
        """
        return ",".join(str(site) for site in sites) if sites else ""

    @staticmethod
    def _normalize_search_params(params: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
        """
        规范化上次搜索参数，供前端结果页重新搜索使用。
        """
        if not isinstance(params, dict):
            return None

        normalized = {
            "keyword": str(params.get("keyword") or ""),
            "type": str(params.get("type") or ""),
            "area": str(params.get("area") or ""),
            "title": str(params.get("title") or ""),
            "year": str(params.get("year") or ""),
            "season": str(params.get("season") or ""),
            "sites": str(params.get("sites") or ""),
            "result_type": str(params.get("result_type") or "torrent"),
        }
        return normalized if normalized["keyword"] else None

    def save_last_search_params(
            self,
            *,
            keyword: Optional[str],
            mtype: Optional[MediaType] = None,
            area: Optional[str] = "title",
            title: Optional[str] = None,
            year: Optional[str] = None,
            season: Optional[int] = None,
            sites: Optional[List[int]] = None,
            result_type: Optional[str] = "torrent",
    ) -> None:
        """
        保存最后一次资源搜索参数。
        """
        params = self._normalize_search_params(
            {
                "keyword": keyword,
                "type": mtype.value if isinstance(mtype, MediaType) else mtype,
                "area": area,
                "title": title,
                "year": year,
                "season": season,
                "sites": self._stringify_sites(sites),
                "result_type": result_type or "torrent",
            }
        )
        if params:
            self.save_cache(params, self.__search_params_temp_file)

    async def async_save_last_search_params(
            self,
            *,
            keyword: Optional[str],
            mtype: Optional[MediaType] = None,
            area: Optional[str] = "title",
            title: Optional[str] = None,
            year: Optional[str] = None,
            season: Optional[int] = None,
            sites: Optional[List[int]] = None,
            result_type: Optional[str] = "torrent",
    ) -> None:
        """
        异步保存最后一次资源搜索参数。
        """
        params = self._normalize_search_params(
            {
                "keyword": keyword,
                "type": mtype.value if isinstance(mtype, MediaType) else mtype,
                "area": area,
                "title": title,
                "year": year,
                "season": season,
                "sites": self._stringify_sites(sites),
                "result_type": result_type or "torrent",
            }
        )
        if params:
            await self.async_save_cache(params, self.__search_params_temp_file)

    def last_search_params(self) -> Optional[Dict[str, str]]:
        """
        获取上次搜索使用的参数。
        """
        return self._normalize_search_params(self.load_cache(self.__search_params_temp_file))

    async def async_last_search_params(self) -> Optional[Dict[str, str]]:
        """
        异步获取上次搜索使用的参数。
        """
        return self._normalize_search_params(
            await self.async_load_cache(self.__search_params_temp_file)
        )

    @staticmethod
    def _normalize_ai_indices(ai_indices: List[Any]) -> List[int]:
        """
        过滤模型返回的非法或重复索引，保留原顺序。
        """
        normalized = []
        seen = set()
        for index in ai_indices:
            try:
                value = int(index)
            except (TypeError, ValueError):
                continue
            if value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        return normalized

    @staticmethod
    def _extract_recommend_items(
            filtered_indices: Optional[List[int]], results: List[Any]
    ) -> tuple[List[str], List[int]]:
        """
        构建发送给模型的候选列表和索引映射。
        """
        items: List[str] = []
        valid_indices: List[int] = []
        max_items = settings.AI_RECOMMEND_MAX_ITEMS or 50

        if filtered_indices:
            results_to_process = [
                results[index] for index in filtered_indices if 0 <= index < len(results)
            ]
        else:
            results_to_process = results

        for index, torrent in enumerate(results_to_process):
            if len(items) >= max_items:
                break
            if not torrent.torrent_info:
                continue

            valid_indices.append(index)
            item_info = {
                "index": index,
                "title": torrent.torrent_info.title or "未知",
                "size": (
                    StringUtils.format_size(torrent.torrent_info.size)
                    if torrent.torrent_info.size
                    else "0 B"
                ),
                "seeders": torrent.torrent_info.seeders or 0,
            }
            items.append(json.dumps(item_info, ensure_ascii=False))

        return items, valid_indices

    @staticmethod
    def _restore_original_indices(
            ai_indices: List[int],
            filtered_indices: Optional[List[int]],
            valid_indices: List[int],
            results_count: int,
    ) -> List[int]:
        """
        将模型输出的局部索引映射回原始搜索结果索引。
        """
        original_indices = []
        seen = set()

        for index in ai_indices:
            if not 0 <= index < len(valid_indices):
                continue
            original_index = (
                filtered_indices[valid_indices[index]]
                if filtered_indices
                else valid_indices[index]
            )
            if not 0 <= original_index < results_count or original_index in seen:
                continue
            seen.add(original_index)
            original_indices.append(original_index)

        return original_indices

    @staticmethod
    async def _invoke_recommend_llm(search_results_text: str) -> str:
        """
        通过统一后台提示词机制执行资源推荐。
        """
        from app.agent import ReplyMode, agent_manager
        from app.agent.prompt import prompt_manager

        prompt = prompt_manager.render_system_task_message(
            "search_recommend",
            template_context={"search_results": search_results_text},
        )
        full_output = [""]

        def on_output(text: str):
            full_output[0] = text

        await agent_manager.run_background_prompt(
            message=prompt,
            session_prefix="__agent_search_recommend",
            output_callback=on_output,
            reply_mode=ReplyMode.CAPTURE_ONLY,
            persist_output_message=False,
            allow_message_tools=False,
        )
        return full_output[0].strip()

    def start_recommend_task(
            self,
            filtered_indices: Optional[List[int]],
            search_results_count: int,
            results: List[Any],
    ) -> None:
        """
        启动AI推荐任务。
        """
        if not self.is_ai_recommend_enabled:
            logger.warning("AI推荐功能未启用，跳过任务执行")
            return

        state = type(self)
        request_hash = self._calculate_recommend_request_hash(
            filtered_indices, search_results_count
        )
        if request_hash == state._current_recommend_request_hash:
            return

        self.cancel_ai_recommend()
        state._current_recommend_request_hash = request_hash

        async def run_recommend():
            current_task = asyncio.current_task()

            def is_current_request() -> bool:
                return state._current_recommend_request_hash == request_hash

            try:
                state._ai_recommend_running = True

                items, valid_indices = self._extract_recommend_items(
                    filtered_indices=filtered_indices,
                    results=results,
                )
                if not items:
                    if is_current_request():
                        state._ai_recommend_error = "没有可用于AI推荐的资源"
                    return

                user_preference = (
                        settings.AI_RECOMMEND_USER_PREFERENCE
                        or "Prefer high-quality resources with more seeders"
                )
                search_results_text = (
                    f"User Preference: {user_preference}\n\n"
                    f"Candidate Resources:\n{chr(10).join(items)}"
                )
                ai_response = await self._invoke_recommend_llm(search_results_text)
                if not ai_response:
                    if is_current_request():
                        state._ai_recommend_error = "AI推荐未返回结果"
                    return

                json_match = re.search(r"\[.*?]", ai_response, re.DOTALL)
                if not json_match:
                    raise ValueError(f"无法从响应中提取JSON数组: {ai_response}")

                ai_indices = json.loads(json_match.group())
                if not isinstance(ai_indices, list):
                    raise ValueError(f"AI返回格式错误: {ai_response}")

                original_indices = self._restore_original_indices(
                    ai_indices=self._normalize_ai_indices(ai_indices),
                    filtered_indices=filtered_indices,
                    valid_indices=valid_indices,
                    results_count=len(results),
                )
                if not is_current_request():
                    logger.info("AI推荐结果已过期，丢弃旧结果")
                    return

                state._ai_recommend_result = original_indices
                self.save_cache(original_indices, self.__ai_indices_cache_file)
                logger.info(f"AI推荐完成: {len(original_indices)}项")
            except asyncio.CancelledError:
                logger.info("AI推荐任务被取消")
            except Exception as err:
                logger.error(f"AI推荐任务失败: {err}")
                if is_current_request():
                    state._ai_recommend_error = str(err)
            finally:
                if state._ai_recommend_task == current_task:
                    state._ai_recommend_running = False
                    state._ai_recommend_task = None

        state._ai_recommend_task = asyncio.create_task(run_recommend())

    def search_by_id(self, tmdbid: Optional[int] = None, doubanid: Optional[str] = None,
                     mtype: MediaType = None, area: Optional[str] = "title", season: Optional[int] = None,
                     sites: List[int] = None, cache_local: bool = False) -> List[Context]:
        """
        根据TMDBID/豆瓣ID搜索资源，精确匹配，不过滤本地存在的资源
        :param tmdbid: TMDB ID
        :param doubanid: 豆瓣 ID
        :param mtype: 媒体，电影 or 电视剧
        :param area: 搜索范围，title or imdbid
        :param season: 季数
        :param sites: 站点ID列表
        :param cache_local: 是否缓存到本地
        """
        if cache_local:
            self.cancel_ai_recommend()
            self.save_last_search_params(
                keyword=self._build_search_keyword(tmdbid=tmdbid, doubanid=doubanid),
                mtype=mtype,
                area=area,
                season=season,
                sites=sites,
            )
        mediainfo = self.recognize_media(tmdbid=tmdbid, doubanid=doubanid, mtype=mtype)
        if not mediainfo:
            logger.error(f'{tmdbid} 媒体信息识别失败！')
            return []
        no_exists = None
        if season is not None:
            no_exists = {
                tmdbid or doubanid: {
                    season: NotExistMediaInfo(episodes=[])
                }
            }
        results = self.process(mediainfo=mediainfo, sites=sites, area=area, no_exists=no_exists)
        # 保存到本地文件
        if cache_local:
            self.save_cache(results, self.__result_temp_file)
        return results

    def search_by_title(self, title: str, page: Optional[int] = 0,
                        sites: List[int] = None, cache_local: Optional[bool] = False) -> List[Context]:
        """
        根据标题搜索资源，不识别不过滤，直接返回站点内容
        :param title: 标题，为空时返回所有站点首页内容
        :param page: 页码
        :param sites: 站点ID列表
        :param cache_local: 是否缓存到本地
        """
        if cache_local:
            self.cancel_ai_recommend()
            self.save_last_search_params(
                keyword=title,
                area="title",
                sites=sites,
            )
        if title:
            logger.info(f'开始搜索资源，关键词：{title} ...')
        else:
            logger.info(f'开始浏览资源，站点：{sites} ...')
        # 搜索
        torrents = self.__search_all_sites(keyword=title, sites=sites, page=page) or []
        if not torrents:
            logger.warn(f'{title} 未搜索到资源')
            return []
        # 组装上下文
        contexts = [
            Context(
                meta_info=MetaInfo(title=torrent.title, subtitle=torrent.description),
                torrent_info=torrent,
                resource_source="search",
            ) for torrent in torrents
        ]
        # 保存到本地文件
        if cache_local:
            self.save_cache(contexts, self.__result_temp_file)
        return contexts

    def last_search_results(self) -> Optional[List[Context]]:
        """
        获取上次搜索结果
        """
        return self.load_cache(self.__result_temp_file)

    async def async_last_search_results(self) -> Optional[List[Context]]:
        """
        异步获取上次搜索结果
        """
        return await self.async_load_cache(self.__result_temp_file)

    async def async_last_subtitle_search_results(self) -> Optional[List[SubtitleInfo]]:
        """
        异步获取上次字幕搜索结果。
        """
        return await self.async_load_cache(self.__subtitle_result_temp_file)

    async def async_search_subtitles_by_title(self, title: str, page: Optional[int] = 0,
                                              sites: List[int] = None,
                                              cache_local: Optional[bool] = False) -> List[SubtitleInfo]:
        """
        根据标题异步搜索字幕，不识别不过滤，直接返回站点字幕内容。
        :param title: 标题关键词
        :param page: 页码
        :param sites: 站点ID列表
        :param cache_local: 是否缓存到本地
        """
        if cache_local:
            self.cancel_ai_recommend()
            await self.async_save_last_search_params(
                keyword=title,
                area="title",
                sites=sites,
                result_type="subtitle",
            )
        logger.info(f'开始搜索字幕，关键词：{title} ...')
        subtitles = await self.__async_search_subtitles_all_sites(
            keyword=title, sites=sites, page=page
        ) or []
        if not subtitles:
            logger.warn(f'{title} 未搜索到字幕')
            return []
        if cache_local:
            await self.async_save_cache(subtitles, self.__subtitle_result_temp_file)
        return subtitles

    async def async_search_subtitles_by_title_stream(self, title: str, page: Optional[int] = 0,
                                                     sites: List[int] = None,
                                                     cache_local: Optional[bool] = False) -> AsyncIterator[dict]:
        """
        根据标题渐进式搜索字幕，不识别不过滤，按站点完成顺序返回结果。
        """
        if cache_local:
            self.cancel_ai_recommend()
            await self.async_save_last_search_params(
                keyword=title,
                area="title",
                sites=sites,
                result_type="subtitle",
            )
        logger.info(f'开始渐进式搜索字幕，关键词：{title} ...')

        subtitles: List[SubtitleInfo] = []
        async for event in self.__async_search_subtitles_all_sites_stream(
                keyword=title, sites=sites, page=page):
            result = event.pop("items", []) or []
            if result:
                subtitles.extend(result)
            yield {
                **event,
                "type": "append",
                "items": [subtitle.to_dict() for subtitle in result],
                "total_items": len(subtitles)
            }

        if cache_local:
            await self.async_save_cache(subtitles, self.__subtitle_result_temp_file)

        if not subtitles:
            logger.warn(f'{title} 未搜索到字幕')
        yield {
            "type": "done",
            "stage": "done",
            "text": f"搜索完成，共 {len(subtitles)} 个字幕",
            "items": [subtitle.to_dict() for subtitle in subtitles],
            "total_items": len(subtitles)
        }

    async def async_search_by_id(self, tmdbid: Optional[int] = None, doubanid: Optional[str] = None,
                                 mtype: MediaType = None, area: Optional[str] = "title", season: Optional[int] = None,
                                 sites: List[int] = None, cache_local: bool = False) -> List[Context]:
        """
        根据TMDBID/豆瓣ID异步搜索资源，精确匹配，不过滤本地存在的资源
        :param tmdbid: TMDB ID
        :param doubanid: 豆瓣 ID
        :param mtype: 媒体，电影 or 电视剧
        :param area: 搜索范围，title or imdbid
        :param season: 季数
        :param sites: 站点ID列表
        :param cache_local: 是否缓存到本地
        """
        if cache_local:
            self.cancel_ai_recommend()
            await self.async_save_last_search_params(
                keyword=self._build_search_keyword(tmdbid=tmdbid, doubanid=doubanid),
                mtype=mtype,
                area=area,
                season=season,
                sites=sites,
            )
        mediainfo = await self.async_recognize_media(tmdbid=tmdbid, doubanid=doubanid, mtype=mtype)
        if not mediainfo:
            logger.error(f'{tmdbid} 媒体信息识别失败！')
            return []
        no_exists = None
        if season is not None:
            no_exists = {
                tmdbid or doubanid: {
                    season: NotExistMediaInfo(episodes=[])
                }
            }
        results = await self.async_process(mediainfo=mediainfo, sites=sites, area=area, no_exists=no_exists)
        # 保存到本地文件
        if cache_local:
            await self.async_save_cache(results, self.__result_temp_file)
        return results

    async def async_search_by_title(self, title: str, page: Optional[int] = 0,
                                    sites: List[int] = None, cache_local: Optional[bool] = False) -> List[Context]:
        """
        根据标题异步搜索资源，不识别不过滤，直接返回站点内容
        :param title: 标题，为空时返回所有站点首页内容
        :param page: 页码
        :param sites: 站点ID列表
        :param cache_local: 是否缓存到本地
        """
        if cache_local:
            self.cancel_ai_recommend()
            await self.async_save_last_search_params(
                keyword=title,
                area="title",
                sites=sites,
            )
        if title:
            logger.info(f'开始搜索资源，关键词：{title} ...')
        else:
            logger.info(f'开始浏览资源，站点：{sites} ...')
        # 搜索
        torrents = await self.__async_search_all_sites(keyword=title, sites=sites, page=page) or []
        if not torrents:
            logger.warn(f'{title} 未搜索到资源')
            return []
        # 组装上下文
        contexts = [
            Context(
                meta_info=MetaInfo(title=torrent.title, subtitle=torrent.description),
                torrent_info=torrent,
                resource_source="search",
            ) for torrent in torrents
        ]
        # 保存到本地文件
        if cache_local:
            await self.async_save_cache(contexts, self.__result_temp_file)
        return contexts

    async def async_search_by_title_stream(self, title: str, page: Optional[int] = 0,
                                           sites: List[int] = None,
                                           cache_local: Optional[bool] = False) -> AsyncIterator[dict]:
        """
        根据标题渐进式搜索资源，不识别不过滤，按站点完成顺序返回结果
        """
        if cache_local:
            self.cancel_ai_recommend()
            await self.async_save_last_search_params(
                keyword=title,
                area="title",
                sites=sites,
            )
        if title:
            logger.info(f'开始渐进式搜索资源，关键词：{title} ...')
        else:
            logger.info(f'开始渐进式浏览资源，站点：{sites} ...')

        contexts: List[Context] = []
        async for event in self.__async_search_all_sites_stream(keyword=title, sites=sites, page=page):
            result = event.pop("items", []) or []
            batch_contexts = [
                Context(
                    meta_info=MetaInfo(title=torrent.title, subtitle=torrent.description),
                    torrent_info=torrent,
                    resource_source="search",
                )
                for torrent in result
            ]
            if batch_contexts:
                contexts.extend(batch_contexts)
            yield {
                **event,
                "type": "append",
                "items": [context.to_dict() for context in batch_contexts],
                "total_items": len(contexts)
            }

        if cache_local:
            await self.async_save_cache(contexts, self.__result_temp_file)

        if not contexts:
            logger.warn(f'{title} 未搜索到资源')
        yield {
            "type": "done",
            "text": f"搜索完成，共 {len(contexts)} 个资源",
            "items": [context.to_dict() for context in contexts],
            "total_items": len(contexts)
        }

    async def async_search_by_id_stream(self, tmdbid: Optional[int] = None, doubanid: Optional[str] = None,
                                        mtype: MediaType = None, area: Optional[str] = "title",
                                        season: Optional[int] = None, sites: List[int] = None,
                                        cache_local: bool = False) -> AsyncIterator[dict]:
        """
        根据TMDBID/豆瓣ID渐进式搜索资源，先返回站点原始候选，再返回过滤匹配后的最终结果
        """
        if cache_local:
            self.cancel_ai_recommend()
            await self.async_save_last_search_params(
                keyword=self._build_search_keyword(tmdbid=tmdbid, doubanid=doubanid),
                mtype=mtype,
                area=area,
                season=season,
                sites=sites,
            )
        mediainfo = await self.async_recognize_media(tmdbid=tmdbid, doubanid=doubanid, mtype=mtype)
        if not mediainfo:
            logger.error(f'{tmdbid} 媒体信息识别失败！')
            yield {
                "type": "error",
                "success": False,
                "message": "媒体信息识别失败"
            }
            return

        no_exists = None
        if season is not None:
            no_exists = {
                tmdbid or doubanid: {
                    season: NotExistMediaInfo(episodes=[])
                }
            }

        contexts: List[Context] = []
        async for event in self.async_process_stream(mediainfo=mediainfo, sites=sites, area=area, no_exists=no_exists):
            if event.get("type") == "done":
                contexts = event.get("contexts") or []
                event = {
                    key: value
                    for key, value in event.items()
                    if key != "contexts"
                }
            yield event

        if cache_local:
            await self.async_save_cache(contexts, self.__result_temp_file)

    @staticmethod
    def __prepare_params(mediainfo: MediaInfo,
                         keyword: Optional[str] = None,
                         no_exists: Dict[int, Dict[int, NotExistMediaInfo]] = None
                         ) -> Tuple[Dict[int, List[int]], List[str]]:
        """
        准备搜索参数
        """
        # 缺失的季集
        mediakey = mediainfo.tmdb_id or mediainfo.douban_id
        if no_exists and no_exists.get(mediakey):
            # 过滤剧集
            season_episodes = {sea: info.episodes
                               for sea, info in no_exists[mediakey].items()}
        elif mediainfo.season is not None:
            # 豆瓣只搜索当前季
            season_episodes = {mediainfo.season: []}
        else:
            season_episodes = None

        # 搜索关键词
        if keyword:
            keywords = [keyword]
        else:
            # 去重去空，但要保持顺序
            keywords = list(dict.fromkeys([k for k in [mediainfo.title,
                                                       mediainfo.original_title,
                                                       mediainfo.en_title,
                                                       mediainfo.hk_title,
                                                       mediainfo.tw_title,
                                                       mediainfo.sg_title] if k]))
            # 限制搜索关键词数量
            if settings.MAX_SEARCH_NAME_LIMIT:
                keywords = keywords[:settings.MAX_SEARCH_NAME_LIMIT]

        return season_episodes, keywords

    def __parse_result(self, torrents: List[TorrentInfo],
                       mediainfo: MediaInfo,
                       keyword: Optional[str] = None,
                       rule_groups: List[str] = None,
                       season_episodes: Dict[int, List[int]] = None,
                       custom_words: List[str] = None,
                       filter_params: Dict[str, str] = None) -> List[Context]:
        """
        处理搜索结果
        """

        def __do_filter(torrent_list: List[TorrentInfo]) -> List[TorrentInfo]:
            """
            执行优先级过滤
            """
            return self.filter_torrents(rule_groups=rule_groups,
                                        torrent_list=torrent_list,
                                        mediainfo=mediainfo) or []

        def __do_site_filter(torrent_list: List[TorrentInfo]) -> List[TorrentInfo]:
            """
            执行单个站点的过滤流程
            """
            if not torrent_list:
                return []

            filtered_torrents = torrent_list
            if filter_params:
                handler = TorrentHelper()
                filtered_torrents = [
                    t for t in filtered_torrents
                    if handler.filter_torrent(t, filter_params)
                ]

            if rule_groups and filtered_torrents:
                filtered_torrents = __do_filter(filtered_torrents)

            return filtered_torrents

        def __do_parallel_filter(torrent_list: List[TorrentInfo]) -> List[TorrentInfo]:
            """
            按站点并发执行过滤，保持站点内顺序不变
            """
            if not torrent_list or (not filter_params and not rule_groups):
                return torrent_list

            site_torrents: Dict[Tuple[Optional[int], Optional[str]], List[TorrentInfo]] = {}
            for t in torrent_list:
                site_key = (t.site, t.site_name)
                if site_key not in site_torrents:
                    site_torrents[site_key] = []
                site_torrents[site_key].append(t)

            if len(site_torrents) <= 1:
                return __do_site_filter(torrent_list)

            finished_count = 0
            filtered_by_site: Dict[Tuple[Optional[int], Optional[str]], List[TorrentInfo]] = {}
            max_workers = min(len(site_torrents), settings.CONF.threadpool or len(site_torrents))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                all_tasks = {
                    executor.submit(__do_site_filter, site_torrent_list): site_key
                    for site_key, site_torrent_list in site_torrents.items()
                }
                for future in as_completed(all_tasks):
                    finished_count += 1
                    filtered_by_site[all_tasks[future]] = future.result() or []
                    progress.update(
                        value=finished_count / len(site_torrents) * 50,
                        text=f'正在过滤，已完成 {finished_count} / {len(site_torrents)} 个站点 ...'
                    )

            filtered_ids = {
                id(t)
                for filtered_torrents in filtered_by_site.values()
                for t in filtered_torrents
            }
            return [t for t in torrent_list if id(t) in filtered_ids]

        if not torrents:
            logger.warn(f'{keyword or mediainfo.title} 未搜索到资源')
            return []

        # 开始新进度
        progress = ProgressHelper(ProgressKey.Search)
        progress.start()

        # 开始过滤
        progress.update(value=0, text=f'开始过滤，总 {len(torrents)} 个资源，请稍候...')
        # 匹配订阅附加参数
        if filter_params:
            logger.info(f'开始附加参数过滤，附加参数：{filter_params} ...')
        # 开始过滤规则过滤
        if rule_groups is None:
            # 取搜索过滤规则
            rule_groups: List[str] = SystemConfigOper().get(SystemConfigKey.SearchFilterRuleGroups)
        if rule_groups:
            logger.info(f'开始过滤规则/剧集过滤，使用规则组：{rule_groups} ...')
        torrents = __do_parallel_filter(torrents)
        if rule_groups:
            if not torrents:
                logger.warn(f'{keyword or mediainfo.title} 没有符合过滤规则的资源')
                return []
            logger.info(f"过滤规则/剧集过滤完成，剩余 {len(torrents)} 个资源")

        # 过滤完成
        progress.update(value=50, text=f'过滤完成，剩余 {len(torrents)} 个资源')

        # 总数
        _total = len(torrents)
        # 已处理数
        _count = 0

        # 开始匹配
        _match_torrents = []
        try:
            # 英文标题应该在别名/原标题中，不需要再匹配
            logger.info(f"开始匹配结果 标题：{mediainfo.title}，原标题：{mediainfo.original_title}，别名：{mediainfo.names}")
            progress.update(value=51, text=f'开始匹配，总 {_total} 个资源 ...')
            for torrent in torrents:
                if global_vars.is_system_stopped:
                    break
                _count += 1
                progress.update(value=(_count / _total) * 96,
                                text=f'正在匹配 {torrent.site_name}，已完成 {_count} / {_total} ...')
                if not torrent.title:
                    continue

                # 识别元数据
                torrent_meta = MetaInfo(title=torrent.title, subtitle=torrent.description,
                                        custom_words=custom_words)
                if torrent.title != torrent_meta.org_string:
                    logger.info(f"种子名称应用识别词后发生改变：{torrent.title} => {torrent_meta.org_string}")
                # 季集数过滤
                if season_episodes \
                        and not TorrentHelper.match_season_episodes(torrent=torrent,
                                                                    meta=torrent_meta,
                                                                    season_episodes=season_episodes):
                    continue
                # 比对IMDBID
                if torrent.imdbid \
                        and mediainfo.imdb_id \
                        and torrent.imdbid == mediainfo.imdb_id:
                    logger.info(f'{mediainfo.title} 通过IMDBID匹配到资源：{torrent.site_name} - {torrent.title}')
                    _match_torrents.append((torrent, torrent_meta, "imdbid"))
                    continue

                # 比对种子
                if TorrentHelper.match_torrent(mediainfo=mediainfo,
                                               torrent_meta=torrent_meta,
                                               torrent=torrent):
                    # 匹配成功
                    _match_torrents.append((torrent, torrent_meta, "title"))
                    continue
            # 匹配完成
            logger.info(f"匹配完成，共匹配到 {len(_match_torrents)} 个资源")
            progress.update(value=97,
                            text=f'匹配完成，共匹配到 {len(_match_torrents)} 个资源')

            # 去掉mediainfo中多余的数据
            mediainfo.clear()
            # 组装上下文
            contexts = [
                Context(
                    torrent_info=t[0],
                    media_info=mediainfo,
                    meta_info=t[1],
                    resource_source="search",
                    match_source=t[2],
                    candidate_recognized=False,
                    media_info_is_target=True,
                ) for t in _match_torrents
            ]
        finally:
            torrents.clear()
            del torrents
            _match_torrents.clear()
            del _match_torrents

        # 排序
        progress.update(value=99,
                        text=f'正在对 {len(contexts)} 个资源进行排序，请稍候...')
        contexts = TorrentHelper.sort_torrents(contexts)

        # 结束进度
        logger.info(f'搜索完成，共 {len(contexts)} 个资源')
        progress.update(value=100,
                        text=f'搜索完成，共 {len(contexts)} 个资源')
        progress.end()

        # 去重后返回
        return self.__remove_duplicate(contexts)

    @staticmethod
    def __remove_duplicate(_torrents: List[Context]) -> List[Context]:
        """
        去除重复的种子
        :param _torrents: 种子列表
        :return: 去重后的种子列表
        """
        return list({f"{t.torrent_info.site_name}_{t.torrent_info.title}_{t.torrent_info.description}": t
                     for t in _torrents}.values())

    def process(self, mediainfo: MediaInfo,
                keyword: Optional[str] = None,
                no_exists: Dict[int, Dict[int, NotExistMediaInfo]] = None,
                sites: List[int] = None,
                rule_groups: List[str] = None,
                area: Optional[str] = "title",
                custom_words: List[str] = None,
                filter_params: Dict[str, str] = None) -> List[Context]:
        """
        根据媒体信息搜索种子资源，精确匹配，应用过滤规则，同时根据no_exists过滤本地已存在的资源
        :param mediainfo: 媒体信息
        :param keyword: 搜索关键词
        :param no_exists: 缺失的媒体信息
        :param sites: 站点ID列表，为空时搜索所有站点
        :param rule_groups: 过滤规则组名称列表
        :param area: 搜索范围，title or imdbid
        :param custom_words: 自定义识别词列表
        :param filter_params: 过滤参数
        """

        # 豆瓣标题处理
        if not mediainfo.tmdb_id:
            meta = MetaInfo(title=mediainfo.title)
            mediainfo.title = meta.name
            mediainfo.season = meta.begin_season
        logger.info(f'开始搜索资源，关键词：{keyword or mediainfo.title} ...')

        # 补充媒体信息
        if not mediainfo.names:
            mediainfo: MediaInfo = self.recognize_media(mtype=mediainfo.type,
                                                        tmdbid=mediainfo.tmdb_id,
                                                        doubanid=mediainfo.douban_id)
            if not mediainfo:
                logger.error(f'媒体信息识别失败！')
                return []

        # 准备搜索参数
        season_episodes, keywords = self.__prepare_params(
            mediainfo=mediainfo,
            keyword=keyword,
            no_exists=no_exists
        )

        # 站点搜索结果
        torrents: List[TorrentInfo] = []
        # 站点搜索次数
        search_count = 0

        # 多关键字执行搜索
        for search_word in keywords:
            # 强制休眠 1-10 秒
            if search_count > 0:
                logger.info(f"已搜索 {search_count} 次，强制休眠 1-10 秒 ...")
                time.sleep(random.randint(1, 10))

            # 搜索站点
            results = self.__search_all_sites(
                mediainfo=mediainfo,
                keyword=search_word,
                sites=sites,
                area=area
            ) or []
            # 合并结果

            search_count += 1
            torrents.extend(results)

            # 有结果则停止
            if not settings.SEARCH_MULTIPLE_NAME and torrents:
                logger.info(f"共搜索到 {len(torrents)} 个资源，停止搜索")
                break

        # 处理结果
        return self.__parse_result(
            torrents=torrents,
            mediainfo=mediainfo,
            keyword=keyword,
            rule_groups=rule_groups,
            season_episodes=season_episodes,
            custom_words=custom_words,
            filter_params=filter_params
        )

    async def async_process(self, mediainfo: MediaInfo,
                            keyword: Optional[str] = None,
                            no_exists: Dict[int, Dict[int, NotExistMediaInfo]] = None,
                            sites: List[int] = None,
                            rule_groups: List[str] = None,
                            area: Optional[str] = "title",
                            custom_words: List[str] = None,
                            filter_params: Dict[str, str] = None) -> List[Context]:
        """
        根据媒体信息异步搜索种子资源，精确匹配，应用过滤规则，同时根据no_exists过滤本地已存在的资源
        :param mediainfo: 媒体信息
        :param keyword: 搜索关键词
        :param no_exists: 缺失的媒体信息
        :param sites: 站点ID列表，为空时搜索所有站点
        :param rule_groups: 过滤规则组名称列表
        :param area: 搜索范围，title or imdbid
        :param custom_words: 自定义识别词列表
        :param filter_params: 过滤参数
        """

        # 豆瓣标题处理
        if not mediainfo.tmdb_id:
            meta = MetaInfo(title=mediainfo.title)
            mediainfo.title = meta.name
            mediainfo.season = meta.begin_season
        logger.info(f'开始搜索资源，关键词：{keyword or mediainfo.title} ...')

        # 补充媒体信息
        if not mediainfo.names:
            mediainfo: MediaInfo = await self.async_recognize_media(mtype=mediainfo.type,
                                                                    tmdbid=mediainfo.tmdb_id,
                                                                    doubanid=mediainfo.douban_id)
            if not mediainfo:
                logger.error(f'媒体信息识别失败！')
                return []

        # 准备搜索参数
        season_episodes, keywords = self.__prepare_params(
            mediainfo=mediainfo,
            keyword=keyword,
            no_exists=no_exists
        )

        # 站点搜索结果
        torrents: List[TorrentInfo] = []
        # 站点搜索次数
        search_count = 0

        # 多关键字执行搜索
        for search_word in keywords:
            # 强制休眠 1-10 秒
            if search_count > 0:
                logger.info(f"已搜索 {search_count} 次，强制休眠 1-10 秒 ...")
                await asyncio.sleep(random.randint(1, 10))
            # 搜索站点
            torrents.extend(
                await self.__async_search_all_sites(
                    mediainfo=mediainfo,
                    keyword=search_word,
                    sites=sites,
                    area=area
                ) or []
            )
            search_count += 1
            # 未开启多名称搜索时，有结果则停止
            if not settings.SEARCH_MULTIPLE_NAME and torrents:
                logger.info(f"共搜索到 {len(torrents)} 个资源，停止搜索")
                break

        # 处理结果
        return await run_in_threadpool(self.__parse_result,
                                       torrents=torrents,
                                       mediainfo=mediainfo,
                                       keyword=keyword,
                                       rule_groups=rule_groups,
                                       season_episodes=season_episodes,
                                       custom_words=custom_words,
                                       filter_params=filter_params
                                       )

    async def async_process_stream(self, mediainfo: MediaInfo,
                                   keyword: Optional[str] = None,
                                   no_exists: Dict[int, Dict[int, NotExistMediaInfo]] = None,
                                   sites: List[int] = None,
                                   rule_groups: List[str] = None,
                                   area: Optional[str] = "title",
                                   custom_words: List[str] = None,
                                   filter_params: Dict[str, str] = None) -> AsyncIterator[dict]:
        """
        根据媒体信息渐进式搜索种子资源，先返回站点候选，再返回过滤匹配后的最终结果
        """

        # 豆瓣标题处理
        if not mediainfo.tmdb_id:
            meta = MetaInfo(title=mediainfo.title)
            mediainfo.title = meta.name
            mediainfo.season = meta.begin_season
        logger.info(f'开始渐进式搜索资源，关键词：{keyword or mediainfo.title} ...')

        # 补充媒体信息
        if not mediainfo.names:
            mediainfo = await self.async_recognize_media(mtype=mediainfo.type,
                                                         tmdbid=mediainfo.tmdb_id,
                                                         doubanid=mediainfo.douban_id)
            if not mediainfo:
                logger.error(f'媒体信息识别失败！')
                yield {
                    "type": "error",
                    "success": False,
                    "message": "媒体信息识别失败"
                }
                return

        # 准备搜索参数
        season_episodes, keywords = self.__prepare_params(
            mediainfo=mediainfo,
            keyword=keyword,
            no_exists=no_exists
        )

        torrents: List[TorrentInfo] = []
        candidate_contexts: List[Context] = []
        search_count = 0

        for search_word in keywords:
            if search_count > 0:
                logger.info(f"已搜索 {search_count} 次，强制休眠 1-10 秒 ...")
                await asyncio.sleep(random.randint(1, 10))

            async for event in self.__async_search_all_sites_stream(
                    mediainfo=mediainfo,
                    keyword=search_word,
                    sites=sites,
                    area=area):
                result = event.pop("items", []) or []
                torrents.extend(result)
                batch_contexts = [
                    Context(
                        meta_info=MetaInfo(title=torrent.title, subtitle=torrent.description),
                        media_info=mediainfo,
                        torrent_info=torrent,
                        resource_source="search",
                        media_info_is_target=True,
                    )
                    for torrent in result
                ]
                candidate_contexts.extend(batch_contexts)
                yield {
                    **event,
                    "type": "append",
                    "stage": "searching",
                    "items": [context.to_dict() for context in batch_contexts],
                    "total_items": len(candidate_contexts)
                }

            search_count += 1
            if not settings.SEARCH_MULTIPLE_NAME and torrents:
                logger.info(f"共搜索到 {len(torrents)} 个资源，停止搜索")
                break

        yield {
            "type": "progress",
            "stage": "filtering",
            "value": 98,
            "text": f"正在过滤匹配 {len(torrents)} 个候选资源 ..."
        }

        contexts = await run_in_threadpool(self.__parse_result,
                                           torrents=torrents,
                                           mediainfo=mediainfo,
                                           keyword=keyword,
                                           rule_groups=rule_groups,
                                           season_episodes=season_episodes,
                                           custom_words=custom_words,
                                           filter_params=filter_params)
        final_items = [context.to_dict() for context in contexts]
        yield {
            "type": "replace",
            "stage": "filtered",
            "value": 100,
            "text": f"过滤匹配完成，共 {len(contexts)} 个资源",
            "items": final_items,
            "total_items": len(contexts)
        }
        yield {
            "type": "done",
            "stage": "done",
            "text": f"搜索完成，共 {len(contexts)} 个资源",
            "items": final_items,
            "total_items": len(contexts),
            "contexts": contexts
        }

    def __search_all_sites(self, keyword: str,
                           mediainfo: Optional[MediaInfo] = None,
                           sites: List[int] = None,
                           page: Optional[int] = 0,
                           area: Optional[str] = "title") -> Optional[List[TorrentInfo]]:
        """
        多线程搜索多个站点
        :param mediainfo:  识别的媒体信息
        :param keyword:  搜索关键词
        :param sites:  指定站点ID列表，如有则只搜索指定站点，否则搜索所有站点
        :param page:  搜索页码
        :param area:  搜索区域 title or imdbid
        :reutrn: 资源列表
        """
        # 未开启的站点不搜索
        indexer_sites = []

        # 配置的索引站点
        if not sites:
            sites = SystemConfigOper().get(SystemConfigKey.IndexerSites) or []

        for indexer in SitesHelper().get_indexers():
            # 检查站点索引开关
            if not sites or indexer.get("id") in sites:
                indexer_sites.append(indexer)
        if not indexer_sites:
            logger.warn('未开启任何有效站点，无法搜索资源')
            return []

        # 开始进度
        progress = ProgressHelper(ProgressKey.Search)
        progress.start()
        # 开始计时
        start_time = datetime.now()
        search_pages = self._build_search_pages(page)
        # 总数
        total_num = len(indexer_sites) * len(search_pages)
        # 完成数
        finish_count = 0
        # 更新进度
        progress.update(value=0,
                        text=f"开始搜索，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...")
        # 结果集
        results = []
        # 同一站点按页顺序抓取，避免空页后仍继续请求该站点的后续页。
        max_workers = min(len(indexer_sites), settings.CONF.threadpool or len(indexer_sites))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            pending_tasks = {}

            def submit_site_page(site: dict, page_index: int):
                """
                提交单个站点页搜索任务，并记录该任务对应的站点和页码位置。
                """
                search_page = search_pages[page_index]
                search_keyword = mediainfo.imdb_id if area == "imdbid" and mediainfo else keyword
                if area == "imdbid":
                    # 搜索IMDBID
                    task = executor.submit(self.search_torrents, site=site,
                                           keyword=search_keyword,
                                           mtype=mediainfo.type if mediainfo else None,
                                           page=search_page)
                else:
                    # 搜索标题
                    task = executor.submit(self.search_torrents, site=site,
                                           keyword=search_keyword,
                                           mtype=mediainfo.type if mediainfo else None,
                                           page=search_page)
                pending_tasks[task] = (site, page_index, search_page, search_keyword)

            for site in indexer_sites:
                submit_site_page(site=site, page_index=0)

            try:
                while pending_tasks:
                    if global_vars.is_system_stopped:
                        break
                    done_tasks, _ = wait(pending_tasks, return_when=FIRST_COMPLETED)
                    for future in done_tasks:
                        site, page_index, search_page, search_keyword = pending_tasks.pop(future)
                        finish_count += 1
                        result = future.result()
                        if result:
                            results.extend(result)
                        if (
                            self._should_continue_search_pages(
                                site=site, page_results=result, keyword=search_keyword
                            )
                            and page_index + 1 < len(search_pages)
                        ):
                            submit_site_page(site=site, page_index=page_index + 1)
                        else:
                            logger.debug(
                                f"{site.get('name')} 第 {search_page} 页返回 {len(result or [])} 条，停止继续翻页"
                            )
                        logger.info(f"站点搜索进度：{finish_count} / {total_num}")
                        progress.update(value=finish_count / total_num * 100,
                                        text=f"正在搜索{keyword or ''}，已完成 {finish_count} / {total_num} 个请求 ...")
            finally:
                for task in pending_tasks:
                    task.cancel()
        # 计算耗时
        end_time = datetime.now()
        # 更新进度
        progress.update(value=100,
                        text=f"站点搜索完成，有效资源数：{len(results)}，总耗时 {(end_time - start_time).seconds} 秒")
        logger.info(f"站点搜索完成，有效资源数：{len(results)}，总耗时 {(end_time - start_time).seconds} 秒")
        # 结束进度
        progress.end()

        # 返回
        return results

    async def __async_search_all_sites(self, keyword: str,
                                       mediainfo: Optional[MediaInfo] = None,
                                       sites: List[int] = None,
                                       page: Optional[int] = 0,
                                       area: Optional[str] = "title") -> Optional[List[TorrentInfo]]:
        """
        异步搜索多个站点
        :param mediainfo:  识别的媒体信息
        :param keyword:  搜索关键词
        :param sites:  指定站点ID列表，如有则只搜索指定站点，否则搜索所有站点
        :param page:  搜索页码
        :param area:  搜索区域 title or imdbid
        :reutrn: 资源列表
        """
        # 未开启的站点不搜索
        indexer_sites = []

        # 配置的索引站点
        if not sites:
            sites = SystemConfigOper().get(SystemConfigKey.IndexerSites) or []

        for indexer in await SitesHelper().async_get_indexers():
            # 检查站点索引开关
            if not sites or indexer.get("id") in sites:
                indexer_sites.append(indexer)
        if not indexer_sites:
            logger.warn('未开启任何有效站点，无法搜索资源')
            return []

        # 开始进度
        progress = ProgressHelper(ProgressKey.Search)
        progress.start()
        # 开始计时
        start_time = datetime.now()
        search_pages = self._build_search_pages(page)
        # 总数
        total_num = len(indexer_sites) * len(search_pages)
        # 完成数
        finish_count = 0
        # 更新进度
        progress.update(value=0,
                        text=f"开始搜索，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...")
        # 结果集
        results = []
        semaphore = asyncio.Semaphore(settings.CONF.threadpool or total_num)

        async def search_site_page(site: dict, search_page: int) -> List[TorrentInfo]:
            """
            控制单次站点页请求的并发量，并返回该页的资源列表。
            """
            async with semaphore:
                if area == "imdbid":
                    # 搜索IMDBID
                    return await self.async_search_torrents(site=site,
                                                            keyword=mediainfo.imdb_id if mediainfo else None,
                                                            mtype=mediainfo.type if mediainfo else None,
                                                            page=search_page)
                # 搜索标题
                return await self.async_search_torrents(site=site,
                                                        keyword=keyword,
                                                        mtype=mediainfo.type if mediainfo else None,
                                                        page=search_page)

        pending_tasks = {}

        def submit_site_page(site: dict, page_index: int):
            """
            提交异步站点页搜索任务，并记录该任务对应的站点和页码位置。
            """
            search_page = search_pages[page_index]
            search_keyword = mediainfo.imdb_id if area == "imdbid" and mediainfo else keyword
            task = asyncio.create_task(search_site_page(site=site, search_page=search_page))
            pending_tasks[task] = (site, page_index, search_page, search_keyword)

        for site in indexer_sites:
            submit_site_page(site=site, page_index=0)

        try:
            while pending_tasks:
                if global_vars.is_system_stopped:
                    break
                done_tasks, _ = await asyncio.wait(
                    pending_tasks.keys(),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for future in done_tasks:
                    site, page_index, search_page, search_keyword = pending_tasks.pop(future)
                    finish_count += 1
                    result = await future
                    if result:
                        results.extend(result)
                    if (
                        self._should_continue_search_pages(
                            site=site, page_results=result, keyword=search_keyword
                        )
                        and page_index + 1 < len(search_pages)
                    ):
                        submit_site_page(site=site, page_index=page_index + 1)
                    else:
                        logger.debug(
                            f"{site.get('name')} 第 {search_page} 页返回 {len(result or [])} 条，停止继续翻页"
                        )
                    logger.info(f"站点搜索进度：{finish_count} / {total_num}")
                    progress.update(value=finish_count / total_num * 100,
                                    text=f"正在搜索{keyword or ''}，已完成 {finish_count} / {total_num} 个请求 ...")
        finally:
            for task in pending_tasks:
                if not task.done():
                    task.cancel()
            if pending_tasks:
                await asyncio.gather(*pending_tasks.keys(), return_exceptions=True)

        # 计算耗时
        end_time = datetime.now()
        # 更新进度
        progress.update(value=100,
                        text=f"站点搜索完成，有效资源数：{len(results)}，总耗时 {(end_time - start_time).seconds} 秒")
        logger.info(f"站点搜索完成，有效资源数：{len(results)}，总耗时 {(end_time - start_time).seconds} 秒")
        # 结束进度
        progress.end()

        # 返回
        return results

    async def __async_search_all_sites_stream(self, keyword: str,
                                              mediainfo: Optional[MediaInfo] = None,
                                              sites: List[int] = None,
                                              page: Optional[int] = 0,
                                              area: Optional[str] = "title") -> AsyncIterator[Dict[str, Any]]:
        """
        异步搜索多个站点，按站点完成顺序渐进式返回结果
        :param mediainfo:  识别的媒体信息
        :param keyword:  搜索关键词
        :param sites:  指定站点ID列表，如有则只搜索指定站点，否则搜索所有站点
        :param page:  搜索页码
        :param area:  搜索区域 title or imdbid
        """
        indexer_sites = []

        if not sites:
            sites = SystemConfigOper().get(SystemConfigKey.IndexerSites) or []

        for indexer in await SitesHelper().async_get_indexers():
            if not sites or indexer.get("id") in sites:
                indexer_sites.append(indexer)
        if not indexer_sites:
            logger.warn('未开启任何有效站点，无法搜索资源')
            yield {
                "type": "done",
                "stage": "searching",
                "value": 100,
                "text": "未开启任何有效站点，无法搜索资源",
                "items": [],
                "finished": 0,
                "total": 0
            }
            return

        progress = ProgressHelper(ProgressKey.Search)
        progress.start()
        start_time = datetime.now()
        search_pages = self._build_search_pages(page)
        total_num = len(indexer_sites) * len(search_pages)
        finish_count = 0
        progress.update(value=0,
                        text=f"开始搜索，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...")
        yield {
            "type": "progress",
            "stage": "searching",
            "value": 0,
            "text": f"开始搜索，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...",
            "items": [],
            "finished": 0,
            "total": total_num
        }

        semaphore = asyncio.Semaphore(settings.CONF.threadpool or total_num)

        async def search_site(site: dict, search_page: int) -> List[TorrentInfo]:
            """
            搜索单个站点页，用于渐进式返回入口。
            """
            async with semaphore:
                if area == "imdbid":
                    site_result = await self.async_search_torrents(site=site,
                                                                   keyword=mediainfo.imdb_id if mediainfo else None,
                                                                   mtype=mediainfo.type if mediainfo else None,
                                                                   page=search_page)
                else:
                    site_result = await self.async_search_torrents(site=site,
                                                                   keyword=keyword,
                                                                   mtype=mediainfo.type if mediainfo else None,
                                                                   page=search_page)
                return site_result or []

        tasks = {}

        def submit_site_page(site: dict, page_index: int):
            """
            提交渐进式站点页搜索任务，并保留站点和页码上下文。
            """
            search_page = search_pages[page_index]
            search_keyword = mediainfo.imdb_id if area == "imdbid" and mediainfo else keyword
            task = asyncio.create_task(search_site(site=site, search_page=search_page))
            tasks[task] = (site, page_index, search_page, search_keyword)

        for site in indexer_sites:
            submit_site_page(site=site, page_index=0)

        results_count = 0
        try:
            while tasks:
                if global_vars.is_system_stopped:
                    break
                done_tasks, _ = await asyncio.wait(
                    tasks.keys(),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for future in done_tasks:
                    site, page_index, search_page, search_keyword = tasks.pop(future)
                    finish_count += 1
                    result = await future
                    results_count += len(result)
                    if (
                        self._should_continue_search_pages(
                            site=site, page_results=result, keyword=search_keyword
                        )
                        and page_index + 1 < len(search_pages)
                    ):
                        submit_site_page(site=site, page_index=page_index + 1)
                    else:
                        logger.debug(
                            f"{site.get('name')} 第 {search_page} 页返回 {len(result)} 条，停止继续翻页"
                        )
                    logger.info(f"站点搜索进度：{finish_count} / {total_num}")
                    progress_value = finish_count / total_num * 100
                    progress_text = f"正在搜索{keyword or ''}，已完成 {finish_count} / {total_num} 个请求 ..."
                    progress.update(value=progress_value, text=progress_text)
                    yield {
                        "type": "append",
                        "stage": "searching",
                        "value": progress_value,
                        "text": progress_text,
                        "items": result,
                        "site": site.get("name"),
                        "site_id": site.get("id"),
                        "page": search_page,
                        "finished": finish_count,
                        "total": total_num,
                        "total_items": results_count
                    }
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks.keys(), return_exceptions=True)

        end_time = datetime.now()
        progress.update(value=100,
                        text=f"站点搜索完成，有效资源数：{results_count}，总耗时 {(end_time - start_time).seconds} 秒")
        logger.info(f"站点搜索完成，有效资源数：{results_count}，总耗时 {(end_time - start_time).seconds} 秒")
        progress.end()

    async def __async_search_subtitles_all_sites(self, keyword: str,
                                                 sites: List[int] = None,
                                                 page: Optional[int] = 0) -> Optional[List[SubtitleInfo]]:
        """
        异步搜索多个站点的字幕资源。
        :param keyword: 搜索关键词
        :param sites: 指定站点ID列表，如有则只搜索指定站点，否则搜索所有站点
        :param page: 搜索页码
        :reutrn: 字幕资源列表
        """
        indexer_sites = []

        if not sites:
            sites = SystemConfigOper().get(SystemConfigKey.IndexerSites) or []

        for indexer in await SitesHelper().async_get_indexers():
            if not indexer.get("subtitles"):
                continue
            if not sites or indexer.get("id") in sites:
                indexer_sites.append(indexer)
        if not indexer_sites:
            logger.warn('未开启任何支持字幕搜索的有效站点，无法搜索字幕')
            return []

        progress = ProgressHelper(ProgressKey.Search)
        progress.start()
        start_time = datetime.now()
        search_pages = self._build_search_pages(page)
        total_num = len(indexer_sites) * len(search_pages)
        finish_count = 0
        progress.update(value=0,
                        text=f"开始搜索字幕，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...")
        results = []
        semaphore = asyncio.Semaphore(settings.CONF.threadpool or total_num)

        async def search_site_page(site: dict, search_page: int) -> List[SubtitleInfo]:
            """
            控制单次字幕站点页请求的并发量，并返回该页的字幕列表。
            """
            async with semaphore:
                return await self.async_search_subtitles(
                    site=site, keyword=keyword, page=search_page
                )

        pending_tasks = {}

        def submit_site_page(site: dict, page_index: int):
            """
            提交异步字幕站点页搜索任务，并记录站点和页码位置。
            """
            search_page = search_pages[page_index]
            task = asyncio.create_task(search_site_page(site=site, search_page=search_page))
            pending_tasks[task] = (site, page_index, search_page)

        for site in indexer_sites:
            submit_site_page(site=site, page_index=0)

        try:
            while pending_tasks:
                if global_vars.is_system_stopped:
                    break
                done_tasks, _ = await asyncio.wait(
                    pending_tasks.keys(),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for future in done_tasks:
                    site, page_index, search_page = pending_tasks.pop(future)
                    finish_count += 1
                    result = await future
                    if result:
                        results.extend(result)
                    if (
                            self._should_continue_subtitle_search_pages(site=site, page_results=result)
                            and page_index + 1 < len(search_pages)
                    ):
                        submit_site_page(site=site, page_index=page_index + 1)
                    else:
                        logger.debug(
                            f"{site.get('name')} 字幕第 {search_page} 页返回 {len(result or [])} 条，停止继续翻页"
                        )
                    logger.info(f"站点字幕搜索进度：{finish_count} / {total_num}")
                    progress.update(value=finish_count / total_num * 100,
                                    text=f"正在搜索字幕{keyword or ''}，已完成 {finish_count} / {total_num} 个请求 ...")
        finally:
            for task in pending_tasks:
                if not task.done():
                    task.cancel()
            if pending_tasks:
                await asyncio.gather(*pending_tasks.keys(), return_exceptions=True)

        end_time = datetime.now()
        progress.update(value=100,
                        text=f"站点字幕搜索完成，有效字幕数：{len(results)}，总耗时 {(end_time - start_time).seconds} 秒")
        logger.info(f"站点字幕搜索完成，有效字幕数：{len(results)}，总耗时 {(end_time - start_time).seconds} 秒")
        progress.end()
        return results

    async def __async_search_subtitles_all_sites_stream(self, keyword: str,
                                                        sites: List[int] = None,
                                                        page: Optional[int] = 0) -> AsyncIterator[Dict[str, Any]]:
        """
        异步搜索多个站点的字幕资源，按站点完成顺序渐进式返回结果。
        :param keyword: 搜索关键词
        :param sites: 指定站点ID列表，如有则只搜索指定站点，否则搜索所有站点
        :param page: 搜索页码
        """
        indexer_sites = []

        if not sites:
            sites = SystemConfigOper().get(SystemConfigKey.IndexerSites) or []

        for indexer in await SitesHelper().async_get_indexers():
            if not indexer.get("subtitles"):
                continue
            if not sites or indexer.get("id") in sites:
                indexer_sites.append(indexer)
        if not indexer_sites:
            logger.warn('未开启任何支持字幕搜索的有效站点，无法搜索字幕')
            yield {
                "type": "done",
                "stage": "searching",
                "value": 100,
                "text": "未开启任何支持字幕搜索的有效站点，无法搜索字幕",
                "items": [],
                "finished": 0,
                "total": 0
            }
            return

        progress = ProgressHelper(ProgressKey.Search)
        progress.start()
        start_time = datetime.now()
        search_pages = self._build_search_pages(page)
        total_num = len(indexer_sites) * len(search_pages)
        finish_count = 0
        progress.update(value=0,
                        text=f"开始搜索字幕，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...")
        yield {
            "type": "progress",
            "stage": "searching",
            "value": 0,
            "text": f"开始搜索字幕，共 {len(indexer_sites)} 个站点，{len(search_pages)} 页 ...",
            "items": [],
            "finished": 0,
            "total": total_num
        }

        semaphore = asyncio.Semaphore(settings.CONF.threadpool or total_num)

        async def search_site(site: dict, search_page: int) -> List[SubtitleInfo]:
            """
            搜索单个站点字幕页，用于渐进式返回入口。
            """
            async with semaphore:
                site_result = await self.async_search_subtitles(
                    site=site, keyword=keyword, page=search_page
                )
                return site_result or []

        tasks = {}

        def submit_site_page(site: dict, page_index: int):
            """
            提交渐进式字幕站点页搜索任务，并保留站点和页码上下文。
            """
            search_page = search_pages[page_index]
            task = asyncio.create_task(search_site(site=site, search_page=search_page))
            tasks[task] = (site, page_index, search_page)

        for site in indexer_sites:
            submit_site_page(site=site, page_index=0)

        results_count = 0
        try:
            while tasks:
                if global_vars.is_system_stopped:
                    break
                done_tasks, _ = await asyncio.wait(
                    tasks.keys(),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for future in done_tasks:
                    site, page_index, search_page = tasks.pop(future)
                    finish_count += 1
                    result = await future
                    results_count += len(result)
                    if (
                            self._should_continue_subtitle_search_pages(site=site, page_results=result)
                            and page_index + 1 < len(search_pages)
                    ):
                        submit_site_page(site=site, page_index=page_index + 1)
                    else:
                        logger.debug(
                            f"{site.get('name')} 字幕第 {search_page} 页返回 {len(result)} 条，停止继续翻页"
                        )
                    logger.info(f"站点字幕搜索进度：{finish_count} / {total_num}")
                    progress_value = finish_count / total_num * 100
                    progress_text = f"正在搜索字幕{keyword or ''}，已完成 {finish_count} / {total_num} 个请求 ..."
                    progress.update(value=progress_value, text=progress_text)
                    yield {
                        "type": "append",
                        "stage": "searching",
                        "value": progress_value,
                        "text": progress_text,
                        "items": result,
                        "site": site.get("name"),
                        "site_id": site.get("id"),
                        "page": search_page,
                        "finished": finish_count,
                        "total": total_num,
                        "total_items": results_count
                    }
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks.keys(), return_exceptions=True)

        end_time = datetime.now()
        progress.update(value=100,
                        text=f"站点字幕搜索完成，有效字幕数：{results_count}，总耗时 {(end_time - start_time).seconds} 秒")
        logger.info(f"站点字幕搜索完成，有效字幕数：{results_count}，总耗时 {(end_time - start_time).seconds} 秒")
        progress.end()

    @eventmanager.register(EventType.SiteDeleted)
    def remove_site(self, event: Event):
        """
        从搜索站点中移除与已删除站点相关的设置
        """
        if not event:
            return
        event_data = event.event_data or {}
        site_id = event_data.get("site_id")
        if not site_id:
            return
        if site_id == "*":
            # 清空搜索站点
            SystemConfigOper().set(SystemConfigKey.IndexerSites, [])
            return
        # 从选中的rss站点中移除
        selected_sites = SystemConfigOper().get(SystemConfigKey.IndexerSites) or []
        if site_id in selected_sites:
            selected_sites.remove(site_id)
            SystemConfigOper().set(SystemConfigKey.IndexerSites, selected_sites)
