import asyncio
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from app.agent import agent_manager, prompt_manager
from app.chain import ChainBase
from app.core.config import settings
from app.log import logger
from app.utils.singleton import Singleton
from app.utils.string import StringUtils


class AIRecommendChain(ChainBase, metaclass=Singleton):
    """
    AI推荐处理链，单例运行
    用于基于搜索结果的AI智能推荐
    使用 agent_manager.run_background_prompt 统一后台任务机制
    """

    __ai_indices_cache_file = "__ai_recommend_indices__"

    _ai_recommend_running = False
    _ai_recommend_task: Optional[asyncio.Task] = None
    _current_request_hash: Optional[str] = None
    _ai_recommend_result: Optional[List[int]] = None
    _ai_recommend_error: Optional[str] = None

    @staticmethod
    def _calculate_request_hash(
        filtered_indices: Optional[List[int]], search_results_count: int
    ) -> str:
        """
        计算请求的哈希值，用于判断请求是否变化
        """
        request_data = {
            "filtered_indices": filtered_indices or [],
            "search_results_count": search_results_count,
        }
        return hashlib.md5(
            json.dumps(request_data, sort_keys=True).encode()
        ).hexdigest()

    @property
    def is_enabled(self) -> bool:
        """
        检查AI推荐功能是否已启用。
        """
        return settings.AI_AGENT_ENABLE and settings.AI_RECOMMEND_ENABLED

    def _build_status(self) -> Dict[str, Any]:
        """
        构建AI推荐状态字典
        """
        if not self.is_enabled:
            return {"status": "disabled"}

        if self._ai_recommend_running:
            return {"status": "running"}

        if self._ai_recommend_result is None:
            cached_indices = self.load_cache(self.__ai_indices_cache_file)
            if cached_indices is not None:
                self._ai_recommend_result = cached_indices

        if self._ai_recommend_result is not None:
            return {"status": "completed", "results": self._ai_recommend_result}

        if self._ai_recommend_error is not None:
            return {"status": "error", "error": self._ai_recommend_error}

        return {"status": "idle"}

    def get_current_status_only(self) -> Dict[str, Any]:
        """
        获取当前状态（不校验hash，用于check_only模式）
        """
        return self._build_status()

    def get_status(
        self, filtered_indices: Optional[List[int]], search_results_count: int
    ) -> Dict[str, Any]:
        """
        获取AI推荐状态并检查请求是否变化（用于首次请求或force模式）
        如果请求变化（筛选条件变化），返回idle状态
        """
        request_hash = self._calculate_request_hash(
            filtered_indices, search_results_count
        )
        is_same_request = request_hash == self._current_request_hash

        if not is_same_request:
            return {"status": "idle"} if self.is_enabled else {"status": "disabled"}

        return self._build_status()

    def is_ai_recommend_running(self) -> bool:
        """
        检查AI推荐是否正在运行
        """
        return self._ai_recommend_running

    def cancel_ai_recommend(self):
        """
        取消正在运行的AI推荐任务
        """
        if self._ai_recommend_task and not self._ai_recommend_task.done():
            self._ai_recommend_task.cancel()
        self._ai_recommend_running = False
        self._ai_recommend_task = None
        self._current_request_hash = None
        self._ai_recommend_result = None
        self._ai_recommend_error = None
        self.remove_cache(self.__ai_indices_cache_file)

    def start_recommend_task(
        self,
        filtered_indices: Optional[List[int]],
        search_results_count: int,
        results: List[Any],
    ) -> None:
        """
        启动AI推荐任务
        使用 agent_manager.run_background_prompt 后台Agent机制执行推荐
        :param filtered_indices: 筛选后的索引列表
        :param search_results_count: 搜索结果总数
        :param results: 搜索结果列表
        """
        if not self.is_enabled:
            logger.warning("AI推荐功能未启用，跳过任务执行")
            return

        new_request_hash = self._calculate_request_hash(
            filtered_indices, search_results_count
        )

        if new_request_hash != self._current_request_hash:
            self.cancel_ai_recommend()
            self._current_request_hash = new_request_hash
            self._ai_recommend_result = None
            self._ai_recommend_error = None

            async def run_recommend():
                current_task = asyncio.current_task()
                try:
                    self._ai_recommend_running = True

                    items = []
                    valid_indices = []
                    max_items = settings.AI_RECOMMEND_MAX_ITEMS or 50

                    if filtered_indices is not None and len(filtered_indices) > 0:
                        results_to_process = [
                            results[i]
                            for i in filtered_indices
                            if 0 <= i < len(results)
                        ]
                    else:
                        results_to_process = results

                    for i, torrent in enumerate(results_to_process):
                        if len(items) >= max_items:
                            break

                        if not torrent.torrent_info:
                            continue

                        valid_indices.append(i)

                        item_info = {
                            "index": i,
                            "title": torrent.torrent_info.title or "未知",
                            "size": (
                                StringUtils.format_size(torrent.torrent_info.size)
                                if torrent.torrent_info.size
                                else "0 B"
                            ),
                            "seeders": torrent.torrent_info.seeders or 0,
                        }

                        items.append(json.dumps(item_info, ensure_ascii=False))

                    if not items:
                        self._ai_recommend_error = "没有可用于AI推荐的资源"
                        return

                    user_preference = (
                        settings.AI_RECOMMEND_USER_PREFERENCE
                        or "Prefer high-quality resources with more seeders"
                    )

                    search_results_text = "User Preference: {preference}\n\nCandidate Resources:\n{items}".format(
                        preference=user_preference, items="\n".join(items)
                    )

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
                        suppress_user_reply=True,
                    )

                    ai_response = full_output[0]
                    if not ai_response:
                        self._ai_recommend_error = "AI推荐未返回结果"
                        return

                    try:
                        json_match = re.search(r"\[.*?]", ai_response, re.DOTALL)
                        if not json_match:
                            raise ValueError(f"无法从响应中提取JSON数组: {ai_response}")

                        ai_indices = json.loads(json_match.group())
                        if not isinstance(ai_indices, list):
                            raise ValueError(f"AI返回格式错误: {ai_response}")

                        if filtered_indices:
                            original_indices = [
                                filtered_indices[valid_indices[i]]
                                for i in ai_indices
                                if i < len(valid_indices)
                                and 0
                                <= filtered_indices[valid_indices[i]]
                                < len(results)
                            ]
                        else:
                            original_indices = [
                                valid_indices[i]
                                for i in ai_indices
                                if i < len(valid_indices)
                                and 0 <= valid_indices[i] < len(results)
                            ]

                        self._ai_recommend_result = original_indices
                        self.save_cache(original_indices, self.__ai_indices_cache_file)
                        logger.info(f"AI推荐完成: {len(original_indices)}项")

                    except Exception as e:
                        logger.error(
                            f"解析AI返回结果失败: {e}, 原始响应: {ai_response}"
                        )
                        self._ai_recommend_error = str(e)

                except asyncio.CancelledError:
                    logger.info("AI推荐任务被取消")
                except Exception as e:
                    logger.error(f"AI推荐任务失败: {e}")
                    self._ai_recommend_error = str(e)
                finally:
                    if self._ai_recommend_task == current_task:
                        self._ai_recommend_running = False
                        self._ai_recommend_task = None

            self._ai_recommend_task = asyncio.create_task(run_recommend())
