import re
from typing import List, Optional, Dict, Any
import asyncio
import hashlib
import json

from app.chain import ChainBase
from app.core.config import settings
from app.log import logger
from app.utils.common import log_execution_time
from app.utils.singleton import Singleton
from app.utils.string import StringUtils


class AIRecommendChain(ChainBase, metaclass=Singleton):
    """
    AI推荐处理链，单例运行
    用于基于搜索结果的AI智能推荐
    """

    # 缓存文件名
    __ai_indices_cache_file = "__ai_recommend_indices__"

    # AI推荐状态
    _ai_recommend_running = False
    _ai_recommend_task: Optional[asyncio.Task] = None
    _current_request_hash: Optional[str] = None  # 当前请求的哈希值
    _ai_recommend_result: Optional[List[int]] = None  # AI推荐索引缓存（索引列表）
    _ai_recommend_error: Optional[str] = None  # AI推荐错误信息

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
        :return: 状态字典
        """
        if not self.is_enabled:
            return {"status": "disabled"}

        if self._ai_recommend_running:
            return {"status": "running"}

        # 尝试从数据库加载缓存
        if self._ai_recommend_result is None:
            cached_indices = self.load_cache(self.__ai_indices_cache_file)
            if cached_indices is not None:
                self._ai_recommend_result = cached_indices

        # 只要有结果，始终返回completed状态和数据
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
        # 计算当前请求的hash
        request_hash = self._calculate_request_hash(
            filtered_indices, search_results_count
        )

        # 检查请求是否变化
        is_same_request = request_hash == self._current_request_hash

        # 如果请求变化了（筛选条件改变），返回idle状态
        if not is_same_request:
            return {"status": "idle"} if self.is_enabled else {"status": "disabled"}

        # 请求未变化，返回当前实际状态
        return self._build_status()

    @log_execution_time(logger=logger)
    async def async_ai_recommend(self, items: List[str], preference: str = None) -> str:
        """
        AI推荐
        :param items: 候选资源列表(JSON字符串格式)
        :param preference: 用户偏好(可选)
        :return: AI返回的推荐结果
        """
        # 设置运行状态
        self._ai_recommend_running = True
        try:
            # 导入LLMHelper
            from app.helper.llm import LLMHelper

            # 获取LLM实例
            llm = LLMHelper.get_llm()

            # 构建提示词
            user_preference = (
                preference
                or settings.AI_RECOMMEND_USER_PREFERENCE
                or "Prefer high-quality resources with more seeders"
            )

            # 添加指令
            instruction = """
Task: Select the best matching items from the list based on user preferences.

Each item contains:
- index: Item number
- title: Full torrent title
- size: File size
- seeders: Number of seeders

Output Format: Return ONLY a JSON array of "index" numbers (e.g., [0, 3, 1]). Do NOT include any explanations or other text.
"""
            message = (
                f"User Preference: {user_preference}\n{instruction}\nCandidate Resources:\n"
                + "\n".join(items)
            )

            # 调用LLM
            response = await llm.ainvoke(message)
            return response.content

        except ValueError as e:
            logger.error(f"AI推荐配置错误: {e}")
            raise
        except Exception as e:
            raise
        finally:
            # 清除运行状态
            self._ai_recommend_running = False
            self._ai_recommend_task = None

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
        :param filtered_indices: 筛选后的索引列表
        :param search_results_count: 搜索结果总数
        :param results: 搜索结果列表
        """
        # 防护检查：确保AI推荐功能已启用
        if not self.is_enabled:
            logger.warning("AI推荐功能未启用，跳过任务执行")
            return

        # 计算新请求的哈希值
        new_request_hash = self._calculate_request_hash(
            filtered_indices, search_results_count
        )

        # 如果请求变化了，取消旧任务
        if new_request_hash != self._current_request_hash:
            self.cancel_ai_recommend()

            # 更新请求哈希值
            self._current_request_hash = new_request_hash

            # 重置状态
            self._ai_recommend_result = None
            self._ai_recommend_error = None

            # 启动新任务
            async def run_recommend():
                # 获取当前任务对象，用于在finally中比对
                current_task = asyncio.current_task()
                try:
                    self._ai_recommend_running = True

                    # 准备数据
                    items = []
                    valid_indices = []
                    max_items = settings.AI_RECOMMEND_MAX_ITEMS or 50

                    # 如果提供了筛选索引，先筛选结果；否则使用所有结果
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

                    # 调用AI推荐
                    ai_response = await self.async_ai_recommend(items)

                    # 解析AI返回的索引
                    try:
                        # 使用正则提取JSON数组（非贪婪模式，避免匹配多个数组）
                        json_match = re.search(r'\[.*?\]', ai_response, re.DOTALL)
                        if not json_match:
                            raise ValueError(ai_response)
                            
                        ai_indices = json.loads(json_match.group())
                        if not isinstance(ai_indices, list):
                            raise ValueError(f"AI返回格式错误: {ai_response}")

                        # 映射回原始索引
                        if filtered_indices:
                            original_indices = [
                                filtered_indices[valid_indices[i]]
                                for i in ai_indices
                                if i < len(valid_indices)
                                and 0 <= filtered_indices[valid_indices[i]] < len(results)
                            ]
                        else:
                            original_indices = [
                                valid_indices[i]
                                for i in ai_indices
                                if i < len(valid_indices)
                                and 0 <= valid_indices[i] < len(results)
                            ]

                        # 只返回索引列表，不返回完整数据
                        self._ai_recommend_result = original_indices

                        # 保存到数据库
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
                    # 只有当 self._ai_recommend_task 仍然是当前任务时，才清理状态
                    # 如果任务被取消并启动了新任务，self._ai_recommend_task 已经指向新任务，不应重置
                    if self._ai_recommend_task == current_task:
                        self._ai_recommend_running = False
                        self._ai_recommend_task = None

            # 创建并启动任务
            self._ai_recommend_task = asyncio.create_task(run_recommend())
