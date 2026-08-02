import re
import traceback
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from app.chain.transfer import TransferChain
from app.core.cache import TTLCache
from app.core.config import settings
from app.db.transferhistory_oper import TransferHistoryOper
from app.helper.transferhistory import (HistoryGateAction, coerce_size, describe_history_gate,
                                        evaluate_history_gate, history_src_size, is_skip_action,
                                        max_failed_retries, resolve_history)
from app.log import logger
from app.schemas import FileItem


class TransferDispatcher:
    """
    将监控事件分发到整理链：候选判定、TTL 去重、整理历史查重与整理触发。
    """
    # 历史查询失败待重试队列上限，防止长时间故障期间无限增长
    MAX_PENDING_RETRIES = 1000
    # 单个文件的最大重试次数（按健康检查周期计，60 次约 1 小时）
    MAX_RETRY_ATTEMPTS = 60

    def __init__(self, all_exts: Optional[List[str]] = None, cache: Optional[Any] = None):
        """
        初始化整理分发器。
        :param all_exts: 监控的文件扩展名，默认取系统配置
        :param cache: 去重缓存，默认使用 10 秒 TTL 缓存
        """
        self.all_exts = all_exts if all_exts is not None else (
                settings.RMT_MEDIAEXT + settings.RMT_SUBEXT + settings.RMT_AUDIOEXT)
        self._cache = cache if cache is not None else TTLCache(region="monitor", maxsize=1024, ttl=10)
        self._lock = Lock()
        # 历史查询失败待重试的文件
        self._pending_retries: Dict[str, Dict[str, Any]] = {}
        self._pending_guard = Lock()

    @staticmethod
    def _is_bluray_sub(_path: Path) -> bool:
        """
        判断是否蓝光原盘目录内的媒体流文件。
        """
        return True if re.search(r"BDMV[/\\]STREAM", _path.as_posix(), re.IGNORECASE) else False

    @staticmethod
    def _get_bluray_dir(_path: Path) -> Optional[Path]:
        """
        获取蓝光原盘BDMV目录的上级目录。
        """
        for p in _path.parents:
            if p.name == "BDMV":
                return p.parent
        return None

    @staticmethod
    def _has_suffix_in(file_path: Path, extensions: List[str]) -> bool:
        """
        判断路径后缀是否命中给定扩展名列表。
        """
        if not file_path.suffix:
            return False
        return file_path.suffix.casefold() in {ext.casefold() for ext in extensions}

    def is_transfer_candidate_path(self, file_path: Path) -> bool:
        """
        判断监控事件路径是否需要进入整理链。
        """
        if self._has_suffix_in(file_path, settings.DOWNLOAD_TMPEXT):
            return False
        return self._has_suffix_in(file_path, self.all_exts)

    @staticmethod
    def _build_transfer_src_path(event_path: Path, is_bluray_folder: bool) -> str:
        """
        生成整理记录使用的源路径。
        """
        if is_bluray_folder:
            return f"{event_path.as_posix()}/"
        return event_path.as_posix()

    @classmethod
    def _should_skip_by_history(cls, storage: str, src_path: str,
                                file_size: Optional[float] = None) -> Optional[bool]:
        """
        依据整理历史判断本次是否跳过整理。

        判定策略由 app/helper/transferhistory.py 统一提供，整理链的计划整理段使用
        同一套判定，避免此处放行的文件在下游被另一套「存在记录即拦」的策略收回。
        :param storage: 存储
        :param src_path: 整理记录使用的源路径
        :param file_size: 当前文件大小，蓝光目录等场景可能为 None
        :return: True 跳过整理，False 放行整理，None 查询失败
        """
        try:
            history = resolve_history(src_path, storage=storage,
                                      transfer_history_oper=TransferHistoryOper())
        except Exception as err:
            logger.error(f"查询整理历史失败: {src_path} - {err}")
            return None
        action = evaluate_history_gate(history, file_size=file_size)
        if action == HistoryGateAction.PASS_FAILED:
            logger.debug(f"上次整理失败（{describe_history_gate(history)}），"
                         f"本次重新送入整理链: {src_path}")
        elif action == HistoryGateAction.PASS_SIZE_CHANGED:
            logger.info(f"已整理过但文件已变化（{history_src_size(history)} -> "
                        f"{coerce_size(file_size)}），重新送入整理链: {src_path}")
        elif action == HistoryGateAction.SKIP_RETRY_EXHAUSTED:
            # 放弃自动重试意味着该文件需要人介入，不能只留 debug 日志重蹈静默漏件的覆辙
            logger.warn(f"整理连续失败 {max_failed_retries()} 次已达上限，不再自动重试，"
                        f"请手动整理或删除整理记录: {src_path}")
        elif action == HistoryGateAction.SKIP:
            logger.debug(f"已整理过且文件未变化，跳过: {src_path}")
        return is_skip_action(action)

    @staticmethod
    def _pending_key(storage: str, event_path: Path) -> str:
        """
        生成待重试文件的唯一键。
        """
        return f"{storage}:{Path(event_path).as_posix()}"

    def _register_pending(self, storage: str, event_path: Path, file_size: float = None,
                          reason: str = "整理历史查询失败"):
        """
        登记暂时性故障的文件待重试，重复失败累计次数，超限后放弃。
        :param storage: 存储
        :param event_path: 原始事件路径
        :param file_size: 文件大小，None 表示重试时需要重新读取
        :param reason: 登记原因，用于日志
        """
        key = self._pending_key(storage, event_path)
        with self._pending_guard:
            entry = self._pending_retries.get(key)
            if entry:
                entry["attempts"] += 1
                if entry["attempts"] >= self.MAX_RETRY_ATTEMPTS:
                    self._pending_retries.pop(key, None)
                    logger.error(f"{reason}持续失败，已放弃重试: {key}")
                return
            if len(self._pending_retries) >= self.MAX_PENDING_RETRIES:
                logger.error(f"整理重试队列已满，丢弃: {key}")
                return
            self._pending_retries[key] = {
                "storage": storage,
                "event_path": event_path,
                "file_size": file_size,
                "attempts": 1
            }
        logger.warn(f"{reason}，已登记待重试: {key}")

    def register_unreadable(self, storage: str, event_path: Path):
        """
        登记读取失败的监控事件待重试。

        FUSE/网络挂载抖动时 stat 会瞬时失败，直接丢弃事件就是永久漏件，
        因此复用待重试队列，由健康检查周期重新读取。
        :param storage: 存储
        :param event_path: 事件文件路径
        """
        self._register_pending(storage=storage, event_path=event_path,
                               file_size=None, reason="读取监控事件文件失败")

    @staticmethod
    def _resolve_file_size(event_path: Path) -> Tuple[Optional[int], bool]:
        """
        重新读取文件大小。
        :param event_path: 文件路径
        :return: (文件大小, 文件是否仍然存在)；大小为 None 表示本次读取仍然失败
        """
        try:
            return Path(event_path).stat().st_size, True
        except FileNotFoundError:
            return None, False
        except OSError as err:
            logger.debug(f"重试读取文件大小失败: {event_path} - {err}")
            return None, True

    def _discard_pending(self, storage: str, event_path: Path):
        """
        历史查询已得到确定结果，移除待重试登记。
        :param storage: 存储
        :param event_path: 原始事件路径
        """
        with self._pending_guard:
            self._pending_retries.pop(self._pending_key(storage, event_path), None)

    def clear_pending(self):
        """
        清空待重试队列。监控停止或配置重载时调用，避免已移除的监控目录
        在数据库恢复后仍被看门狗送入整理链。
        """
        with self._pending_guard:
            if not self._pending_retries:
                return
            logger.debug(f"清理整理重试队列，丢弃 {len(self._pending_retries)} 个待重试条目")
            self._pending_retries.clear()

    def retry_pending(self):
        """
        重试历史查询失败的文件，由健康检查周期驱动。
        成功或得到确定结果的条目在 handle_file 内部自动移除。
        """
        with self._pending_guard:
            items = list(self._pending_retries.values())
        for item in items:
            storage = item["storage"]
            event_path = item["event_path"]
            file_size = item["file_size"]
            if file_size is None and storage == "local":
                # 因读取失败入队的事件没有大小，重试时必须重新读取
                file_size, exists = self._resolve_file_size(event_path)
                if not exists:
                    logger.debug(f"待重试文件已不存在，放弃: {storage}:{event_path}")
                    self._discard_pending(storage=storage, event_path=event_path)
                    continue
                if file_size is None:
                    # 仍然读不到，累计失败次数后等下个周期，超限由登记逻辑放弃
                    self._register_pending(storage=storage, event_path=event_path,
                                           reason="读取监控事件文件失败")
                    continue
            logger.info(f"重试整理: {storage}:{event_path}")
            self.handle_file(storage=storage, event_path=event_path, file_size=file_size)

    def handle_file(self, storage: str, event_path: Path, file_size: float = None) -> bool:
        """
        整理一个文件。
        :param storage: 存储
        :param event_path: 事件文件路径
        :param file_size: 文件大小
        :return: 是否进入整理链
        """
        with self._lock:
            # 登记重试用原始事件路径，蓝光目录解析在重试时重新执行
            origin_path = event_path
            is_bluray_folder = False
            # 蓝光原盘文件处理
            if self._is_bluray_sub(event_path):
                event_path = self._get_bluray_dir(event_path)
                if not event_path:
                    return False
                is_bluray_folder = True
            elif not self.is_transfer_candidate_path(event_path):
                return False

            # TTL缓存控重
            if self._cache.get(str(event_path)):
                return False
            self._cache[str(event_path)] = True

            src_path = self._build_transfer_src_path(
                event_path=event_path,
                is_bluray_folder=is_bluray_folder,
            )
            skip_by_history = self._should_skip_by_history(
                storage=storage,
                src_path=src_path,
                file_size=file_size,
            )
            if skip_by_history is None:
                # 查询失败是暂时故障，登记待重试（由健康检查周期驱动），不能永久跳过
                self._register_pending(storage=storage, event_path=origin_path, file_size=file_size)
                return False
            if skip_by_history:
                self._discard_pending(storage=storage, event_path=origin_path)
                return False

            try:
                if is_bluray_folder:
                    logger.info(f"开始整理蓝光原盘: {event_path}")
                else:
                    logger.info(f"开始整理文件: {event_path}")
                # 开始整理
                TransferChain().do_transfer(
                    fileitem=FileItem(
                        storage=storage,
                        path=src_path,
                        type="file" if not is_bluray_folder else "dir",
                        name=event_path.name,
                        basename=event_path.stem,
                        extension=event_path.suffix[1:],
                        size=file_size
                    )
                )
                # 整理已执行完毕，此前因暂时性故障登记的重试条目到此作废
                self._discard_pending(storage=storage, event_path=origin_path)
                return True
            except Exception as e:
                logger.error("目录监控整理文件发生错误：%s - %s" % (str(e), traceback.format_exc()))
                # 去重缓存在入口已写入，整理抛异常时必须失效，否则 TTL 窗口内该文件的
                # 后续事件会被静默吞掉，等于一次异常就丢一个文件
                self._invalidate_cache(str(event_path))
                # 已稳定落地的文件不会再产生任何事件，批量整理期间撞上一次 DB/网络瞬断
                # 就是永久丢件，因此与历史查询失败同样登记待重试；登记用原始事件路径，
                # 重试时重新解析蓝光目录并重走完整流程。异常未清空登记，重试次数会持续
                # 累计，达到上限后由 _register_pending 放弃，不会无限重试
                self._register_pending(storage=storage, event_path=origin_path,
                                       file_size=file_size, reason="整理执行异常")
                return False

    def _invalidate_cache(self, key: str):
        """
        使去重缓存条目失效，兼容缓存后端与测试注入的字典。
        :param key: 缓存键
        """
        try:
            delete = getattr(self._cache, "delete", None)
            if callable(delete):
                delete(key)
                return
            self._cache.pop(key, None)
        except Exception as err:
            logger.debug(f"清理监控去重缓存失败: {key} - {err}")
