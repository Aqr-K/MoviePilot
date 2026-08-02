from typing import Any, Optional

from app.core.cache import TTLCache
from app.core.config import settings
from app.db.models.transferhistory import TransferHistory
from app.db.transferhistory_oper import TransferHistoryOper
from app.log import logger

# 失败重试次数的合法区间。下界为 1：一次瞬时故障（网络抖动、TMDB 瞬断、移动失败）
# 不该让文件永久漏整理，所以不允许关闭重试；上界为 10：永远识别不出的文件重试再多
# 也不会成功，只会重复推送失败通知，批量导入场景下会刷屏，所以不允许无限重试
MIN_FAILED_RETRIES = 1
MAX_FAILED_RETRIES = 10

# 同一源路径的连续整理失败次数。整理链在写失败历史时累计、整理成功或删除历史时清零，
# 查重闸只读不写，避免监控层与整理链对同一个事件重复计数。
# 计数是进程缓存态：过期或重启后归零，重启往往正是为了修复导致失败的问题，再试一轮是期望行为
FAILED_RETRY_TTL = 24 * 3600
_failed_retry_counts = TTLCache(region="transfer_failed_retry", maxsize=5000, ttl=FAILED_RETRY_TTL)


class HistoryGateAction:
    """
    整理历史查重闸的判定结果。

    监控分发（app/monitor/dispatcher.py）与整理链计划整理段（app/chain/transfer.py）
    共用本模块，避免两处各写一套去重策略后互相对冲：上游放行的文件被下游按
    「存在记录即拦」全额收回，等于放行逻辑完全失效。
    """
    # 没有整理记录
    PASS_NO_RECORD = "pass_no_record"
    # 上次整理失败且重试次数未用尽，放行重试
    PASS_FAILED = "pass_failed"
    # 已整理成功但源文件已变化，放行交由 overwrite_mode 决断
    PASS_SIZE_CHANGED = "pass_size_changed"
    # 上次整理失败且重试次数已用尽，跳过
    SKIP_RETRY_EXHAUSTED = "skip_retry_exhausted"
    # 已整理成功且源文件未变化，跳过
    SKIP = "skip"


def is_skip_action(action: str) -> bool:
    """
    判断查重闸判定是否为跳过整理。
    :param action: HistoryGateAction 之一
    :return: True 表示跳过
    """
    return action in (HistoryGateAction.SKIP, HistoryGateAction.SKIP_RETRY_EXHAUSTED)


def max_failed_retries() -> int:
    """
    读取失败重试上限并钳制到合法区间。

    配置为负数、0 或超过上界时都会被钳制并记录 warn：关闭重试会让瞬时故障造成
    永久漏件，无限重试会让永久失败的文件反复刷通知，两端都不接受。
    :return: 合法的最大重试次数
    """
    raw = settings.TRANSFER_MAX_FAILED_RETRIES
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warn(f"TRANSFER_MAX_FAILED_RETRIES 配置非法（{raw!r}），"
                    f"已回退为 {MIN_FAILED_RETRIES}")
        return MIN_FAILED_RETRIES
    if value < MIN_FAILED_RETRIES:
        logger.warn(f"TRANSFER_MAX_FAILED_RETRIES 不能小于 {MIN_FAILED_RETRIES}"
                    f"（当前 {value}），已按 {MIN_FAILED_RETRIES} 处理")
        return MIN_FAILED_RETRIES
    if value > MAX_FAILED_RETRIES:
        logger.warn(f"TRANSFER_MAX_FAILED_RETRIES 不能大于 {MAX_FAILED_RETRIES}"
                    f"（当前 {value}），已按 {MAX_FAILED_RETRIES} 处理")
        return MAX_FAILED_RETRIES
    return value


def failed_retry_key(src_path: Optional[str], storage: Optional[str] = None) -> Optional[str]:
    """
    生成失败重试计数的缓存键。
    :param src_path: 整理记录使用的源路径
    :param storage: 源存储
    :return: 缓存键，源路径为空时返回 None
    """
    if not src_path:
        return None
    return f"{storage or 'local'}:{src_path}"


def failed_retry_count(src_path: Optional[str], storage: Optional[str] = None) -> int:
    """
    读取同一源路径已累计的连续整理失败次数。
    :param src_path: 整理记录使用的源路径
    :param storage: 源存储
    :return: 已失败次数，无记录时为 0
    """
    key = failed_retry_key(src_path, storage)
    if not key:
        return 0
    return _failed_retry_counts.get(key) or 0


def record_transfer_failure(src_path: Optional[str], storage: Optional[str] = None) -> int:
    """
    累计一次整理失败。
    :param src_path: 整理记录使用的源路径
    :param storage: 源存储
    :return: 累计后的失败次数
    """
    key = failed_retry_key(src_path, storage)
    if not key:
        return 0
    count = (_failed_retry_counts.get(key) or 0) + 1
    _failed_retry_counts[key] = count
    return count


def clear_transfer_failures(src_path: Optional[str], storage: Optional[str] = None) -> None:
    """
    清空同一源路径的失败计数。整理成功、或用户删除整理记录（显式要求重来）时调用。
    :param src_path: 整理记录使用的源路径
    :param storage: 源存储
    """
    key = failed_retry_key(src_path, storage)
    if key:
        # 缺省值必须是 0 而不是 None：CacheBackend.pop 把「default 为 None」当成「未提供
        # default」，键不存在时会抛 KeyError。整理成功路径上绝大多数文件从未失败过，
        # 传 None 会让每一次首次成功整理都炸掉成功回调
        _failed_retry_counts.pop(key, 0)


def coerce_size(size: Any) -> Optional[int]:
    """
    统一转换文件大小，无法转换时返回 None（视为不可比对）。
    :param size: 原始大小值
    :return: 文件大小
    """
    if size is None:
        return None
    try:
        return int(size)
    except (TypeError, ValueError):
        return None


def history_src_size(history: TransferHistory) -> Optional[int]:
    """
    读取整理记录中的源文件大小。
    src_fileitem 是 JSON 列，历史数据可能为空、缺 size 键甚至不是字典，
    取不到时统一返回 None 交由调用方保守处理。
    :param history: 整理记录
    :return: 源文件大小，取不到时为 None
    """
    src_fileitem = getattr(history, "src_fileitem", None)
    if not isinstance(src_fileitem, dict):
        return None
    return coerce_size(src_fileitem.get("size"))


def resolve_history(src_path: str, storage: Optional[str] = None,
                    transfer_history_oper: Optional[TransferHistoryOper] = None
                    ) -> Optional[TransferHistory]:
    """
    查询源路径对应的整理记录。

    get_by_src 没有排序，同一源路径同时存在成功与失败记录时返回哪条不确定，
    拿到失败记录后再确认一次有无成功记录，避免把已整理成功的文件重复整理。
    查询异常不在此处吞掉，由调用方按各自的重试策略处理。
    :param src_path: 整理记录使用的源路径
    :param storage: 存储
    :param transfer_history_oper: 复用的历史操作对象，未传时新建
    :return: 命中的整理记录，未命中时为 None
    """
    oper = transfer_history_oper or TransferHistoryOper()
    history = oper.get_by_src(src_path, storage=storage)
    if history is not None and not history.status:
        history = oper.get_success_by_src(src_path, storage=storage) or history
    return history


def evaluate_history_gate(history: Optional[TransferHistory],
                          file_size: Optional[float] = None,
                          retry_count: Optional[int] = None) -> str:
    """
    依据整理历史判断本次是否跳过整理。

    成功记录不能简单地「存在即跳过」：同路径重新上传的新版本会因此没有机会走到
    整理链的 overwrite_mode 判定，升级永远无法入库，故源文件大小变化时一律放行。
    失败记录按有界重试处理：未达上限放行重试，让瞬时故障（网络/识别/移动）自愈；
    达到上限后跳过，避免永久失败的文件反复刷失败通知。
    :param history: 整理记录，未命中时为 None
    :param file_size: 当前文件大小，蓝光目录等场景可能为 None
    :param retry_count: 已累计的失败次数，None 表示按记录源路径实时查询
    :return: HistoryGateAction 之一
    """
    if history is None:
        return HistoryGateAction.PASS_NO_RECORD
    if not history.status:
        if retry_count is None:
            retry_count = failed_retry_count(
                getattr(history, "src", None),
                getattr(history, "src_storage", None),
            )
        if retry_count >= max_failed_retries():
            return HistoryGateAction.SKIP_RETRY_EXHAUSTED
        # 监控事件是稀疏驱动的（落地事件/延迟重扫/补偿扫描），入口还有 TTL 去重兜底，
        # 配合失败次数上限，重试频率与总量都可控
        return HistoryGateAction.PASS_FAILED
    recorded_size = history_src_size(history)
    current_size = coerce_size(file_size)
    if recorded_size is not None and current_size is not None and current_size != recorded_size:
        # 同路径换成了另一个版本（如升级为更高码率），是否覆盖交给整理链的
        # overwrite_mode 决断，查重闸不做替代判断
        return HistoryGateAction.PASS_SIZE_CHANGED
    # 无法比对大小（蓝光目录、历史记录缺 size）时保守跳过，避免重复整理
    return HistoryGateAction.SKIP


def describe_history_gate(history: Optional[TransferHistory],
                          file_size: Optional[float] = None) -> str:
    """
    生成查重闸判定的可读说明，供日志定位「到底是哪条记录在拦」。
    :param history: 整理记录
    :param file_size: 当前文件大小
    :return: 说明文本
    """
    if history is None:
        return "无整理记录"
    if not history.status:
        count = failed_retry_count(
            getattr(history, "src", None),
            getattr(history, "src_storage", None),
        )
        return f"失败记录 #{history.id}，已重试 {count}/{max_failed_retries()} 次"
    recorded_size = history_src_size(history)
    current_size = coerce_size(file_size)
    if recorded_size is None and current_size is None:
        return f"成功记录 #{history.id}，大小不可比对"
    return f"成功记录 #{history.id}，大小 {recorded_size} -> {current_size}"
