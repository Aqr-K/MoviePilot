# -*- coding: utf-8 -*-
"""
模块契约校验家族（从 ModuleManager 抽出为独立模块）。

与 manager/loader 解耦：仅依赖标准库 inspect 与 ModuleType 枚举，_ModuleBase 走 lazy import 防环。
verify_module_contract 为 _ModuleBase 基类契约的核心判定；各域 verify_*_contract 在其上叠加
get_type 与核心方法要求，共用 _verify_typed_contract。ModuleManager 仍以静态方法别名再导出全部函数，
故 ModuleManager.verify_*_contract 调用方零改动。
"""
import inspect
from typing import List, Tuple

from app.schemas.types import ModuleType


def verify_module_contract(module_cls: type) -> Tuple[bool, List[str]]:
    """
    校验外部模块类是否满足 _ModuleBase 基类契约，作为「验证注册」的核心判定。

    宽松策略（缺注解/不可内省时降级跳过、不抛异常），返回 (是否通过, 失败原因列表)。
    供 register_module 把旧「注入」式注册升级为「验证后注册」——不通过仅作废弃提醒、
    不强制拒绝，保证零插件破坏。
    """
    if not isinstance(module_cls, type):
        return False, ["不是类对象"]
    reasons: List[str] = []
    # 1) 应继承 _ModuleBase（真模块 vs 任意注入类的核心区分）；lazy import 避免 import-time 环
    try:
        from app.modules import _ModuleBase
        if not issubclass(module_cls, _ModuleBase):
            reasons.append("未继承 app.modules._ModuleBase")
    except ImportError:
        pass  # app.modules 依赖未就绪时仅降级跳过该项；其它异常照常上报
    # 2) 抽象方法须全部落地，否则不可实例化
    abstracts = getattr(module_cls, "__abstractmethods__", frozenset())
    if abstracts:
        reasons.append(f"抽象方法未实现：{sorted(abstracts)}")
    # 3) 契约方法存在且可调用 + 签名宽松兼容（生命周期/声明方法不应要求额外必填位置参）
    for _name in ("init_module", "init_setting", "stop", "test", "get_type", "get_subtype"):
        _fn = getattr(module_cls, _name, None)
        if not callable(_fn):
            reasons.append(f"缺少契约方法：{_name}")
            continue
        try:
            _extra = [
                p.name for p in inspect.signature(_fn).parameters.values()
                if p.name not in ("self", "cls")
                and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
                and p.default is p.empty
            ]
            if _extra:
                reasons.append(f"{_name} 签名不兼容：要求额外必填参 {_extra}")
        except (ValueError, TypeError):
            pass  # 无法内省 → 降级跳过
    return (not reasons), reasons


def _verify_typed_contract(module_cls: type, expected_type: ModuleType,
                           required_methods: Tuple[str, ...] = (),
                           method_label: str = "") -> Tuple[bool, List[str]]:
    """
    域契约通用校验（各 verify_*_contract 的共用实现）：在 _ModuleBase 基类契约之上，要求
    get_type()==expected_type，并要求 required_methods 全部可调用。能力方法按需实现的域
    传空 required_methods 即可。返回 (是否通过, 失败原因列表)。
    """
    ok, reasons = verify_module_contract(module_cls)
    reasons = list(reasons)
    _get_type = getattr(module_cls, "get_type", None)
    if not callable(_get_type):
        reasons.append("缺少 get_type")
    else:
        try:
            if _get_type() != expected_type:
                reasons.append(f"get_type 须为 {expected_type}（实际 {_get_type()}）")
        except Exception as err:
            reasons.append(f"get_type 调用失败：{err}")
    for _name in required_methods:
        if not callable(getattr(module_cls, _name, None)):
            reasons.append(f"缺少{method_label}方法：{_name}")
    return (not reasons), reasons


def verify_data_source_contract(module_cls: type) -> Tuple[bool, List[str]]:
    """
    校验数据源（媒体识别/信息源，MediaRecognize 域）契约：基类契约 + get_type==MediaRecognize。
    识别能力方法（recognize_media/search_medias/obtain_images 等）按方法名分发、按需实现，
    故不强制（避免误拒 thetvdb 这类仅实现部分/其它方法的真实源）。
    """
    return _verify_typed_contract(module_cls, ModuleType.MediaRecognize)


def verify_downloader_contract(module_cls: type) -> Tuple[bool, List[str]]:
    """
    校验下载器（Downloader 域）契约：基类契约 + get_type==Downloader + 核心操作
    download/list_torrents/remove_torrents。完整 IDownloader 面（start/stop/torrent_files 等）
    按方法名分发、按需实现。供 provides_downloaders() 注册前严格校验。
    """
    return _verify_typed_contract(
        module_cls, ModuleType.Downloader,
        ("download", "list_torrents", "remove_torrents"), "下载器")


def verify_notification_contract(module_cls: type) -> Tuple[bool, List[str]]:
    """
    校验消息渠道（Notification 域）契约：基类契约 + get_type==Notification + 核心方法 post_message。
    其余消息能力方法（post_medias/post_torrents/delete_message 等）按方法名分发、按需实现。
    供 provides_notifications() 注册前严格校验。
    """
    return _verify_typed_contract(
        module_cls, ModuleType.Notification, ("post_message",), "消息渠道")


def verify_mediaserver_contract(module_cls: type) -> Tuple[bool, List[str]]:
    """
    校验媒体服务器（MediaServer 域）契约：基类契约 + get_type==MediaServer。能力方法
    （mediaserver_librarys/media_statistic 等）各后端实现子集不同，按方法名分发、按需实现，
    故不强制。供 provides_mediaservers() 注册前严格校验。
    """
    return _verify_typed_contract(module_cls, ModuleType.MediaServer)
