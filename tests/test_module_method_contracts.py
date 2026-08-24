"""模块字符串方法契约清单的架构测试。"""

import json
from pathlib import Path

from app.runtime.extensions.contract.module_method import (
    ModuleErrorPolicy,
    ModuleExecutionMode,
    ModuleResultAggregation,
    ModuleResultShape,
    diagnose_module_callable,
    diagnose_module_result,
    get_module_method_contract,
    get_multi_source_contract,
    is_explicit_module_method,
    list_explicit_module_contracts,
)


RUNTIME_BASELINE = (
    Path(__file__).parent / "fixtures" / "architecture" / "runtime-contract-baseline.json"
)

# 图片获取是累积管道：Fanart、TheMovieDb、Douban 按优先级依次在同一个产出上继续富化。
_PIPELINE_METHODS = frozenset({"obtain_images", "async_obtain_images"})


def test_host_no_longer_dispatches_through_aggregation() -> None:
    """宿主的四个显式分发原语覆盖全部语义，聚合分发只服务插件生态。

    聚合分发用一套歧义协议兼顾通知、收集、仲裁与管道四种需求，调用方无法表达意图。
    宿主一旦出现新的聚合调用，快照即记录在案，此处随之变红。
    """
    payload = json.loads(RUNTIME_BASELINE.read_text(encoding="utf-8"))

    assert payload["run_module"]["methods"] == {}


def test_pipeline_methods_declare_pipeline_aggregation() -> None:
    """累积管道方法必须声明管道语义，不能退回未分类聚合。"""
    for method in _PIPELINE_METHODS:
        contract = get_module_method_contract(method)
        assert contract.aggregation is ModuleResultAggregation.PIPELINE


def test_high_frequency_capability_families_are_explicit() -> None:
    """媒体发现、识别、存储和消息族不能退回未分类 legacy 契约。"""
    expected_families = {
        "match_media": "media-metadata",
        "media_detail": "media-metadata",
        "discover": "media-discovery",
        "recognize_media": "media-recognition",
        "media_exists": "media-library",
        "mediaserver_items": "media-server",
        "list_files": "storage",
        "finalize_message": "messaging",
        "scheduler_job": "scheduling",
        "torrent_files": "downloader",
    }

    for method, family in expected_families.items():
        assert is_explicit_module_method(method)
        assert get_module_method_contract(method).family == family


def test_source_prefixed_methods_no_longer_declare_a_dedicated_family() -> None:
    """六个多来源能力契约把数据源降为参数后，源前缀方法名退回未分类 legacy 契约。"""
    for method in (
        "tmdb_collection",
        "async_tmdb_episodes",
        "douban_info",
        "bangumi_info",
        "anilist_info",
        "tvdb_slug",
    ):
        assert not is_explicit_module_method(method)
        assert get_module_method_contract(method).family == "legacy"


def test_media_exists_declares_its_multi_source_protocol() -> None:
    """多来源存量判定的让出方式、收窄开关与取用规则必须成文可查。"""
    contract = get_multi_source_contract("media_exists")

    assert contract is not None
    assert len(contract.sources) == 2
    assert "None" in contract.abstain
    assert dict(contract.narrowing).keys() == {"server", "itemid", "LOCAL_EXISTS_SEARCH"}
    assert "并集" in contract.arbitration


def test_single_source_method_declares_no_multi_source_protocol() -> None:
    """单一来源能力不登记多来源协议。"""
    assert get_multi_source_contract("mediaserver_items") is None


def test_unknown_plugin_method_keeps_legacy_compatibility() -> None:
    """第三方插件自定义方法仍应落入开放的 legacy 调度协议。"""
    contract = get_module_method_contract("third_party_custom_method")

    assert contract.family == "legacy"
    assert contract.supports_sync is True
    assert contract.supports_async is True


def test_contract_v2_freezes_every_observed_host_method() -> None:
    """全部已观察宿主能力必须具备可生成文档和诊断的完整 V2 字段。"""
    contracts = list_explicit_module_contracts()

    assert len(contracts) >= 211
    for contract in contracts.values():
        assert contract.version == 1
        assert contract.input_contract != "legacy_args"
        assert contract.result_contract
        assert contract.execution is ModuleExecutionMode.SYNC_OR_ASYNC
        assert contract.timeout_policy == "caller_budget"
        assert contract.error_policy is ModuleErrorPolicy.ISOLATE_PROVIDER
        assert contract.public_to_plugins is True


def test_signature_diagnostics_do_not_reject_legacy_callable() -> None:
    """无法检查的旧插件 callable 只产生诊断，仍由 dispatcher 决定是否执行。"""
    class _OpaqueCallable:
        """模拟 inspect 无法解析签名的第三方 callable。"""

        @property
        def __signature__(self):
            """模拟扩展对象不提供 Python signature。"""
            raise ValueError("opaque")

        def __call__(self):
            """保留可调用行为。"""
            return "ok"

    assert diagnose_module_callable("recognize_media", _OpaqueCallable()) == (
        "signature-unavailable",
    )
    assert _OpaqueCallable()() == "ok"


def test_signature_diagnostics_report_missing_contract_parameters() -> None:
    """显式 Contract 应能指出 provider 遗漏的宿主调用参数。"""
    def incomplete_storage_provider(fileitem):
        """模拟仍未接受 recursion 参数的旧存储 provider。"""
        return [fileitem]

    assert diagnose_module_callable(
        "list_files", incomplete_storage_provider
    ) == ("missing-parameter:recursion",)


def test_signature_diagnostics_accept_keyword_compatibility_provider() -> None:
    """带 **kwargs 的第三方 provider 继续兼容逐步扩展的输入契约。"""
    def compatible_provider(**kwargs):
        """模拟通过关键字参数保持前向兼容的第三方 provider。"""
        return kwargs

    assert diagnose_module_callable("snapshot_storage", compatible_provider) == ()


def test_result_diagnostics_check_only_enabled_basic_shapes() -> None:
    """高频方法检查基础结果形状，业务对象合同仍留给逐族适配器。"""
    assert get_module_method_contract("list_files").result_shape is ModuleResultShape.LIST
    assert diagnose_module_result("list_files", [object()]) == ()
    assert diagnose_module_result("list_files", None) == ()
    assert diagnose_module_result("list_files", "legacy-value") == (
        "unexpected-result:list:str",
    )
    assert diagnose_module_result("mediaserver_play_url", "https://example.test") == ()
    assert diagnose_module_result("mediaserver_play_url", 7) == (
        "unexpected-result:string:int",
    )


def test_unknown_plugin_result_keeps_unchecked_legacy_compatibility() -> None:
    """未知第三方方法的任意返回值继续不做结果形状诊断。"""
    assert diagnose_module_result("third_party_custom_method", object()) == ()
