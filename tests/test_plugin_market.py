"""
S9d 抽取验证：app.helper.plugin_market 行为单测。

覆盖：
- process_plugins_list 的合并 / 去重 / 版本择优 / 市场来源优先逻辑
- install_plugin_missing_dependencies 的早返回与委派安装路径
- PluginManager 门面方法与抽出模块的等价性（委派契约）
"""
from app import schemas
from app.core.config import settings
from app.helper import plugin_market


def _plugin(pid: str, version: str, repo_url: str) -> schemas.Plugin:
    return schemas.Plugin(id=pid, plugin_version=version, repo_url=repo_url)


def _ids_versions(plugins):
    return {(p.id, p.plugin_version) for p in plugins}


def test_merge_adds_base_only_plugins(monkeypatch):
    """高版本列表与基础列表合并：基础列表中未出现的插件应被纳入。"""
    monkeypatch.setattr(settings, "PLUGIN_MARKET", "https://m1", raising=False)
    higher = [_plugin("A", "1.0", "https://m1")]
    base = [_plugin("A", "1.0", "https://m1"), _plugin("B", "1.0", "https://m1")]

    result = plugin_market.process_plugins_list(higher, base)

    assert {p.id for p in result} == {"A", "B"}


def test_keeps_highest_version_per_id(monkeypatch):
    """同 ID 多版本：仅保留版本号最大的那个。"""
    monkeypatch.setattr(settings, "PLUGIN_MARKET", "https://m1", raising=False)
    higher = [_plugin("A", "2.0", "https://m1")]
    base = [_plugin("A", "1.0", "https://m1")]

    result = plugin_market.process_plugins_list(higher, base)

    assert len(result) == 1
    assert result[0].id == "A"
    assert result[0].plugin_version == "2.0"


def test_market_source_preferred_over_local_same_version(monkeypatch):
    """同 ID + 同版本：市场来源优先于本地来源。"""
    monkeypatch.setattr(settings, "PLUGIN_MARKET", "https://m1", raising=False)
    higher = []
    base = [_plugin("A", "1.0", "local://A"), _plugin("A", "1.0", "https://m1")]

    result = plugin_market.process_plugins_list(higher, base)

    assert len(result) == 1
    assert result[0].repo_url == "https://m1"


def test_empty_inputs_return_empty(monkeypatch):
    monkeypatch.setattr(settings, "PLUGIN_MARKET", "", raising=False)
    assert plugin_market.process_plugins_list([], []) == []


class _FakePluginSource:
    def __init__(self, missing, install_result=(True, "ok")):
        self._missing = missing
        self._install_result = install_result
        self.installed_with = None

    def find_missing_dependencies(self):
        return self._missing

    def install_dependencies(self, deps):
        self.installed_with = deps
        return self._install_result


def test_install_missing_deps_early_return_when_none(monkeypatch):
    """无缺失依赖时直接返回空列表，不触发安装。"""
    fake = _FakePluginSource(missing=[])
    monkeypatch.setattr(plugin_market, "get_plugin_source", lambda: fake)

    result = plugin_market.install_plugin_missing_dependencies()

    assert result == []
    assert fake.installed_with is None


def test_install_missing_deps_delegates_install(monkeypatch):
    """存在缺失依赖时委派安装并返回缺失列表。"""
    fake = _FakePluginSource(missing=["dep-a", "dep-b"], install_result=(True, "done"))
    monkeypatch.setattr(plugin_market, "get_plugin_source", lambda: fake)

    result = plugin_market.install_plugin_missing_dependencies()

    assert result == ["dep-a", "dep-b"]
    assert fake.installed_with == ["dep-a", "dep-b"]


def test_pluginmanager_facade_delegates_process(monkeypatch):
    """PluginManager.process_plugins_list 门面与抽出模块结果一致。"""
    from app.helper.plugin_manager import PluginManager

    monkeypatch.setattr(settings, "PLUGIN_MARKET", "https://m1", raising=False)
    higher = [_plugin("A", "2.0", "https://m1")]
    base = [_plugin("A", "1.0", "https://m1"), _plugin("B", "1.0", "https://m1")]

    facade = PluginManager.process_plugins_list(higher, base)
    direct = plugin_market.process_plugins_list(higher, base)

    assert _ids_versions(facade) == _ids_versions(direct)


def test_pluginmanager_facade_delegates_install(monkeypatch):
    """PluginManager.install_plugin_missing_dependencies 门面委派到抽出模块。"""
    from app.helper.plugin_manager import PluginManager

    fake = _FakePluginSource(missing=["dep-x"])
    monkeypatch.setattr(plugin_market, "get_plugin_source", lambda: fake)

    result = PluginManager.install_plugin_missing_dependencies()

    assert result == ["dep-x"]
    assert fake.installed_with == ["dep-x"]
