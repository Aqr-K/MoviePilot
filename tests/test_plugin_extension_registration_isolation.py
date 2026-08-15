"""扩展点注册逐类隔离：任一类失败不连累其余。"""
from unittest.mock import Mock, patch

from app.runtime.extensions import plugin_lifecycle


def test_a_failing_registrar_does_not_block_the_others():
    """一类扩展点注册失败不连累其余两类。"""
    calls = []

    def record(name):
        """记录该类注册被执行"""
        return lambda *args, **kwargs: calls.append(name)

    with patch.object(plugin_lifecycle, "register_plugin_modules",
                      side_effect=RuntimeError("boom")), \
            patch.object(plugin_lifecycle, "register_plugin_storages",
                         side_effect=record("storages")), \
            patch.object(plugin_lifecycle, "register_plugin_channel_capabilities",
                         side_effect=record("capabilities")):
        plugin_lifecycle.register_plugin_extensions({}, Mock(), None)

    assert calls == ["storages", "capabilities"]


def test_every_registrar_runs_even_when_all_of_them_fail():
    """三类都失败时每类仍各自被尝试过一次。"""
    attempted = []

    def blow_up(name):
        """记录尝试并抛错"""
        def _raise(*args, **kwargs):
            attempted.append(name)
            raise RuntimeError(name)
        return _raise

    with patch.object(plugin_lifecycle, "register_plugin_modules",
                      side_effect=blow_up("modules")), \
            patch.object(plugin_lifecycle, "register_plugin_storages",
                         side_effect=blow_up("storages")), \
            patch.object(plugin_lifecycle, "register_plugin_channel_capabilities",
                         side_effect=blow_up("capabilities")):
        plugin_lifecycle.register_plugin_extensions({}, Mock(), None)

    assert attempted == ["modules", "storages", "capabilities"]


def test_one_bad_capability_does_not_abort_the_rest():
    """单条渠道能力声明抛错不影响同一趟里的其余声明。"""
    from app.runtime.extensions import plugin_lifecycle as lifecycle

    accepted = []
    good = Mock(channel="ok")
    bad = Mock(channel="bad")

    def register(capability, owner):
        """坏声明抛错，好声明记账"""
        if capability is bad:
            raise RuntimeError("boom")
        accepted.append((capability.channel, owner))
        return True

    manager = Mock()
    manager.register_capabilities.side_effect = register
    with patch.object(lifecycle, "get_plugin_provided_channel_capabilities",
                      return_value={"plugin_a": [bad, good]}), \
            patch.object(lifecycle, "ChannelCapabilityManager", manager):
        lifecycle.register_plugin_channel_capabilities({}, None)

    assert accepted == [("ok", "plugin_a")]


def test_one_bad_storage_does_not_abort_the_rest():
    """单条存储声明抛错不影响同一趟里的其余声明。"""
    from app.runtime.extensions import plugin_lifecycle as lifecycle

    registered = []

    def register(storage, owner):
        """坏声明抛错，好声明记账"""
        if storage == "bad":
            raise RuntimeError("boom")
        registered.append((storage, owner))
        return True

    with patch.object(lifecycle, "get_plugin_provided_storages",
                      return_value={"plugin_a": ["bad", "good"]}), \
            patch("app.adapters.storage.registry.register_storage", side_effect=register):
        lifecycle.register_plugin_storages({}, None)

    assert registered == [("good", "plugin_a")]
