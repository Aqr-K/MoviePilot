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
