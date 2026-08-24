"""进程外插件宿主的端到端验证。

覆盖四条必须成立的路径：常驻有状态实例的全生命周期、插件反向调用宿主受限 API、
失控插件被超时隔离而宿主不受影响、子进程崩溃后宿主感知并恢复；另加白名单拒绝
与声明跨进程序列化往返。
"""
import os
import time
from pathlib import Path

import pytest

from app.runtime.extensions.contract.declaration import ScheduleDeclaration
from app.runtime.extensions.remote import (
    HOST_API_TABLE,
    HostApiError,
    HostApiGateway,
    RemotePluginCrashed,
    RemotePluginError,
    RemotePluginProxy,
    RemotePluginSpec,
    RemotePluginTimeout,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 样例插件的定位坐标，全部用例共用
SAMPLE_SPEC = RemotePluginSpec(
    module="tests.fixtures.remote_plugins.sample_plugin",
    class_name="SampleRemotePlugin",
    plugin_id="SampleRemotePlugin",
    instance_id="default",
    sys_path=(str(PROJECT_ROOT),),
)
# 常规调用的超时秒数，需容纳子进程冷启动
CALL_TIMEOUT = 15.0
# 死循环用例的超时秒数，取小值以免拖慢测试
SPIN_TIMEOUT = 1.5


class FakeHostBackend:
    """
    宿主受限 API 的假后端，记录全部落到宿主侧的调用。
    """

    def __init__(self):
        self.plugin_data = {}
        self.plugin_config = {"enabled": True}
        self.system_config = {"DownloadPath": "/media/downloads"}
        self.events = []
        self.messages = []
        self.logs = []

    def handlers(self):
        """
        :return: 宿主 API 名到实现的映射
        """
        return {
            "systemconfig.get": lambda key: self.system_config.get(key),
            "pluginconfig.get": lambda: dict(self.plugin_config),
            "pluginconfig.set": self._config_set,
            "plugindata.get": lambda key=None: (
                dict(self.plugin_data) if key is None else self.plugin_data.get(key)
            ),
            "plugindata.save": self._data_save,
            "plugindata.delete": self._data_delete,
            "event.send": self._event_send,
            "message.post": self._message_post,
            "logger.log": lambda level, message: self.logs.append((level, message)),
        }

    def _config_set(self, config):
        self.plugin_config = dict(config)
        return True

    def _data_save(self, key, value):
        self.plugin_data[key] = value
        return True

    def _data_delete(self, key):
        return self.plugin_data.pop(key, None) is not None

    def _event_send(self, etype, data=None):
        self.events.append((etype, data))
        return True

    def _message_post(self, title, text=""):
        self.messages.append((title, text))
        return True


def _process_gone(pid, wait=5.0) -> bool:
    """
    等待并判定某个进程确实已经消失。
    :param pid: 进程号
    :param wait: 最长等待秒数
    :return: 进程是否已消失
    """
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def backend():
    """宿主受限 API 的假后端。"""
    return FakeHostBackend()


@pytest.fixture
def gateway(backend):
    """按假后端装配的宿主 API 网关。"""
    return HostApiGateway(handlers=backend.handlers())


@pytest.fixture
def proxy_factory(gateway):
    """
    产出插件代理并在用例结束后统一回收，保证不留孤儿进程。
    """
    created = []

    def _make(timeout=CALL_TIMEOUT, api_gateway=None):
        proxy = RemotePluginProxy(
            spec=SAMPLE_SPEC,
            gateway=api_gateway or gateway,
            timeout=timeout,
        )
        created.append(proxy)
        return proxy

    yield _make

    for proxy in created:
        pids = list(proxy.spawned_pids)
        proxy.close()
        for pid in pids:
            assert _process_gone(pid), f"插件子进程未被回收: pid={pid}"


@pytest.fixture
def plugin(proxy_factory):
    """已完成 init_plugin 的插件代理。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True, "counter": 0, "cron": "0 2 * * *"})
    return proxy


# ---------------------------------------------------------------------- #
# 全生命周期
# ---------------------------------------------------------------------- #


def test_full_lifecycle_runs_in_child_process(plugin):
    """init_plugin 到 stop_service 的全链路在子进程内完成，且不在宿主进程内。"""
    assert plugin.get_state() is True
    assert plugin.pid is not None
    assert plugin.pid != os.getpid()

    assert plugin.call("echo", args=("hello",), kwargs={"suffix": "-远程"}) == "hello-远程"

    plugin.stop_service()
    assert plugin.call("is_stopped") is True


def test_plugin_instance_keeps_state_between_calls(plugin):
    """插件实例常驻子进程，多次调用之间保持内部状态。"""
    assert plugin.call("bump") == 1
    assert plugin.call("bump", kwargs={"step": 5}) == 6
    assert plugin.call("bump") == 7


def test_disabled_state_follows_injected_config(proxy_factory):
    """init_plugin 传入的配置在子进程内真正生效。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": False})
    assert proxy.get_state() is False


def test_plugin_exception_maps_back_to_host(plugin):
    """插件内部异常经协议映射为宿主侧异常，且不影响后续调用。"""
    with pytest.raises(RemotePluginError) as excinfo:
        plugin.call("boom", kwargs={"message": "样例失败"})
    assert "样例失败" in str(excinfo.value)
    assert plugin.call("echo", args=("still-alive",)) == "still-alive"


def test_unknown_method_is_rejected(plugin):
    """调用插件没有的方法被拒绝，而不是静默返回 None。"""
    with pytest.raises(RemotePluginError):
        plugin.call("no_such_method")


# ---------------------------------------------------------------------- #
# 反向回调宿主
# ---------------------------------------------------------------------- #


def test_plugin_calls_whitelisted_host_api(plugin, backend):
    """插件反向调用宿主白名单 API 并拿到结果。"""
    assert plugin.call("read_system_config", args=("DownloadPath",)) == "/media/downloads"


def test_multiple_host_calls_interleave_within_one_plugin_call(plugin, backend):
    """一次插件调用内可以交错多次宿主回调，响应不会与插件结果串味。"""
    result = plugin.call("save_and_read", args=("last_run",), kwargs={"value": {"n": 7}})
    assert result == {"n": 7}
    assert backend.plugin_data["last_run"] == {"n": 7}
    # 交错之后紧接的普通调用仍取到正确的响应
    assert plugin.call("echo", args=("after",)) == "after"


def test_host_call_result_does_not_shift_response_ids(plugin, backend):
    """连续多轮「宿主回调 + 普通调用」不会让请求与响应错位。"""
    for index in range(5):
        assert plugin.call("save_and_read", args=(f"k{index}",), kwargs={"value": index}) == index
        assert plugin.call("bump") == index + 1
    assert backend.plugin_data == {f"k{i}": i for i in range(5)}


def test_host_api_outside_whitelist_is_refused(plugin, backend):
    """白名单外的宿主调用被拒绝，宿主不执行任何动作。"""
    answer = plugin.call(
        "try_invoke_host",
        args=("chain.recognize_media",),
        kwargs={"title": "任意标题"},
    )
    assert answer.startswith("err:")
    assert "chain.recognize_media" in answer
    # 拒绝之后插件与宿主都还在正常工作
    assert plugin.call("echo", args=("ok",)) == "ok"


def test_host_api_rejects_bad_arguments(plugin, backend):
    """宿主对子进程送来的参数做校验，类型不符即拒绝。"""
    answer = plugin.call(
        "try_invoke_host", args=("plugindata.save",), kwargs={"key": 123, "value": 1}
    )
    assert answer.startswith("err:")
    assert backend.plugin_data == {}

    answer = plugin.call("try_invoke_host", args=("plugindata.save",), kwargs={"key": "k"})
    assert answer.startswith("err:")

    answer = plugin.call(
        "try_invoke_host",
        args=("plugindata.save",),
        kwargs={"key": "k", "value": 1, "extra": 2},
    )
    assert answer.startswith("err:")


def test_host_api_table_is_explicit_data(backend):
    """白名单是显式的数据表，不含 ChainBase 全面。"""
    names = {spec.name for spec in HOST_API_TABLE}
    assert "plugindata.save" in names
    assert not any(name.startswith("chain.") for name in names)
    assert all(spec.params is not None for spec in HOST_API_TABLE)

    gate = HostApiGateway(handlers=backend.handlers())
    assert set(gate.api_names) <= names
    with pytest.raises(HostApiError):
        gate.invoke("chain.recognize_media", {"title": "x"})
    with pytest.raises(HostApiError):
        gate.invoke("__class__", {})


def test_gateway_without_handler_does_not_expose_api(backend):
    """表里声明但未注入实现的 API 不对外暴露。"""
    handlers = backend.handlers()
    handlers.pop("plugindata.save")
    gate = HostApiGateway(handlers=handlers)
    assert "plugindata.save" not in gate.api_names
    with pytest.raises(HostApiError):
        gate.invoke("plugindata.save", {"key": "k", "value": 1})


# ---------------------------------------------------------------------- #
# 故障隔离
# ---------------------------------------------------------------------- #


def test_runaway_plugin_is_isolated_by_timeout(proxy_factory):
    """死循环插件被超时隔离，宿主进程不受影响并能继续工作。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True, "counter": 0})
    proxy.call("bump")
    first_pid = proxy.pid

    started = time.monotonic()
    with pytest.raises(RemotePluginTimeout):
        proxy.call("spin_forever", timeout=SPIN_TIMEOUT)
    elapsed = time.monotonic() - started
    assert elapsed < SPIN_TIMEOUT + 5

    assert _process_gone(first_pid), "超时后失控子进程未被强杀"
    assert proxy.pid is None
    assert proxy.generation == 1

    # 宿主自身完好：下一次调用惰性重启子进程并重放 init_plugin
    assert proxy.get_state() is True
    assert proxy.generation == 2
    assert proxy.pid != first_pid
    # 强杀丢掉了实例状态，重放配置后计数器回到初值
    assert proxy.call("bump") == 1


def test_timeout_is_not_retried(proxy_factory):
    """超时不重试——重试只会再冻一次。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True})
    started = time.monotonic()
    with pytest.raises(RemotePluginTimeout):
        proxy.call("spin_forever", timeout=SPIN_TIMEOUT)
    assert time.monotonic() - started < SPIN_TIMEOUT * 2


def test_crashed_child_is_detected_and_recovered(proxy_factory):
    """子进程崩溃被宿主感知，且下一次调用自动恢复到已初始化状态。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True, "counter": 10})
    assert proxy.call("bump") == 11
    first_pid = proxy.pid

    with pytest.raises(RemotePluginCrashed):
        proxy.call("crash_now")

    assert _process_gone(first_pid)
    assert proxy.get_state() is True
    assert proxy.pid != first_pid
    # 恢复即重放 init_plugin，状态回到配置声明的初值而不是崩溃前的值
    assert proxy.call("bump") == 11


def test_terminated_child_respawns_lazily(proxy_factory):
    """主动回收子进程后，下一次调用惰性重启并重放初始化，调用方无感。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True, "counter": 3})
    first_pid = proxy.pid
    proxy.terminate_worker()
    assert _process_gone(first_pid)

    assert proxy.call("bump") == 4
    assert proxy.pid != first_pid
    assert proxy.generation == 2


def test_write_phase_pipe_break_is_retried_once(proxy_factory, monkeypatch):
    """请求还没送达就断管属于良性竞态，重启后重试一次。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True, "counter": 0})

    original_send = proxy._send  # noqa: SLF001 - 精确验证重试语义
    calls = {"n": 0}

    def flaky_send(message):
        calls["n"] += 1
        if calls["n"] == 1:
            raise BrokenPipeError("模拟写入时断管")
        return original_send(message)

    monkeypatch.setattr(proxy, "_send", flaky_send)
    assert proxy.call("bump") == 1
    assert calls["n"] >= 2


def test_host_handler_reentering_proxy_is_refused_not_deadlocked(proxy_factory, backend):
    """宿主回调实现里回头再调插件会死锁，代理必须当场拒绝而不是挂起。

    子进程此刻正阻塞在等待 hostresult 上，不会处理新的 call；宿主若在应答
    hostresult 之前又去等新 call 的 result，两边互等。
    """
    reentry = {}

    handlers = backend.handlers()

    def reentrant_get(key):
        try:
            reentry["result"] = proxy.call("echo", args=("重入",))
        except Exception as err:  # noqa: BLE001 - 记录拒绝原因供断言
            reentry["error"] = err
        return "已尝试重入"

    handlers["systemconfig.get"] = reentrant_get
    proxy = proxy_factory(api_gateway=HostApiGateway(handlers=handlers), timeout=8.0)
    proxy.init_plugin({"enabled": True})

    assert proxy.call("read_system_config", args=("任意键",)) == "已尝试重入"
    assert "result" not in reentry
    assert isinstance(reentry.get("error"), RemotePluginError)
    # 拒绝重入之后，代理仍然可用
    assert proxy.call("echo", args=("之后",)) == "之后"


def test_plugin_stdout_noise_does_not_corrupt_protocol(plugin):
    """插件往 stdout 打印不会污染协议通道。"""
    assert plugin.call("noisy", args=("一号",)) == "一号"
    assert plugin.call("noisy", args=("二号",)) == "二号"
    assert plugin.call("bump") == 1


def test_close_reclaims_child_process(proxy_factory):
    """close 之后子进程确实消失，不留孤儿。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True})
    pid = proxy.pid
    proxy.close()
    assert proxy.pid is None
    assert _process_gone(pid)


# ---------------------------------------------------------------------- #
# 声明跨进程序列化
# ---------------------------------------------------------------------- #


def test_schedule_declaration_survives_process_boundary(proxy_factory):
    """ScheduleDeclaration 的数据部分原样过进程边界，impl 换成 RPC 派发。"""
    proxy = proxy_factory()
    proxy.init_plugin({"enabled": True, "counter": 0, "cron": "30 4 * * *"})

    declarations = proxy.provides("schedules")
    assert len(declarations) == 1
    declaration = declarations[0]

    assert isinstance(declaration, ScheduleDeclaration)
    assert declaration.job_id == "sample_sync"
    assert declaration.name == "样例同步"
    assert declaration.trigger == "cron"
    assert dict(declaration.trigger_args) == {"crontab": "30 4 * * *"}
    assert dict(declaration.kwargs) == {"scope": "all"}

    # impl 不是原对象而是一个把调用派回子进程的可调用体
    assert callable(declaration.impl)
    assert declaration.impl(**dict(declaration.kwargs)) == "synced:all:100"
    # 确实是同一个常驻实例在执行
    assert proxy.call("bump") == 101


def test_provides_hook_absent_returns_empty(plugin):
    """插件没实现的声明钩子返回空列表而不是报错。"""
    assert plugin.provides("commands") == []
