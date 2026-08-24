"""进程外插件宿主的 worker 入口。

**本文件不被 import，只作为独立脚本执行**（宿主用
``subprocess.Popen([sys.executable, <本文件绝对路径>])`` 启动）。它自身只依赖
标准库，连协议模块都按文件路径加载而不是 ``import app.runtime...``——插件模块要
牵进什么依赖是插件自己的事，worker 骨架不该再叠一层宿主的导入链。

与 ``fsworker`` 的根本差别在于**有状态**：那边每个请求各自独立，这边插件实例在
本进程内常驻，``init_plugin`` 之后的配置与内部状态一直保留到进程结束。因此进程
一旦被回收，状态即随之丢失，恢复要靠宿主重放初始化。

协议见 ``protocol.py``。本进程做三件事：按握手报文装载插件实例、按 ``call`` 报文
调用插件方法、把插件发起的宿主回调转成 ``hostcall`` 报文并等待 ``hostresult``。

**协议通道与插件输出隔离**：启动时先把 stdout/stdin 的文件描述符复制一份留给协议
自用，再把 0 号描述符接到 /dev/null、1 号描述符指向 stderr。插件里任何 ``print``
都落到 stderr，撞不进协议通道——第三方代码打一行日志就把宿主的读循环喂成
JSONDecodeError 是不可接受的。
"""
import importlib
import importlib.util
import os
import sys
import traceback
from typing import Any, Callable, Dict, List, Optional


def _load_protocol():
    """
    按文件路径加载协议模块，绕开包导入。
    :return: 协议模块对象
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protocol.py")
    spec = importlib.util.spec_from_file_location("_remote_plugin_protocol", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


protocol = _load_protocol()


class HostCallError(Exception):
    """宿主拒绝或未能完成一次反向调用。"""


class Channel:
    """
    协议通道，独占一对与插件输出隔离的文件描述符。
    """

    def __init__(self, read_fd: int, write_fd: int):
        """
        :param read_fd: 读端描述符
        :param write_fd: 写端描述符
        """
        self._reader = os.fdopen(read_fd, "rb", buffering=0)
        self._writer = os.fdopen(write_fd, "wb", buffering=0)

    def read(self) -> Optional[Dict[str, Any]]:
        """
        读取一条报文。
        :return: 报文字典，管道关闭时为 None
        """
        line = self._reader.readline()
        if not line:
            return None
        return protocol.decode(line)

    def write(self, message: Dict[str, Any]) -> None:
        """
        写出一条报文。
        :param message: 报文字典
        """
        self._writer.write(protocol.encode(message))


def _isolate_streams() -> Channel:
    """
    把协议通道从标准流上摘下来，之后插件的输出污染不到协议。
    :return: 协议通道
    """
    read_fd = os.dup(0)
    write_fd = os.dup(1)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    # 1 号描述符改指 stderr：插件的 print 落到 stderr，由宿主按需丢弃或收集
    os.dup2(2, 1)
    sys.stdout = os.fdopen(os.dup(2), "w", buffering=1, errors="replace")
    sys.stdin = open(os.devnull, "r")  # noqa: SIM115 - 进程存活期间常开
    return Channel(read_fd, write_fd)


class HostNamespace:
    """
    宿主 API 的一级命名空间，让插件写成 ``host.plugindata.save(...)``。
    """

    def __init__(self, invoke: Callable[..., Any], prefix: str, actions: frozenset):
        """
        :param invoke: 反向调用入口
        :param prefix: 命名空间名
        :param actions: 该命名空间下可用的动作名
        """
        self._invoke = invoke
        self._prefix = prefix
        self._actions = actions

    def __getattr__(self, action: str) -> Callable[..., Any]:
        """
        :param action: 动作名
        :return: 绑定到 ``前缀.动作`` 的调用入口
        """
        if action not in self._actions:
            raise AttributeError(f"宿主未开放 {self._prefix}.{action}")

        def _call(**kwargs):
            return self._invoke(f"{self._prefix}.{action}", **kwargs)

        return _call


class RemoteHost:
    """
    插件侧的宿主句柄，把宿主回调转成 ``hostcall`` 报文。

    握手报文带来的 API 名清单只用于生成命名空间语法糖并尽早报错；**判定白名单的
    是宿主**，绕过命名空间直接 ``invoke`` 一个表外的名字同样会被宿主拒绝。
    """

    def __init__(self, channel: Channel, api_names: List[str]):
        """
        :param channel: 协议通道
        :param api_names: 宿主开放的 API 名清单
        """
        self._channel = channel
        self._api_names = frozenset(api_names)
        self._next_id = 0
        namespaces: Dict[str, set] = {}
        for name in self._api_names:
            prefix, _, action = name.partition(".")
            if action:
                namespaces.setdefault(prefix, set()).add(action)
        self._namespaces = {
            prefix: HostNamespace(self.invoke, prefix, frozenset(actions))
            for prefix, actions in namespaces.items()
        }

    def __getattr__(self, prefix: str) -> HostNamespace:
        """
        :param prefix: 命名空间名
        :return: 该命名空间
        """
        namespace = self.__dict__.get("_namespaces", {}).get(prefix)
        if namespace is None:
            raise AttributeError(f"宿主未开放命名空间 {prefix}")
        return namespace

    @property
    def api_names(self) -> frozenset:
        """
        :return: 宿主开放的 API 名
        """
        return self._api_names

    def invoke(self, api: str, **kwargs) -> Any:
        """
        发起一次宿主回调并同步等待结果。

        等待期间只可能读到本次回调的 ``hostresult``：宿主的请求是串行的，它此刻
        正阻塞在等待本插件调用的结果上，不会再发起新的 ``call``。
        :param api: 宿主 API 名
        :param kwargs: 关键字参数
        :return: 宿主返回值
        :raises HostCallError: 宿主拒绝调用，或宿主侧管道已关闭
        """
        self._next_id += 1
        call_id = self._next_id
        self._channel.write({
            "t": protocol.MSG_HOSTCALL, "id": call_id, "api": api, "kwargs": kwargs,
        })
        while True:
            message = self._channel.read()
            if message is None:
                raise HostCallError("宿主已关闭连接")
            if message.get("t") != protocol.MSG_HOSTRESULT:
                raise HostCallError(f"等待宿主回调结果时收到意外报文: {message.get('t')}")
            if message.get("id") != call_id:
                raise HostCallError("宿主回调结果的序号不匹配")
            if message.get("ok"):
                return message.get("result")
            raise HostCallError(message.get("error") or f"{api} 调用失败")


def _instantiate(spec: Dict[str, Any]):
    """
    按握手报文装载并实例化插件。
    :param spec: 插件定位坐标
    :return: 插件实例
    """
    for entry in reversed(spec.get("sys_path") or []):
        if entry and entry not in sys.path:
            sys.path.insert(0, entry)

    module = importlib.import_module(spec["module"])
    plugin_type = getattr(module, spec["class_name"], None)
    if plugin_type is None:
        raise AttributeError(f"{spec['module']} 内没有 {spec['class_name']}")
    try:
        return plugin_type(
            plugin_id=spec.get("plugin_id"), instance_id=spec.get("instance_id")
        )
    except TypeError:
        # 不接受标识参数的插件按无参构造，与进程内的装载行为一致
        return plugin_type()


def _resolve(instance: Any, method: Any) -> Callable[..., Any]:
    """
    定位插件上的一个可调用方法。
    :param instance: 插件实例
    :param method: 方法名
    :return: 绑定方法
    :raises AttributeError: 方法名不合法或不存在
    :raises TypeError: 该名字不是可调用对象
    """
    if not isinstance(method, str) or not method or method.startswith("_"):
        raise AttributeError(f"方法名不可调用: {method!r}")
    target = getattr(instance, method, None)
    if target is None:
        raise AttributeError(f"插件没有方法 {method}")
    if not callable(target):
        raise TypeError(f"{method} 不是可调用对象")
    return target


def _declarations(result: Any) -> List[Dict[str, Any]]:
    """
    把声明钩子的返回值序列化成报文。
    :param result: 钩子返回值
    :return: 声明报文列表
    """
    if not result:
        return []
    return [protocol.serialize_declaration(item) for item in result]


def _handle_call(instance: Any, message: Dict[str, Any]) -> Dict[str, Any]:
    """
    执行一次插件方法调用并组装响应报文。
    :param instance: 插件实例
    :param message: 调用报文
    :return: 响应报文
    """
    response = {"t": protocol.MSG_RESULT, "id": message.get("id")}
    is_declaration = bool(message.get("decl"))
    try:
        try:
            target = _resolve(instance, message.get("method"))
        except AttributeError:
            # 插件没实现的声明钩子等价于「不提供该扩展点」，不算错误
            if is_declaration:
                response.update({"ok": True, "result": []})
                return response
            raise
        args = message.get("args") or []
        kwargs = message.get("kwargs") or {}
        if not isinstance(args, list) or not isinstance(kwargs, dict):
            raise TypeError("调用参数形状不合协议")
        result = target(*args, **kwargs)
        response.update({
            "ok": True,
            "result": _declarations(result) if is_declaration else result,
        })
    except BaseException as err:  # noqa: BLE001 - 插件的任何失败都要变成一条响应
        response.update({
            "ok": False,
            "error": str(err) or err.__class__.__name__,
            "errtype": err.__class__.__name__,
            "traceback": traceback.format_exc(limit=8),
        })
    return response


def _safe_write(channel: Channel, response: Dict[str, Any]) -> None:
    """
    写出响应；返回值过不了进程边界时改写成一条错误响应。

    插件返回了只在本进程内成立的对象是常见错误，它必须表现为「这次调用失败」，
    而不是让宿主读到半行报文。
    :param channel: 协议通道
    :param response: 响应报文
    """
    try:
        channel.write(response)
    except protocol.ProtocolError as err:
        channel.write({
            "t": protocol.MSG_RESULT,
            "id": response.get("id"),
            "ok": False,
            "error": f"插件返回值过不了进程边界: {err}",
            "errtype": "ProtocolError",
        })


def main() -> int:
    """
    握手后进入请求循环，直到宿主关闭管道。
    :return: 进程退出码
    """
    channel = _isolate_streams()
    hello = channel.read()
    if not hello or hello.get("t") != protocol.MSG_HELLO:
        return 1
    if hello.get("protocol") != protocol.PROTOCOL_VERSION:
        channel.write({
            "t": protocol.MSG_READY, "ok": False,
            "error": f"协议版本不匹配: 宿主 {hello.get('protocol')}，"
                     f"worker {protocol.PROTOCOL_VERSION}",
        })
        return 1

    spec = hello.get("spec") or {}
    try:
        instance = _instantiate(spec)
        instance.host = RemoteHost(channel, hello.get("host_apis") or [])
    except BaseException as err:  # noqa: BLE001 - 装载失败也要如实回报
        channel.write({
            "t": protocol.MSG_READY, "ok": False,
            "error": f"{err.__class__.__name__}: {err}",
            "traceback": traceback.format_exc(limit=8),
        })
        return 1

    channel.write({
        "t": protocol.MSG_READY, "ok": True, "pid": os.getpid(),
        "plugin": spec.get("class_name"),
    })

    while True:
        try:
            message = channel.read()
        except protocol.ProtocolError:
            # 宿主送来的报文损坏，跳过这一行继续，不拖垮常驻实例
            continue
        if message is None:
            return 0
        if message.get("t") != protocol.MSG_CALL:
            continue
        _safe_write(channel, _handle_call(instance, message))


if __name__ == "__main__":
    sys.exit(main())
