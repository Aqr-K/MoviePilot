"""进程外插件宿主的宿主侧代理。

一个代理管一个插件实例的一个常驻子进程：惰性拉起、崩溃自愈、超时强杀回收，并在
单对管道上跑双向 RPC——宿主发起的方法调用与插件发起的宿主回调可以任意交错。

**有状态是与 ``fsproxy`` 的根本差别**。那边每个操作独立，强杀无损；这边插件实例
在子进程内常驻，``init_plugin`` 之后的配置与内部状态随进程一起消失。因此代理记住
最后一次生效的配置，任何一次重启（超时强杀或崩溃）之后的**首个调用会先重放
``init_plugin``**，调用方拿到的是一个重新初始化过的实例，而不是一个半死不活的。

三种故障的处置各不相同，因为它们对插件副作用的含义不同：

- **超时**：判定插件失控，SIGKILL 回收并把 ``RemotePluginTimeout`` 交给调用方，
  **不重试**——重试只会再冻一次。
- **读响应阶段断管**（插件把子进程带崩）：请求已经送达、副作用可能已经发生，
  重试语义不成立，抛 ``RemotePluginCrashed`` 由调用方裁决。
- **写请求阶段断管**：请求根本没送达，属于「子进程恰好在两次调用之间退出」的
  良性竞态，重启后重试一次。

协议见 ``protocol.py``，宿主回调的白名单见 ``host_api.py``。
"""
import selectors
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.runtime.extensions.remote.host_api import HostApiGateway
from app.runtime.extensions.remote.protocol import (
    MSG_CALL,
    MSG_HELLO,
    MSG_HOSTCALL,
    MSG_HOSTRESULT,
    MSG_READY,
    MSG_RESULT,
    PROTOCOL_VERSION,
    ProtocolError,
    decode,
    deserialize_declaration,
    encode,
)
from app.runtime.log import logger

# worker 脚本路径。按绝对路径直接执行而不是 -m：直接执行文件不触发包导入链，
# 子进程只在装载插件模块时才付出依赖代价
_WORKER_PATH = Path(__file__).parent / "plugin_worker.py"
# 单次插件调用的默认超时秒数
DEFAULT_CALL_TIMEOUT = 60.0
# 强杀子进程后等待它消失的宽限秒数，不能无限等待
_KILL_GRACE = 5.0

# 声明类的解析结果缓存，键为类名
_DECLARATION_TYPES: Dict[str, type] = {}


class RemotePluginError(Exception):
    """进程外插件调用失败。

    :param message: 错误描述
    :param errtype: 子进程内原始异常的类型名
    :param remote_traceback: 子进程内的调用栈文本
    """

    def __init__(self, message: str, errtype: str = "",
                 remote_traceback: str = ""):
        super().__init__(message)
        self.errtype = errtype
        self.remote_traceback = remote_traceback


class RemotePluginTimeout(RemotePluginError):
    """插件在约定时间内没有返回，判定失控，子进程已被强杀。"""


class RemotePluginCrashed(RemotePluginError):
    """子进程在调用过程中消失，本次调用的副作用未知。"""


@dataclass(frozen=True)
class RemotePluginSpec:
    """
    进程外插件的定位坐标。

    :param module: 插件模块的可导入名
    :param class_name: 插件主类名
    :param plugin_id: 插件标识，构造实例时传入
    :param instance_id: 实例标识，构造实例时传入
    :param sys_path: 子进程需要额外加入 ``sys.path`` 的目录
    """

    module: str
    class_name: str
    plugin_id: Optional[str] = None
    instance_id: Optional[str] = None
    sys_path: Tuple[str, ...] = field(default_factory=tuple)

    def as_payload(self) -> Dict[str, Any]:
        """
        :return: 握手报文里的插件坐标部分
        """
        return {
            "module": self.module,
            "class_name": self.class_name,
            "plugin_id": self.plugin_id,
            "instance_id": self.instance_id,
            "sys_path": list(self.sys_path),
        }


def _declaration_types() -> Dict[str, type]:
    """
    取出契约模块里全部扩展声明类。

    以契约模块为界建表而不是按类名反射：子进程送来的 ``kind`` 是不可信输入，
    只有落在这张表里的类名才可达。
    :return: 类名到声明类的映射
    """
    if not _DECLARATION_TYPES:
        from app.runtime.extensions.contract import declaration as declaration_module

        for name, value in vars(declaration_module).items():
            if (isinstance(value, type)
                    and issubclass(value, declaration_module.ExtensionDeclaration)):
                _DECLARATION_TYPES[name] = value
    return _DECLARATION_TYPES


class RemotePluginProxy:
    """
    单个进程外插件实例的宿主侧代理。

    请求严格串行，由锁保证：一个代理同时只有一个在途调用，因此读循环里等待的
    ``result`` 唯一，插件在此期间发起的 ``hostcall`` 就地应答后继续等待即可。
    """

    def __init__(self, spec: RemotePluginSpec, gateway: HostApiGateway,
                 timeout: float = DEFAULT_CALL_TIMEOUT,
                 python_executable: Optional[str] = None):
        """
        :param spec: 插件定位坐标
        :param gateway: 宿主受限 API 网关
        :param timeout: 单次调用的默认超时秒数
        :param python_executable: 拉起子进程用的解释器，默认取当前解释器
        """
        self._spec = spec
        self._gateway = gateway
        self._timeout = float(timeout)
        self._python = python_executable or sys.executable
        self._process: Optional[subprocess.Popen] = None
        self._selector: Optional[selectors.BaseSelector] = None
        self._lock = threading.RLock()
        self._call_id = 0
        self._generation = 0
        self._spawned_pids: List[int] = []
        self._config: Optional[Dict[str, Any]] = None
        self._initialized = False
        self._in_flight = False

    # ------------------------------------------------------------------ #
    # 状态
    # ------------------------------------------------------------------ #

    @property
    def spec(self) -> RemotePluginSpec:
        """
        :return: 插件定位坐标
        """
        return self._spec

    @property
    def pid(self) -> Optional[int]:
        """
        :return: 当前存活子进程的进程号，没有存活子进程时为 None
        """
        process = self._process
        if process is None or process.poll() is not None:
            return None
        return process.pid

    @property
    def generation(self) -> int:
        """
        :return: 本代理已经启动过的子进程代数，每重启一次加一
        """
        return self._generation

    @property
    def spawned_pids(self) -> Tuple[int, ...]:
        """
        :return: 本代理启动过的全部子进程号，供回收核查
        """
        return tuple(self._spawned_pids)

    # ------------------------------------------------------------------ #
    # 对外调用
    # ------------------------------------------------------------------ #

    def init_plugin(self, config: Optional[Mapping[str, Any]] = None) -> None:
        """
        在子进程内生效配置，并记住它以备重启后重放。
        :param config: 配置字典
        """
        payload = dict(config or {})
        with self._lock:
            self._config = payload
            self._initialized = False
            self.call("init_plugin", args=(payload,))
            self._initialized = True

    def get_state(self) -> bool:
        """
        :return: 插件是否处于启用状态
        """
        return bool(self.call("get_state"))

    def stop_service(self) -> None:
        """
        通知插件停止服务。子进程本身不因此退出，回收进程用 ``close()``。
        """
        self.call("stop_service")

    def call(self, method: str, args: Sequence[Any] = (),
             kwargs: Optional[Mapping[str, Any]] = None,
             timeout: Optional[float] = None) -> Any:
        """
        调用插件的一个方法。

        参数与返回值都必须能 JSON 序列化往返——这是进程边界的硬约束，不能靠
        约定回避。参数写成 ``args``/``kwargs`` 两个显式形参而不是 ``*args,
        **kwargs``，是为了不让插件的参数名与本方法自己的形参撞车。
        :param method: 插件方法名
        :param args: 位置参数
        :param kwargs: 关键字参数
        :param timeout: 本次调用的超时秒数，为空取默认值
        :return: 插件返回值
        :raises RemotePluginTimeout: 插件在超时内未返回，子进程已被强杀
        :raises RemotePluginCrashed: 子进程在调用过程中消失
        :raises RemotePluginError: 插件内部抛出异常，或返回值过不了进程边界
        """
        return self._dispatch(method, args, kwargs, timeout, declarations=False)

    def provides(self, hook: str, timeout: Optional[float] = None) -> List[Any]:
        """
        取回插件某一族扩展点的声明。

        声明的数据部分原样过进程边界，``impl`` 换成一个把调用派回子进程的可调用
        体，宿主对它的调用形状与进程内声明一字不差。插件没实现该钩子时返回空列表。
        :param hook: 扩展点族名，例如 ``schedules``
        :param timeout: 本次调用的超时秒数，为空取默认值
        :return: 扩展声明列表
        """
        payloads = self._dispatch(
            f"provides_{hook}", (), None, timeout, declarations=True
        ) or []
        return [
            deserialize_declaration(
                payload, self._resolve_declaration_type, self._make_impl
            )
            for payload in payloads
        ]

    def terminate_worker(self) -> None:
        """
        回收当前子进程。下一次调用会惰性重启并重放初始化，调用方无感。
        """
        with self._lock:
            self._shutdown()

    def close(self) -> None:
        """
        关闭代理并回收子进程。
        """
        with self._lock:
            self._shutdown()

    # ------------------------------------------------------------------ #
    # 调用链
    # ------------------------------------------------------------------ #

    def _dispatch(self, method: str, args: Sequence[Any],
                  kwargs: Optional[Mapping[str, Any]],
                  timeout: Optional[float], declarations: bool) -> Any:
        """
        发起一次调用，含惰性拉起、初始化重放与写入阶段重试。
        :param method: 插件方法名
        :param args: 位置参数
        :param kwargs: 关键字参数
        :param timeout: 本次调用的超时秒数
        :param declarations: 返回值是否按扩展声明序列化
        :return: 插件返回值
        """
        deadline = time.monotonic() + (self._timeout if timeout is None else float(timeout))
        with self._lock:
            if self._in_flight:
                # 宿主回调的实现里回头再调本插件必然死锁：子进程正阻塞在等待
                # hostresult 上、不会处理新的 call，而宿主要等新 call 的 result
                # 才肯应答那条 hostresult。当场拒绝，不把它拖成一次挂起
                raise RemotePluginError(
                    f"不允许在宿主回调中重入调用 {self._label()}.{method}，"
                    f"该调用会与子进程互等",
                    errtype="Reentrant",
                )
            self._in_flight = True
            try:
                self._ensure_worker(deadline)
                self._call_id += 1
                message = {
                    "t": MSG_CALL,
                    "id": self._call_id,
                    "method": method,
                    "args": list(args),
                    "kwargs": dict(kwargs or {}),
                    "decl": declarations,
                }
                try:
                    self._send(message)
                except (BrokenPipeError, ConnectionError, OSError, ValueError) as err:
                    # 请求还没送达就断管，插件不可能产生副作用，重启后重试一次
                    logger.debug(f"进程外插件写入请求失败，重启后重试: {method} - {err}")
                    self._shutdown()
                    self._ensure_worker(deadline)
                    self._send(message)
                return self._pump(message["id"], deadline, method)
            finally:
                self._in_flight = False

    def _pump(self, call_id: int, deadline: float, method: str) -> Any:
        """
        读循环：按报文类型分派，就地应答宿主回调，直到取到本次调用的结果。
        :param call_id: 本次调用的序号
        :param deadline: 本次调用的截止时刻
        :param method: 插件方法名，仅用于日志与错误文案
        :return: 插件返回值
        """
        while True:
            message = self._read_message(deadline, method)
            kind = message.get("t")
            if kind == MSG_HOSTCALL:
                self._answer_hostcall(message)
                continue
            if kind != MSG_RESULT:
                # 迟到的握手响应等无关报文直接丢弃，不影响本次等待
                continue
            if message.get("id") != call_id:
                self._shutdown()
                raise RemotePluginCrashed(
                    f"进程外插件响应序号错位: {self._label()}.{method}"
                )
            if message.get("ok"):
                return message.get("result")
            raise RemotePluginError(
                f"{self._label()}.{method} 执行失败: "
                f"{message.get('errtype') or 'Error'}: {message.get('error') or '未知错误'}",
                errtype=str(message.get("errtype") or ""),
                remote_traceback=str(message.get("traceback") or ""),
            )

    def _answer_hostcall(self, message: Mapping[str, Any]) -> None:
        """
        执行一次插件发起的宿主回调并回写结果。

        网关抛出的拒绝与实现自身的异常都转成一条失败响应：插件越权或宿主实现
        出错都不该让读循环中断，否则一个坏插件就能把代理拖成崩溃态。
        :param message: 回调报文
        """
        response: Dict[str, Any] = {
            "t": MSG_HOSTRESULT, "id": message.get("id"),
        }
        api = message.get("api")
        try:
            response.update({
                "ok": True,
                "result": self._gateway.invoke(api, message.get("kwargs")),
            })
        except Exception as err:  # noqa: BLE001 - 任何失败都要变成一条响应
            logger.debug(f"进程外插件的宿主回调被拒绝: {self._label()} {api} - {err}")
            response.update({
                "ok": False,
                "error": str(err) or err.__class__.__name__,
                "errtype": err.__class__.__name__,
            })
        try:
            self._write(response)
        except (BrokenPipeError, ConnectionError, OSError, ProtocolError) as err:
            logger.debug(f"回写宿主回调结果失败: {self._label()} {api} - {err}")

    def _read_message(self, deadline: float, method: str) -> Dict[str, Any]:
        """
        读一条报文，超时即强杀子进程。
        :param deadline: 截止时刻
        :param method: 插件方法名，仅用于错误文案
        :return: 报文字典
        :raises RemotePluginTimeout: 截止时刻前没有读到任何一行
        :raises RemotePluginCrashed: 子进程已退出或送来损坏的报文
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._selector.select(timeout=remaining):
            logger.error(
                f"进程外插件 {self._label()}.{method} 超时未返回，正在强杀子进程"
            )
            self._shutdown()
            raise RemotePluginTimeout(
                f"进程外插件 {self._label()}.{method} 超时未返回，子进程已被回收",
                errtype="Timeout",
            )
        line = self._process.stdout.readline()
        if not line:
            self._shutdown()
            raise RemotePluginCrashed(
                f"进程外插件 {self._label()} 的子进程已退出，"
                f"{method} 的执行结果未知"
            )
        try:
            return decode(line)
        except ProtocolError as err:
            self._shutdown()
            raise RemotePluginCrashed(
                f"进程外插件 {self._label()} 的响应损坏: {err}"
            ) from err

    # ------------------------------------------------------------------ #
    # 进程生命周期
    # ------------------------------------------------------------------ #

    def _ensure_worker(self, deadline: float) -> None:
        """
        确保子进程可用，不可用时重新拉起并重放初始化。
        :param deadline: 本次调用的截止时刻
        :raises RemotePluginCrashed: 子进程拉起或握手失败
        """
        if self._process is not None and self._process.poll() is None:
            return
        self._shutdown()
        self._spawn()
        self._handshake(deadline)
        if self._initialized:
            # 强杀丢掉了实例状态，重放最后一次生效的配置把它带回可用状态
            logger.info(f"进程外插件 {self._label()} 子进程已重启，正在重放初始化")
            self._replay_init(deadline)

    def _spawn(self) -> None:
        """
        拉起 worker 子进程。
        """
        self._process = subprocess.Popen(  # noqa: S603 - 命令行由本模块构造
            [self._python, str(_WORKER_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._process.stdout, selectors.EVENT_READ)
        self._generation += 1
        self._spawned_pids.append(self._process.pid)
        logger.debug(
            f"进程外插件 {self._label()} 子进程已启动: "
            f"pid={self._process.pid} 第{self._generation}代"
        )

    def _handshake(self, deadline: float) -> None:
        """
        与子进程握手，交出插件坐标与宿主开放的 API 清单。
        :param deadline: 截止时刻
        :raises RemotePluginCrashed: 握手失败或插件装载失败
        """
        try:
            self._write({
                "t": MSG_HELLO,
                "protocol": PROTOCOL_VERSION,
                "spec": self._spec.as_payload(),
                "host_apis": list(self._gateway.api_names),
            })
        except (BrokenPipeError, ConnectionError, OSError) as err:
            self._shutdown()
            raise RemotePluginCrashed(
                f"进程外插件 {self._label()} 握手失败: {err}"
            ) from err

        message = self._read_message(deadline, "__handshake__")
        if message.get("t") != MSG_READY or not message.get("ok"):
            error = message.get("error") or "子进程未就绪"
            remote_traceback = str(message.get("traceback") or "")
            self._shutdown()
            raise RemotePluginCrashed(
                f"进程外插件 {self._label()} 装载失败: {error}",
                errtype="LoadError",
                remote_traceback=remote_traceback,
            )

    def _replay_init(self, deadline: float) -> None:
        """
        重放最后一次生效的配置。
        :param deadline: 截止时刻
        """
        self._call_id += 1
        self._write({
            "t": MSG_CALL,
            "id": self._call_id,
            "method": "init_plugin",
            "args": [dict(self._config or {})],
            "kwargs": {},
            "decl": False,
        })
        self._pump(self._call_id, deadline, "init_plugin")

    def _send(self, message: Mapping[str, Any]) -> None:
        """
        发送一条调用报文。写入阶段失败是可重试的，故独立成一个方法。
        :param message: 调用报文
        """
        self._write(message)

    def _write(self, message: Mapping[str, Any]) -> None:
        """
        把一条报文写进子进程的 stdin。
        :param message: 报文字典
        :raises BrokenPipeError: 子进程已被回收
        """
        process = self._process
        if process is None or process.stdin is None:
            raise BrokenPipeError(f"进程外插件 {self._label()} 的子进程已被回收")
        process.stdin.write(encode(message))
        process.stdin.flush()

    def _shutdown(self) -> None:
        """
        回收子进程。

        用 SIGKILL 而不是 SIGTERM：失控插件正忙在死循环里，信号处理器根本不会
        被执行；且不无限等待它消失——否则「可放弃的子进程」又变回一次不可放弃的
        阻塞。
        """
        if self._selector is not None:
            try:
                self._selector.close()
            except Exception as err:  # noqa: BLE001
                logger.debug(f"关闭进程外插件读选择器失败: {self._label()} - {err}")
            self._selector = None
        process, self._process = self._process, None
        if process is None:
            return
        for stream in (process.stdin, process.stdout):
            try:
                if stream:
                    stream.close()
            except Exception as err:  # noqa: BLE001
                logger.debug(f"关闭进程外插件管道失败: {self._label()} - {err}")
        if process.poll() is not None:
            return
        try:
            process.kill()
            process.wait(timeout=_KILL_GRACE)
        except subprocess.TimeoutExpired:
            logger.warn(
                f"进程外插件 {self._label()} 子进程未能及时退出，"
                f"交由系统回收: pid={process.pid}"
            )
        except Exception as err:  # noqa: BLE001
            logger.debug(f"回收进程外插件子进程失败: {self._label()} - {err}")

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #

    def _label(self) -> str:
        """
        :return: 插件在日志与错误文案里的标识
        """
        plugin_id = self._spec.plugin_id or self._spec.class_name
        instance_id = self._spec.instance_id
        return f"{plugin_id}@{instance_id}" if instance_id else plugin_id

    @staticmethod
    def _resolve_declaration_type(kind: str) -> type:
        """
        按类名取出扩展声明类。
        :param kind: 声明类名
        :return: 声明类
        :raises ProtocolError: 类名不在契约模块内
        """
        declaration_type = _declaration_types().get(kind)
        if declaration_type is None:
            raise ProtocolError(f"未知的扩展声明类型: {kind}")
        return declaration_type

    def _make_impl(self, symbol: str):
        """
        为一条声明建出把调用派回子进程的实现代理。
        :param symbol: 子进程内的方法名
        :return: 可调用体，调用形状与进程内声明的 ``impl`` 一致
        """

        def _impl(**kwargs):
            return self.call(symbol, kwargs=kwargs)

        _impl.__name__ = symbol
        _impl.__qualname__ = f"{self._label()}.{symbol}"
        return _impl


def worker_path() -> Path:
    """
    :return: worker 脚本的绝对路径
    """
    return _WORKER_PATH
