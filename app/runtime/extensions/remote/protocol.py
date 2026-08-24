"""进程外插件宿主的线路协议。

**本模块只依赖标准库**：worker 侧按文件路径直接加载它（不走 ``import app.*``），
一份定义同时供宿主与 worker 使用，避免两侧各写一份常量后悄悄漂移。

线路格式为 stdin/stdout 逐行 JSON，每行一条报文，``t`` 字段给出报文类型。

握手（宿主 → worker，随后 worker → 宿主）::

    {"t": "hello", "protocol": 1, "spec": {...}, "host_apis": ["plugindata.save", ...]}
    {"t": "ready", "ok": true, "pid": 1234, "plugin": "SampleRemotePlugin"}

调用（宿主 → worker，``id`` 由宿主发号）::

    {"t": "call", "id": 1, "method": "bump", "args": [], "kwargs": {"step": 2}, "decl": false}
    {"t": "result", "id": 1, "ok": true, "result": 3}
    {"t": "result", "id": 1, "ok": false, "error": "...", "errtype": "ValueError"}

反向回调（worker → 宿主，``id`` 由 worker 独立发号）::

    {"t": "hostcall", "id": 1, "api": "plugindata.save", "kwargs": {"key": "k", "value": 1}}
    {"t": "hostresult", "id": 1, "ok": true, "result": true}
    {"t": "hostresult", "id": 1, "ok": false, "error": "...", "errtype": "HostApiError"}

两个方向各自持有独立的 ``id`` 序列，因此一条管道上的报文按 ``t`` 分派即可区分
「这是对我请求的响应」与「这是对方发起的新请求」；宿主的读循环在等待某个
``result`` 期间遇到 ``hostcall`` 就地应答后继续等待，两种报文可以任意交错。

声明报文把一条 ``XxxDeclaration`` 拆成两部分：数据字段原样序列化，``impl``
退化为符号名，宿主收到后按符号名建出一个把调用派回子进程的可调用体。
"""
import json
from typing import Any, Callable, Dict, Mapping

# 协议版本号，两侧握手时比对
PROTOCOL_VERSION = 1

# 报文类型
MSG_HELLO = "hello"
MSG_READY = "ready"
MSG_CALL = "call"
MSG_RESULT = "result"
MSG_HOSTCALL = "hostcall"
MSG_HOSTRESULT = "hostresult"

# 声明中承载实现引用的字段名，该字段不参与序列化
IMPL_FIELD = "impl"

# 单条报文的字节上限。子进程里跑的是第三方代码，其输出按不可信输入对待，
# 不设上限时一条畸形报文就能把宿主的内存吃光
MAX_MESSAGE_BYTES = 8 * 1024 * 1024


class ProtocolError(Exception):
    """报文不合协议：类型未知、字段缺失或承载了过不了进程边界的对象。"""


def encode(message: Mapping[str, Any]) -> bytes:
    """
    把一条报文编码成可写入管道的一行字节。
    :param message: 报文字典
    :return: 以换行结尾的 UTF-8 字节串
    :raises ProtocolError: 报文含无法 JSON 序列化的对象或超出长度上限
    """
    try:
        line = json.dumps(message, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as err:
        raise ProtocolError(f"报文无法序列化: {err}") from err
    payload = (line + "\n").encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"报文超过 {MAX_MESSAGE_BYTES} 字节上限")
    return payload


def decode(line: bytes) -> Dict[str, Any]:
    """
    把管道上读到的一行解码成报文。
    :param line: 一行字节
    :return: 报文字典
    :raises ProtocolError: 该行不是合法 JSON 对象或超出长度上限
    """
    if len(line) > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"报文超过 {MAX_MESSAGE_BYTES} 字节上限")
    try:
        message = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise ProtocolError(f"报文不是合法 JSON: {err}") from err
    if not isinstance(message, dict):
        raise ProtocolError("报文必须是 JSON 对象")
    return message


def jsonable(value: Any) -> Any:
    """
    把声明字段的值转换成可 JSON 序列化的等价形状。

    只放行纯数据：``MappingProxyType`` 与元组是声明里常见的不可变容器，分别
    退化为字典与列表；其余非 JSON 类型一律判为过不了进程边界。
    :param value: 字段值
    :return: 等价的 JSON 数据
    :raises ProtocolError: 该值不是纯数据
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(item) for item in value]
    raise ProtocolError(f"声明字段含过不了进程边界的对象: {type(value).__name__}")


def serialize_declaration(declaration: Any) -> Dict[str, Any]:
    """
    把一条扩展声明拆成握手报文。

    数据字段原样序列化，``impl`` 只留下符号名——可调用对象本身过不去，而对端
    按同名方法自行响应即可还原调用。
    :param declaration: 扩展声明实例，须是 dataclass
    :return: ``{"kind": 类名, "impl": 符号名或 None, "fields": {...}}``
    :raises ProtocolError: 传入的不是声明，或字段含非纯数据
    """
    fields = getattr(type(declaration), "__dataclass_fields__", None)
    if not fields:
        raise ProtocolError(f"不是扩展声明: {type(declaration).__name__}")

    impl_symbol = None
    payload: Dict[str, Any] = {}
    for name in fields:
        value = getattr(declaration, name)
        if name == IMPL_FIELD:
            if value is None:
                continue
            impl_symbol = getattr(value, "__name__", None)
            if not impl_symbol:
                raise ProtocolError("声明的 impl 没有可寻址的符号名")
            continue
        payload[name] = jsonable(value)
    return {"kind": type(declaration).__name__, IMPL_FIELD: impl_symbol, "fields": payload}


def deserialize_declaration(payload: Mapping[str, Any],
                            resolve_kind: Callable[[str], type],
                            impl_factory: Callable[[str], Callable]) -> Any:
    """
    把握手报文还原成宿主侧的扩展声明。

    ``impl`` 由 ``impl_factory`` 按符号名建出：还原的不是原对象，而是一个把调用
    派回子进程的可调用体，对宿主而言调用形状与进程内声明一字不差。
    :param payload: 声明报文
    :param resolve_kind: 按类名取出声明类，取不到时应抛异常
    :param impl_factory: 按符号名建出实现代理
    :return: 扩展声明实例
    :raises ProtocolError: 报文缺字段、类名不认识或字段不属于该声明
    """
    kind = payload.get("kind")
    if not isinstance(kind, str):
        raise ProtocolError("声明报文缺少 kind")
    fields = payload.get("fields")
    if not isinstance(fields, Mapping):
        raise ProtocolError("声明报文缺少 fields")

    declaration_type = resolve_kind(kind)
    declared = getattr(declaration_type, "__dataclass_fields__", {})
    kwargs: Dict[str, Any] = {}
    for name, value in fields.items():
        if name not in declared or name == IMPL_FIELD:
            raise ProtocolError(f"{kind} 没有字段 {name}")
        kwargs[name] = _restore_field(declared[name], value)

    impl_symbol = payload.get(IMPL_FIELD)
    if impl_symbol is not None:
        if not isinstance(impl_symbol, str):
            raise ProtocolError("声明报文的 impl 不是符号名")
        kwargs[IMPL_FIELD] = impl_factory(impl_symbol)
    return declaration_type(**kwargs)


def _restore_field(field: Any, value: Any) -> Any:
    """
    按字段默认值的容器形状还原 JSON 数据。

    声明里的容器一律是不可变形状（``MappingProxyType`` 或元组），默认值本身
    就说明了该用哪一种，因此不必解析类型注解。
    :param field: dataclass 字段描述
    :param value: JSON 数据
    :return: 还原后的字段值
    """
    default = getattr(field, "default", None)
    if isinstance(default, Mapping) and isinstance(value, dict):
        from types import MappingProxyType

        return MappingProxyType(value)
    if isinstance(default, tuple) and isinstance(value, list):
        return tuple(value)
    return value
