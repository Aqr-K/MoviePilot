"""进程外插件反向调用宿主的受限 API 网关。

进程内的插件基类把整个 ``ChainBase``、事件管理器与各持久化访问对象都挂在
``self`` 上，插件想调什么就调什么。跨进程后这条路径必须收窄成一张**显式的数据表**：
子进程里跑的是第三方代码，送上来的 API 名与参数按不可信输入对待，只有表里
登记过的名字才可达，参数按登记的形状逐项校验后才交给实现。

表只描述「有哪些 API、各自收什么参数」，具体实现由构造时注入——网关因此不依赖
任何持久化或链路对象，测试可注入假后端，宿主装配时注入真实实现。表里登记了但
没注入实现的 API 不对外暴露，插件看不到也调不到。
"""
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

# 参数与返回值都必须能 JSON 序列化往返，这是跨进程的硬边界
_JSON_TYPES: Tuple[type, ...] = (bool, int, float, str, list, dict, type(None))

# 字符串型参数的长度上限，防止子进程用超长键撑爆宿主的存储
MAX_STRING_LENGTH = 4096

# 日志级别的合法取值
LOG_LEVELS = ("debug", "info", "warning", "error")


class HostApiError(Exception):
    """宿主拒绝了一次反向调用：API 不在白名单、参数不合登记形状或实现未注入。"""


@dataclass(frozen=True)
class ParamSpec:
    """
    一个宿主 API 参数的登记形状。

    :param name: 参数名，反向调用一律按关键字传参，位置参数不参与协议
    :param types: 允许的类型，取值须落在 JSON 可序列化的类型内
    :param required: 是否必填
    :param default: 选填参数的缺省值
    :param choices: 取值枚举，为 None 表示不限
    """

    name: str
    types: Tuple[type, ...]
    required: bool = True
    default: Any = None
    choices: Optional[Tuple[Any, ...]] = None


@dataclass(frozen=True)
class HostApiSpec:
    """
    一条宿主 API 的登记项。

    :param name: API 名，形如 ``命名空间.动作``，即插件侧看到的调用名
    :param params: 参数登记表
    :param summary: 该 API 做什么
    """

    name: str
    params: Tuple[ParamSpec, ...] = field(default_factory=tuple)
    summary: str = ""


# 开放给进程外插件的宿主能力，刻意只取最小可用子集：不含 ChainBase 全面，
# 不含任意属性反射。要新增能力就往这张表里加一条，加不进来的调不到
HOST_API_TABLE: Tuple[HostApiSpec, ...] = (
    HostApiSpec(
        name="systemconfig.get",
        params=(ParamSpec("key", (str,)),),
        summary="读取系统配置项",
    ),
    HostApiSpec(
        name="pluginconfig.get",
        params=(),
        summary="读取本插件实例的配置",
    ),
    HostApiSpec(
        name="pluginconfig.set",
        params=(ParamSpec("config", (dict,)),),
        summary="写入本插件实例的配置",
    ),
    HostApiSpec(
        name="plugindata.get",
        params=(ParamSpec("key", (str, type(None)), required=False),),
        summary="读取本插件实例的数据，键为空时取全部",
    ),
    HostApiSpec(
        name="plugindata.save",
        params=(ParamSpec("key", (str,)), ParamSpec("value", _JSON_TYPES)),
        summary="写入本插件实例的一项数据",
    ),
    HostApiSpec(
        name="plugindata.delete",
        params=(ParamSpec("key", (str,)),),
        summary="删除本插件实例的一项数据",
    ),
    HostApiSpec(
        name="event.send",
        params=(
            ParamSpec("etype", (str,)),
            ParamSpec("data", (dict,), required=False, default=None),
        ),
        summary="广播一个事件，不等待任何监听者",
    ),
    HostApiSpec(
        name="message.post",
        params=(
            ParamSpec("title", (str,)),
            ParamSpec("text", (str,), required=False, default=""),
        ),
        summary="发送一条用户通知",
    ),
    HostApiSpec(
        name="logger.log",
        params=(
            ParamSpec("level", (str,), choices=LOG_LEVELS),
            ParamSpec("message", (str,)),
        ),
        summary="写一条宿主日志",
    ),
)


class HostApiGateway:
    """
    宿主受限 API 的入口，负责白名单判定、参数校验与实现分发。
    """

    def __init__(self, handlers: Mapping[str, Callable[..., Any]],
                 table: Tuple[HostApiSpec, ...] = HOST_API_TABLE):
        """
        :param handlers: API 名到实现的映射，只有同时在表里登记且注入了实现的
                         API 才对外暴露
        :param table: 白名单数据表，默认取本模块登记的表
        :raises HostApiError: 注入了表外的实现
        """
        registry = {spec.name: spec for spec in table}
        unknown = set(handlers) - set(registry)
        if unknown:
            raise HostApiError(f"注入了白名单外的宿主 API 实现: {sorted(unknown)}")
        self._specs: Dict[str, HostApiSpec] = {
            name: registry[name] for name in handlers
        }
        self._handlers: Dict[str, Callable[..., Any]] = dict(handlers)

    @property
    def api_names(self) -> Tuple[str, ...]:
        """
        :return: 当前对外暴露的 API 名，握手时原样交给子进程
        """
        return tuple(sorted(self._specs))

    def invoke(self, api: Any, arguments: Any) -> Any:
        """
        执行一次反向调用。
        :param api: 子进程送来的 API 名
        :param arguments: 子进程送来的关键字参数
        :return: 实现的返回值，须能 JSON 序列化
        :raises HostApiError: API 不可达、参数不合登记形状或返回值过不了进程边界
        """
        if not isinstance(api, str):
            raise HostApiError("宿主 API 名必须是字符串")
        spec = self._specs.get(api)
        if spec is None:
            raise HostApiError(f"宿主 API 不在白名单内: {api}")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise HostApiError(f"{api} 的参数必须是对象")

        kwargs = self._validate(spec, arguments)
        result = self._handlers[api](**kwargs)
        return self._validate_result(api, result)

    @staticmethod
    def _validate(spec: HostApiSpec, arguments: Mapping[str, Any]) -> Dict[str, Any]:
        """
        按登记形状校验一次调用的参数。
        :param spec: API 登记项
        :param arguments: 送来的参数
        :return: 校验通过的关键字参数
        :raises HostApiError: 有多余参数、缺必填参数或类型取值不符
        """
        declared = {param.name for param in spec.params}
        extra = set(arguments) - declared
        if extra:
            raise HostApiError(f"{spec.name} 不接受参数: {sorted(extra)}")

        kwargs: Dict[str, Any] = {}
        for param in spec.params:
            if param.name not in arguments:
                if param.required:
                    raise HostApiError(f"{spec.name} 缺少必填参数: {param.name}")
                kwargs[param.name] = param.default
                continue
            value = arguments[param.name]
            # bool 是 int 的子类，登记 int 的参数不应放行 True
            if isinstance(value, bool) and bool not in param.types:
                raise HostApiError(f"{spec.name} 的参数 {param.name} 类型不符")
            if not isinstance(value, param.types):
                raise HostApiError(
                    f"{spec.name} 的参数 {param.name} 类型不符: "
                    f"期望 {[t.__name__ for t in param.types]}，收到 {type(value).__name__}"
                )
            if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
                raise HostApiError(f"{spec.name} 的参数 {param.name} 超过长度上限")
            if param.choices is not None and value not in param.choices:
                raise HostApiError(
                    f"{spec.name} 的参数 {param.name} 取值不合法: {value}"
                )
            kwargs[param.name] = value
        return kwargs

    @staticmethod
    def _validate_result(api: str, result: Any) -> Any:
        """
        校验返回值能过进程边界。

        实现返回了 ORM 行、``Path`` 这类只在宿主进程内成立的对象时，错误应当在
        宿主这一侧就判出来，而不是等到写管道时炸在读循环里。
        :param api: API 名
        :param result: 实现的返回值
        :return: 原样返回
        :raises HostApiError: 返回值无法 JSON 序列化
        """
        try:
            json.dumps(result, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as err:
            raise HostApiError(f"{api} 的返回值过不了进程边界: {err}") from err
        return result
