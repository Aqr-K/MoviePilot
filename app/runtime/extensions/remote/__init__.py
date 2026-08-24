"""进程外插件宿主。

把插件实例放进独立子进程执行，宿主经 RPC 驱动它。存在的理由与 ``fsproxy`` 同源：
**Python 无法中断已经跑起来的第三方代码，也无法强杀线程**，因此进程内的失控插件
（死循环、永不返回的阻塞调用、吃光线程池）没有任何回收手段。子进程可以被 SIGKILL，
故障因此从「不可处理的挂死」降级为「一次可捕获的调用失败」。

进程边界画在插件周围而不是 HTTP 层，是因为 HTTP 分片只会**复制**失控插件而不是
隔离它；判据见 ``docs/process-isolation-design.md``。

线路协议
--------

stdin/stdout 逐行 JSON，每行一条报文，``t`` 字段给出类型。**两个方向各持有独立的
``id`` 序列**，因此单对管道上既能跑「宿主→插件」的请求-响应，也能跑「插件→宿主」的
反向回调，两者任意交错也分得清谁是谁的响应::

    宿主 → worker  {"t": "hello", "protocol": 1, "spec": {...}, "host_apis": [...]}
    worker → 宿主  {"t": "ready", "ok": true, "pid": 1234}

    宿主 → worker  {"t": "call", "id": 1, "method": "sync", "args": [], "kwargs": {}}
    worker → 宿主  {"t": "hostcall", "id": 1, "api": "plugindata.get", "kwargs": {}}
    宿主 → worker  {"t": "hostresult", "id": 1, "ok": true, "result": {...}}
    worker → 宿主  {"t": "result", "id": 1, "ok": true, "result": "done"}

宿主的读循环在等待某个 ``result`` 期间遇到 ``hostcall`` 就地应答后继续等待。请求
严格串行（一个代理同时只有一个在途调用），所以等待中的 ``result`` 唯一。

失败一律以报文形式回报，不靠管道关闭表达：
``{"t": "result", "id": N, "ok": false, "error": "...", "errtype": "ValueError"}``。

三条设计约束
------------

1. **插件实例常驻子进程**，``init_plugin`` 之后的状态一直保留。进程一旦被回收状态
   即丢失，因此代理记住最后一次生效的配置，重启后的首个调用先重放 ``init_plugin``。
2. **宿主回调是一张显式的白名单数据表**（见 ``host_api``），不是属性反射。子进程里
   跑的是第三方代码，API 名与参数按不可信输入对待。
3. **协议通道与插件输出隔离**。worker 启动时把协议用的文件描述符复制一份独占，插件
   的 ``print`` 落到 stderr，撞不进协议通道。

跨进程的声明契约
----------------

``provides_*`` 交出的 ``XxxDeclaration`` 天然可分：数据字段原样序列化，``impl``
退化为符号名，宿主收到后建出一个把调用派回子进程的可调用体。以定时任务为例，
``CronTrigger`` 对象过不了进程边界，而「cron 加五段表达式」这样的数据过得去。
"""
from app.runtime.extensions.remote.host_api import (
    HOST_API_TABLE,
    HostApiError,
    HostApiGateway,
    HostApiSpec,
    ParamSpec,
)
from app.runtime.extensions.remote.protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    deserialize_declaration,
    serialize_declaration,
)
from app.runtime.extensions.remote.proxy import (
    DEFAULT_CALL_TIMEOUT,
    RemotePluginCrashed,
    RemotePluginError,
    RemotePluginProxy,
    RemotePluginSpec,
    RemotePluginTimeout,
    worker_path,
)

__all__ = [
    "DEFAULT_CALL_TIMEOUT",
    "HOST_API_TABLE",
    "HostApiError",
    "HostApiGateway",
    "HostApiSpec",
    "PROTOCOL_VERSION",
    "ParamSpec",
    "ProtocolError",
    "RemotePluginCrashed",
    "RemotePluginError",
    "RemotePluginProxy",
    "RemotePluginSpec",
    "RemotePluginTimeout",
    "deserialize_declaration",
    "serialize_declaration",
    "worker_path",
]
