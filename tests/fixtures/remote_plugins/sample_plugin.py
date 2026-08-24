"""进程外插件宿主的样例插件。

形状与 ``_PluginBase`` 的生命周期方法一致（``init_plugin``/``get_state``/
``stop_service`` 与 ``provides_*`` 声明钩子），但不继承它：``_PluginBase.__init__``
会构造数据库访问对象与事件管理器，子进程里没有宿主的连接与配置，构造即失败。
样例插件因此只保留跨进程契约真正涉及的那部分形状。

``host`` 属性由 worker 在实例化之后、``init_plugin`` 之前注入，插件经它反向调用
宿主的受限 API。
"""
import os
import sys
from typing import Any, List, Optional

from app.runtime.extensions.contract.declaration import ScheduleDeclaration


class SampleRemotePlugin:
    """
    覆盖跨进程插件宿主各条路径的样例插件。
    """

    plugin_name = "样例远程插件"
    plugin_desc = "进程外插件宿主的端到端验证插件"

    def __init__(self, plugin_id: Optional[str] = None, instance_id: Optional[str] = None):
        """
        :param plugin_id: 插件标识
        :param instance_id: 实例标识
        """
        self.plugin_id = plugin_id or self.__class__.__name__
        self.instance_id = instance_id or "default"
        self.host = None
        self._enabled = False
        self._counter = 0
        self._cron = "0 1 * * *"
        self._stopped = False

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #

    def init_plugin(self, config: dict = None):
        """
        生效配置。
        :param config: 配置字典
        """
        config = config or {}
        self._enabled = bool(config.get("enabled", False))
        self._counter = int(config.get("counter", 0))
        self._cron = config.get("cron") or "0 1 * * *"
        self._stopped = False

    def get_state(self) -> bool:
        """
        :return: 插件是否处于启用状态
        """
        return self._enabled

    def stop_service(self):
        """
        停止插件服务。
        """
        self._stopped = True

    def is_stopped(self) -> bool:
        """
        :return: 是否已停止
        """
        return self._stopped

    # ------------------------------------------------------------------ #
    # 业务方法
    # ------------------------------------------------------------------ #

    def echo(self, text: str, suffix: str = "") -> str:
        """
        原样回显，用于验证位置参数与关键字参数都能过进程边界。
        :param text: 回显文本
        :param suffix: 追加后缀
        :return: 拼接后的文本
        """
        return f"{text}{suffix}"

    def bump(self, step: int = 1) -> int:
        """
        累加实例内计数器，用于验证插件实例在子进程内常驻且保持状态。
        :param step: 步长
        :return: 累加后的计数
        """
        self._counter += step
        return self._counter

    def boom(self, message: str = "插件内部错误") -> None:
        """
        主动抛出异常，用于验证插件异常经协议映射回宿主。
        :param message: 异常文案
        """
        raise ValueError(message)

    # ------------------------------------------------------------------ #
    # 反向调用宿主
    # ------------------------------------------------------------------ #

    def save_and_read(self, key: str, value: Any) -> Any:
        """
        连续两次反向调用宿主：先写插件数据再读回，用于验证一次插件调用内
        可以交错多次宿主回调。
        :param key: 数据键
        :param value: 数据值
        :return: 读回的数据值
        """
        self.host.plugindata.save(key=key, value=value)
        return self.host.plugindata.get(key=key)

    def read_system_config(self, key: str) -> Any:
        """
        读取宿主系统配置。
        :param key: 配置键
        :return: 配置值
        """
        return self.host.systemconfig.get(key=key)

    def invoke_host(self, api: str, **kwargs) -> Any:
        """
        直接按名字发起一次宿主回调，绕过本地命名空间。

        白名单是否生效由宿主判定而不是由子进程自觉，这个方法用于让测试从
        「不可信的一侧」发起越权调用。
        :param api: 宿主 API 名
        :param kwargs: 调用参数
        :return: 宿主返回值
        """
        return self.host.invoke(api, **kwargs)

    def try_invoke_host(self, api: str, **kwargs) -> str:
        """
        发起一次宿主回调并把失败转成字符串返回，便于断言拒绝原因。
        :param api: 宿主 API 名
        :param kwargs: 调用参数
        :return: 成功时为 ``ok:<结果>``，失败时为 ``err:<原因>``
        """
        try:
            return f"ok:{self.host.invoke(api, **kwargs)}"
        except Exception as err:  # noqa: BLE001 - 样例插件刻意吞掉以便断言文案
            return f"err:{err}"

    # ------------------------------------------------------------------ #
    # 故障注入
    # ------------------------------------------------------------------ #

    def spin_forever(self) -> None:
        """
        永不返回的死循环，模拟失控插件。

        既不 sleep 也不做 IO：这类插件在宿主进程内会一直占着线程且无法中断，
        正是进程边界要隔离的形态。
        """
        while True:
            pass

    def crash_now(self) -> None:
        """
        立刻杀死自身进程，模拟插件把子进程带崩。

        用 ``os._exit`` 而不是抛异常：抛异常会被 worker 捕获并转成一条正常的
        错误响应，测不到「进程没了」这条路径。
        """
        os._exit(70)

    def noisy(self, text: str) -> str:
        """
        向 stdout 与 stderr 各写一行再返回，验证插件的输出不会污染协议通道。
        :param text: 输出文本
        :return: 原样返回的文本
        """
        print(f"stdout噪声:{text}")
        sys.stdout.write(f"未换行噪声:{text}")
        sys.stdout.flush()
        sys.stderr.write(f"stderr噪声:{text}\n")
        return text

    # ------------------------------------------------------------------ #
    # 声明式扩展点
    # ------------------------------------------------------------------ #

    def provides_schedules(self) -> List[ScheduleDeclaration]:
        """
        声明一条定时任务。
        :return: 定时任务声明列表
        """
        return [
            ScheduleDeclaration(
                job_id="sample_sync",
                name="样例同步",
                trigger="cron",
                trigger_args={"crontab": self._cron},
                kwargs={"scope": "all"},
                impl=self.scheduled_sync,
            )
        ]

    def scheduled_sync(self, scope: str = "") -> str:
        """
        定时任务声明所指向的实现。
        :param scope: 同步范围
        :return: 执行结果描述
        """
        self._counter += 100
        return f"synced:{scope}:{self._counter}"
