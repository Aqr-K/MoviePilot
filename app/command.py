import copy
import threading
import traceback
from typing import Any, Union, Dict, List, Optional, Set, Tuple

from app.chain import ChainBase
from app.chain.download import DownloadChain
from app.chain.message import MessageChain
from app.chain.site import SiteChain
from app.chain.skills import SkillsChain
from app.chain.subscribe import SubscribeChain
from app.chain.system import SystemChain
from app.chain.transfer import TransferChain
from app.runtime.events import Event as ManagerEvent, eventmanager, Event
from app.runtime.extensions.plugin_instance import is_default_instance_key, plugin_id_of
from app.runtime.extensions.plugin_manager import PluginManager
from app.runtime.extensions.plugin_spi import get_plugin_commands
from app.application.messaging.message import MessageHelper
from app.runtime.thread import ThreadHelper
from app.runtime.log import logger
from app.scheduler import Scheduler
from app.schemas import Notification, CommandRegisterEventData
from app.schemas.types import EventType, MessageChannel, ChainEventType
from app.foundation.reflection import ObjectUtils
from app.foundation.singleton import Singleton
from app.foundation.collections import DictUtils


class CommandChain(ChainBase):
    pass


def _finish_command_processing_status(status: Optional[dict], user_id: Optional[str] = None) -> None:
    """
    命令执行完成后通过消息模块收口渠道处理状态。
    """
    if not status:
        return
    CommandChain().finish_message_processing_status(
        status=status,
        userid=user_id,
    )


class Command(metaclass=Singleton):
    """
    全局命令管理，消费事件
    """

    def __init__(self):
        # 插件管理器
        super().__init__()
        # 注册的命令集合
        self._registered_commands = {}
        # 所有命令集合
        self._commands = {}
        # 内建命令集合
        self._preset_commands = {
            "/cookiecloud": {
                "id": "cookiecloud",
                "type": "scheduler",
                "description": "同步站点",
                "category": "站点",
            },
            "/sites": {
                "func": SiteChain().remote_list,
                "description": "管理站点",
                "category": "站点",
                "data": {},
            },
            "/mediaserver_sync": {
                "id": "mediaserver_sync",
                "type": "scheduler",
                "description": "同步媒体服务器",
                "category": "管理",
            },
            "/subscribes": {
                "func": SubscribeChain().remote_list,
                "description": "管理订阅",
                "category": "订阅",
                "data": {},
            },
            "/downloading": {
                "func": DownloadChain().remote_downloading,
                "description": "正在下载",
                "category": "管理",
                "data": {},
            },
            "/transfer": {
                "id": "transfer",
                "type": "scheduler",
                "description": "下载文件整理",
                "category": "管理",
            },
            "/redo": {
                "func": TransferChain().remote_transfer,
                "description": "手动整理",
                "data": {},
            },
            "/clear_cache": {
                "func": SystemChain().remote_clear_cache,
                "description": "清理缓存",
                "category": "管理",
                "data": {},
            },
            "/restart": {
                "func": SystemChain().restart,
                "description": "重启系统",
                "category": "管理",
                "data": {},
            },
            "/version": {
                "func": SystemChain().version,
                "description": "当前版本",
                "category": "管理",
                "data": {},
            },
            "/clear_session": {
                "func": MessageChain().remote_clear_session,
                "description": "清除会话",
                "category": "管理",
                "data": {},
            },
            "/stop_agent": {
                "func": MessageChain().remote_stop_agent,
                "description": "停止推理",
                "category": "管理",
                "data": {},
            },
            "/session_status": {
                "func": MessageChain().remote_session_status,
                "description": "会话状态",
                "category": "智能体",
                "data": {},
            },
            "/skills": {
                "func": SkillsChain().remote_manage,
                "description": "管理技能",
                "category": "智能体",
                "data": {},
            },
        }
        # 插件命令集合
        self._plugin_commands = {}
        # 其他命令集合
        self._other_commands = {}
        # 上次构建时已告警的命令重叠，用于重复构建时抑制同一组提示
        self._warned_command_overlaps: Set[Tuple[str, str, str]] = set()
        # 初始化锁
        self._rlock = threading.RLock()
        # 插件管理
        self.pluginmanager = PluginManager()
        # 定时服务管理
        self.scheduler = Scheduler()
        # 消息管理器
        self.messagehelper = MessageHelper()
        # 初始化命令
        self.init_commands()

    def init_commands(self, pid: Optional[str] = None) -> None:
        """
        初始化菜单命令
        """
        # 使用线程池提交后台任务，避免引起阻塞
        ThreadHelper().submit(self.__init_commands_background, pid)

    def __init_commands_background(self, pid: Optional[str] = None) -> None:
        """
        后台初始化菜单命令
        """
        try:
            with self._rlock:
                logger.debug("Acquired lock for initializing commands in background.")
                self._plugin_commands = self.__build_plugin_commands(pid)
                self._commands = {
                    **self._preset_commands,
                    **self._plugin_commands,
                    **self._other_commands,
                }

                # 强制触发注册
                force_register = False
                # 触发事件允许可以拦截和调整命令
                event, initial_commands = self.__trigger_register_commands_event()

                if event and event.event_data:
                    # 如果事件返回有效的 event_data，使用事件中调整后的命令
                    event_data: CommandRegisterEventData = event.event_data
                    # 如果事件被取消，跳过命令注册
                    if event_data.cancel:
                        logger.debug(
                            f"Command initialization canceled by event: {event_data.source}"
                        )
                        return
                    # 如果拦截源与插件标识一致时，这里认为需要强制触发注册
                    if pid is not None and pid == event_data.source:
                        force_register = True
                    initial_commands = event_data.commands or {}
                    logger.debug(
                        f"Registering command count from event: {len(initial_commands)}"
                    )
                else:
                    logger.debug(
                        f"Registering initial command count: {len(initial_commands)}"
                    )

                # initial_commands 必须是 self._commands 的子集
                filtered_initial_commands = DictUtils.filter_keys_to_subset(
                    initial_commands, self._commands
                )
                # 如果 filtered_initial_commands 为空，则跳过注册
                if not filtered_initial_commands and not force_register:
                    logger.debug("Filtered commands are empty, skipping registration.")
                    return

                # 对比调整后的命令与当前命令
                if (
                    filtered_initial_commands != self._registered_commands
                    or force_register
                ):
                    logger.debug(
                        "Command set has changed or force registration is enabled."
                    )
                    self._registered_commands = filtered_initial_commands
                    CommandChain().register_commands(commands=filtered_initial_commands)
                else:
                    logger.debug(
                        "Command set unchanged, skipping broadcast registration."
                    )
        except Exception as e:
            logger.error(
                f"Error occurred during command initialization in background: {e}",
                exc_info=True,
            )

    def __trigger_register_commands_event(self) -> tuple[Optional[Event], dict]:
        """
        触发事件，允许调整命令数据
        """

        def add_commands(source, command_type):
            """
            添加命令集合
            """
            for cmd, command in source.items():
                if not command.get("show", True):
                    continue

                command_data = {
                    "type": command_type,
                    "description": command.get("description"),
                    "category": command.get("category"),
                }
                # 如果有 pid，则添加到命令数据中
                plugin_id = command.get("pid")
                if plugin_id:
                    command_data["pid"] = plugin_id
                commands[cmd] = command_data

        # 初始化命令字典
        commands: Dict[str, dict] = {}
        add_commands(self._preset_commands, "preset")
        add_commands(self._plugin_commands, "plugin")
        add_commands(self._other_commands, "other")

        # 触发事件允许可以拦截和调整命令
        event_data = CommandRegisterEventData(
            commands=commands, origin="CommandChain", service=None
        )
        event = eventmanager.send_event(ChainEventType.CommandRegister, event_data)
        return event, commands

    def __build_plugin_commands(self, _: Optional[str] = None) -> Dict[str, dict]:
        """
        构建插件命令

        菜单里一条命令只占一个条目，条目的描述与归属取自选中的声明来源；同一来源重复声明
        按最后一次声明更新。多个来源声明同一条命令时，归属插件按声明顺序取先到者，该插件
        内优先取默认实例，因此分身不会顶掉默认实例的菜单条目。

        菜单条目不限制执行范围：命令按事件类型投递，订阅了该事件且已启用的实例都会收到。

        :return: {命令: 命令条目}
        """
        # 为了保证命令顺序的一致性，目前这里没有直接使用 pid 获取单一插件命令，后续如果存在性能问题，可以考虑优化这里的逻辑
        declarations: Dict[str, Dict[str, dict]] = {}
        for command in get_plugin_commands(self.pluginmanager.running_plugins):
            cmd = command.get("cmd")
            if not cmd:
                continue
            declarations.setdefault(cmd, {})[command.get("pid")] = command
        plugin_commands = {}
        overlaps = set()
        for cmd, by_owner in declarations.items():
            owner = self.__elect_command_owner(list(by_owner))
            overlaps.update((cmd, owner, other) for other in by_owner if other != owner)
            command = by_owner[owner]
            plugin_commands[cmd] = {
                "pid": owner,
                "func": self.send_plugin_event,
                "description": command.get("desc"),
                "category": command.get("category"),
                "show": command.get("show", True),
                "data": {
                    "etype": command.get("event"),
                    "data": command.get("data"),
                },
            }
        self.__warn_command_overlaps(overlaps)
        return plugin_commands

    @staticmethod
    def __elect_command_owner(owners: List[str]) -> str:
        """
        在声明同一条命令的来源中选出菜单归属

        先按声明顺序定下归属插件，再在该插件内优先取默认实例。

        :param owners: 声明该命令的实例键，按声明顺序排列
        :return: 菜单条目归属的实例键
        """
        elected_plugin = plugin_id_of(owners[0])
        same_plugin = [owner for owner in owners if plugin_id_of(owner) == elected_plugin]
        return next(
            (owner for owner in same_plugin if is_default_instance_key(owner)),
            same_plugin[0],
        )

    def __warn_command_overlaps(self, overlaps: Set[Tuple[str, str, str]]) -> None:
        """
        就多个来源声明同一条命令留下告警，重复构建时同一组重叠只提示一次

        :param overlaps: (命令, 菜单归属实例键, 未占用菜单的实例键) 集合
        """
        warned = getattr(self, "_warned_command_overlaps", None)
        if warned is None:
            warned = set()
        for overlap in sorted(overlaps - warned):
            cmd, owner, other = overlap
            logger.warning(
                f"插件命令重叠：{cmd} 的菜单条目取自 {owner}，{other} 的声明不再单独显示；"
                f"命令事件仍按各自的事件订阅投递"
            )
        self._warned_command_overlaps = overlaps

    def __run_command(
        self,
        command: Dict[str, any],
        data_str: Optional[str] = "",
        channel: MessageChannel = None,
        source: Optional[str] = None,
        userid: Union[str, int] = None,
    ):
        """
        运行定时服务
        """
        if command.get("type") == "scheduler":
            # 定时服务
            if userid:
                CommandChain().post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        title=f"开始执行 {command.get('description')} ...",
                        userid=userid,
                    )
                )

            # 执行定时任务
            self.scheduler.start(job_id=command.get("id"))

            if userid:
                CommandChain().post_message(
                    Notification(
                        channel=channel,
                        source=source,
                        title=f"{command.get('description')} 执行完成",
                        userid=userid,
                    )
                )
        else:
            # 命令
            cmd_data = copy.deepcopy(command["data"]) if command.get("data") else {}
            args_num = ObjectUtils.arguments(command["func"])
            if args_num > 0:
                if cmd_data:
                    # 有内置参数直接使用内置参数
                    data = cmd_data.get("data") or {}
                    data["channel"] = channel
                    data["source"] = source
                    data["user"] = userid
                    if data_str:
                        data["arg_str"] = data_str
                    cmd_data["data"] = data
                    command["func"](**cmd_data)
                elif args_num == 3:
                    # 没有输入参数，只输入渠道来源、用户ID和消息来源
                    command["func"](channel, userid, source)
                elif args_num > 3:
                    # 多个输入参数：用户输入、用户ID
                    command["func"](data_str, channel, userid, source)
            else:
                # 没有参数
                command["func"]()

    def get_commands(self):
        """
        获取命令列表
        """
        if not self._commands:
            with self._rlock:
                if not self._commands:
                    self._commands = {
                        **self._preset_commands,
                        **self._plugin_commands,
                        **self._other_commands,
                    }
        return self._commands

    def get(self, cmd: str) -> Any:
        """
        获取命令
        """
        return self._commands.get(cmd, {})

    def register(
        self,
        cmd: str,
        func: Any,
        data: Optional[dict] = None,
        desc: Optional[str] = None,
        category: Optional[str] = None,
        show: bool = True,
    ) -> None:
        """
        注册单个命令
        """
        # 单独调用的，统一注册到其他
        self._other_commands[cmd] = {
            "func": func,
            "description": desc,
            "category": category,
            "data": data or {},
            "show": show,
        }

    def execute(
        self,
        cmd: str,
        data_str: Optional[str] = "",
        channel: MessageChannel = None,
        source: Optional[str] = None,
        userid: Union[str, int] = None,
    ) -> None:
        """
        执行命令
        """
        command = self.get(cmd)
        if command:
            try:
                if userid:
                    logger.info(
                        f"用户 {userid} 开始执行：{command.get('description')} ..."
                    )
                else:
                    logger.info(f"开始执行：{command.get('description')} ...")

                # 执行命令
                self.__run_command(
                    command,
                    data_str=data_str,
                    channel=channel,
                    source=source,
                    userid=userid,
                )

                if userid:
                    logger.info(f"用户 {userid} {command.get('description')} 执行完成")
                else:
                    logger.info(f"{command.get('description')} 执行完成")
            except Exception as err:
                logger.error(
                    f"执行命令 {cmd} 出错：{str(err)} - {traceback.format_exc()}"
                )
                self.messagehelper.put(
                    title=f"执行命令 {cmd} 出错", message=str(err), role="system"
                )

    @staticmethod
    def send_plugin_event(etype: EventType, data: dict) -> None:
        """
        发送插件命令事件

        按事件类型广播，订阅该事件且已启用的插件实例都会收到，投递范围不受菜单条目归属限制。

        :param etype: 命令声明的事件类型
        :param data: 命令声明的事件数据
        """
        eventmanager.send_event(etype, data)

    @eventmanager.register(EventType.CommandExcute)
    def command_event(self, event: ManagerEvent) -> None:
        """
        注册命令执行事件
        event_data: {
            "cmd": "/xxx args"
        }
        """
        # 命令参数
        event_str = event.event_data.get("cmd")
        # 消息渠道
        event_channel = event.event_data.get("channel")
        # 消息来源
        event_source = event.event_data.get("source")
        # 消息用户
        event_user = event.event_data.get("user")
        try:
            if event_str:
                cmd = event_str.split()[0]
                args = " ".join(event_str.split()[1:])
                if self.get(cmd):
                    self.execute(
                        cmd=cmd,
                        data_str=args,
                        channel=event_channel,
                        source=event_source,
                        userid=event_user,
                    )
        finally:
            _finish_command_processing_status(
                event.event_data.get("processing_status"),
                user_id=event_user,
            )

    @eventmanager.register(EventType.ModuleReload)
    def module_reload_event(self, _: ManagerEvent) -> None:
        """
        注册模块重载事件
        """
        # 发生模块重载时，重新注册命令
        self.init_commands()
