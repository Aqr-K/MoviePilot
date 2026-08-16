from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Any, List, Dict, Tuple, Optional, Type

from app.chain import ChainBase
from app.core.config import settings
from app.core.event import EventManager
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID, normalize_instance_id
from app.db.oper.pluginconfig import PluginConfigOper
from app.db.oper.plugindata import PluginDataOper
from app.db.oper.systemconfig import SystemConfigOper
from app.helper.message import MessageHelper
from app.runtime.extensions.plugin_instance import instance_key
from app.schemas import Notification, NotificationType, MessageChannel


class PluginChian(ChainBase):
    """
    插件处理链
    """
    pass


class _PluginBase(metaclass=ABCMeta):
    """
    插件模块基类，通过继续该类实现插件功能
    除内置属性外，还有以下方法可以扩展或调用：
    - stop_service() 停止插件服务
    - get_config() 获取配置信息
    - update_config() 更新配置信息
    - init_plugin() 生效配置信息
    - get_data_path() 获取插件数据保存目录
    """
    # 插件名称
    plugin_name: Optional[str] = ""
    # 插件描述
    plugin_desc: Optional[str] = ""
    # 插件顺序
    plugin_order: Optional[int] = 9999

    # 插件标识，缺省取插件类名
    _plugin_id: Optional[str] = None
    # 实例标识，缺省为默认实例
    _instance_id: str = DEFAULT_INSTANCE_ID

    def __init__(self, plugin_id: Optional[str] = None, instance_id: Optional[str] = None):
        """
        :param plugin_id: 插件标识，缺省取插件类名
        :param instance_id: 实例标识，缺省为默认实例
        """
        # 实例身份，配置、数据与数据目录都按它寻址
        self._plugin_id = plugin_id or self.__class__.__name__
        self._instance_id = normalize_instance_id(instance_id)
        # 插件数据
        self.plugindata = PluginDataOper()
        # 插件配置
        self.pluginconfig = PluginConfigOper()
        # 处理链
        self.chain = PluginChian()
        # 系统配置
        self.systemconfig = SystemConfigOper()
        # 系统消息
        self.systemmessage = MessageHelper()
        # 事件管理器
        self.eventmanager = EventManager()

    @property
    def plugin_id(self) -> str:
        """
        获取插件标识
        """
        return self._plugin_id or self.__class__.__name__

    @property
    def instance_id(self) -> str:
        """
        获取实例标识
        """
        return self._instance_id or DEFAULT_INSTANCE_ID

    @property
    def instance_key(self) -> str:
        """
        获取实例键

        事件定向投递、接口路由与定时服务都以实例键定位一个实例；默认实例的实例键即插件标识。

        向框架登记「本实例」时一律传本属性，不要传 self.plugin_id 或 self.__class__.__name__：
        裸插件标识只解析到默认实例，分身实例用它登记的插件输入会话，用户回复会被投递给默认
        实例而不是自己。典型场景是
        `plugin_input_interaction_manager.create_or_replace(..., plugin_id=self.instance_key, ...)`。
        """
        return instance_key(self.plugin_id, self.instance_id)

    @abstractmethod
    def init_plugin(self, config: dict = None):
        """
        生效配置信息
        :param config: 配置信息字典
        """
        pass

    def get_name(self) -> str:
        """
        获取插件名称
        :return: 插件名称
        """
        return self.plugin_name

    @abstractmethod
    def get_state(self) -> bool:
        """
        获取插件运行状态
        """
        pass

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """
        注册插件远程命令
        [{
            "cmd": "/xx",
            "event": EventType.xx,
            "desc": "名称",
            "category": "分类，需要注册到Wechat时必须有分类",
            "data": {}
        }]
        """
        pass

    @staticmethod
    def get_render_mode() -> Tuple[str, Optional[str]]:
        """
        获取插件渲染模式
        :return: 1、渲染模式，支持：vue/vuetify，默认vuetify；2、vue模式下编译后文件的相对路径，默认为`dist/asserts`，vuetify模式下为None
        """
        return "vuetify", None

    @abstractmethod
    def get_api(self) -> List[Dict[str, Any]]:
        """
        注册插件API
        [{
            "path": "/xx",
            "endpoint": self.xxx,
            "methods": ["GET", "POST"],
            "auth: "apikey",  # 鉴权类型：apikey/bear
            "summary": "API名称",
            "description": "API说明"
        }]
        """
        pass

    @abstractmethod
    def get_form(self) -> Tuple[Optional[List[dict]], Dict[str, Any]]:
        """
        拼装插件配置页面，插件配置页面使用Vuetify组件拼装，参考：https://vuetifyjs.com/
        :return: 1、页面配置（vuetify模式）或 None（vue模式）；2、默认数据结构
        """
        pass

    @abstractmethod
    def get_page(self) -> Optional[List[dict]]:
        """
        拼装插件详情页面，需要返回页面配置，同时附带数据
        插件详情页面使用Vuetify组件拼装，参考：https://vuetifyjs.com/
        :return: 页面配置（vuetify模式）或 None（vue模式）
        """
        pass

    def get_service(self) -> List[Dict[str, Any]]:
        """
        注册插件公共服务
        [{
            "id": "服务ID",
            "name": "服务名称",
            "trigger": "触发器：cron/interval/date/CronTrigger.from_crontab()",
            "func": self.xxx,
            "kwargs": {} # 定时器参数
        }]
        """
        pass

    def get_dashboard(self, key: str, **kwargs) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], Optional[List[dict]]]]:
        """
        获取插件仪表盘页面，需要返回：1、仪表板col配置字典；2、全局配置（布局、自动刷新等）；3、仪表板页面元素配置含数据json（vuetify）或 None（vue模式）
        1、col配置参考：
        {
            "cols": 12, "md": 6
        }
        2、全局配置参考：
        {
            "refresh": 10, // 自动刷新时间，单位秒
            "border": True, // 是否显示边框，默认True，为False时取消组件边框和边距，由插件自行控制
            "title": "组件标题", // 组件标题，如有将显示该标题，否则显示插件名称
            "subtitle": "组件子标题", // 组件子标题，缺省时不展示子标题
        }
        3、vuetify模式页面配置使用Vuetify组件拼装，参考：https://vuetifyjs.com/；vue模式为None

        kwargs参数可获取的值：1、user_agent：浏览器UA

        :param key: 仪表盘key，根据指定的key返回相应的仪表盘数据，缺省时返回一个固定的仪表盘数据（兼容旧版）
        """
        pass

    def get_dashboard_meta(self) -> Optional[List[Dict[str, str]]]:
        """
        获取插件仪表盘元信息
        返回示例：
            [{
                "key": "dashboard1", // 仪表盘的key，在当前插件范围唯一
                "name": "仪表盘1" // 仪表盘的名称
            }, {
                "key": "dashboard2",
                "name": "仪表盘2"
            }]
        """
        pass

    def get_auth_providers(self) -> List[Dict[str, Any]]:
        """
        声明插件提供的登录认证入口。

        返回示例：
        [{
            "id": "oidc",
            "name": "OIDC 登录",
            "icon": "mdi-openid",
            "component": "AuthPage",
            "enabled": True
        }]
        """
        pass

    def get_module(self) -> Dict[str, Any]:
        """
        获取插件模块声明，用于胁持系统模块实现（方法名：方法实现）
        {
            "id1": self.xxx1,
            "id2": self.xxx2,
        }

        该方式已废弃，无契约校验且卸载不可回收，请改用 provides_modules()
        """
        pass

    def provides_modules(self) -> List[Any]:
        """
        获取插件声明的系统模块，注册后与内建模块同权参与分发

        元素可以是模块类，也可以是 ProvidedModule 声明（自定义模块标识或构造方式）。
        模块类需继承 app.modules._ModuleBase 并实现完整契约，未通过校验的会被拒绝注册。
        [ProvidedModule(MyStorageModule), MyNotificationModule]

        :return: 模块声明列表
        """
        return []

    def provides_downloaders(self) -> List[Any]:
        """
        声明本插件提供的下载器模块

        与 provides_modules() 走同一条注册通道，额外校验模块类型为 ModuleType.Downloader，
        类型不符的声明在注册前被拒绝而不是等到分发时才发现。

        :return: 模块声明列表
        """
        return []

    def provides_mediaservers(self) -> List[Any]:
        """
        声明本插件提供的媒体服务器模块

        与 provides_modules() 走同一条注册通道，额外校验模块类型为 ModuleType.MediaServer。

        :return: 模块声明列表
        """
        return []

    def provides_notifications(self) -> List[Any]:
        """
        声明本插件提供的消息渠道模块

        与 provides_modules() 走同一条注册通道，额外校验模块类型为 ModuleType.Notification。
        渠道的按钮、富文本等能力另经 provides_channel_capabilities() 声明。

        :return: 模块声明列表
        """
        return []

    def provides_data_sources(self) -> List[Any]:
        """
        声明本插件提供的媒体识别数据源模块

        与 provides_modules() 走同一条注册通道，额外校验模块类型为
        ModuleType.MediaRecognize。

        :return: 模块声明列表
        """
        return []

    def provides_storages(self) -> List[Type]:
        """
        声明本插件提供的存储实现，注册后与内建存储同权参与存储分发

        与 provides_modules() 走同一条注册通道，额外校验模块类型为 ModuleType.Storage。
        返回继承自 app.modules.storages.StorageBase 的存储【类】列表（非实例），类上的
        schema 属性即该存储的标识，也是模块子类型。标识可以是字符串，不必是 StorageSchema
        枚举成员——枚举是内建存储的封闭集合，插件按字符串取名即可。

        存储按标识精确分发，同一标识只能有一个模块在运行：与内建存储或其它来源的存储
        重名时注册被拒，先到者胜。

        【多实例】同一插件的多个实例声明同一个存储类时后者被拒；需要多份配置的存储，
        让每个实例声明各自 schema 不同的存储类。

        :return: 存储类列表
        """
        return []

    def provides_channel_capabilities(self) -> List[Any]:
        """
        声明本插件提供的消息渠道能力

        返回 app.schemas.message.ChannelCapabilities 列表。系统据此决定是否向该渠道下发
        按钮、Markdown、文件等内容；未声明的渠道按最保守的兜底值处理，富交互会被降级。
        声明可覆盖内建渠道的能力，插件停用时自动恢复内建取值。

        :return: 渠道能力列表
        """
        return []

    def get_actions(self) -> List[Dict[str, Any]]:
        """
        获取插件工作流动作
        [{
            "id": "动作ID",
            "name": "动作名称",
            "func": self.xxx,
            "kwargs": {} # 需要附加传递的参数
        }]

        对实现函数的要求：
        1、函数的第一个参数固定为 ActionContent 实例，如需要传递额外参数，在kwargs中定义
        2、函数的返回：执行状态 True / False，更新后的 ActionContent 实例
        """
        pass

    def provides_models(self) -> List[Type]:
        """
        声明本插件【自管理】的数据库模型类（插件自有表，声明式注册）。

        返回继承自 build_plugin_base(本插件ID) 的 ORM 模型【类】列表（非实例）。
        这些模型挂在插件专属的独立 MetaData 上，落到插件独立的 .db 文件 / schema，
        与核心库及其它插件完全隔离；框架（PluginManager 启停）据此自动建表/卸载删库，
        无需插件自行管理 Engine/Session。默认不声明任何表。

        用法：在插件模块内 `PluginBase = build_plugin_base(self.plugin_id)`，
        定义 `class XxxModel(PluginBase): ...`，再于此返回 `[XxxModel, ...]`；
        读写用 `self.get_plugin_db().session()`（即「自会话管理」）。

        【多实例】自管理表按插件划分，同一插件的全部实例共享同一个库与同一套表——
        这与 get_config()、save_data()/get_data()、get_data_path() 按实例隔离的行为
        不同。分身实例写同一张表时，只按业务键建唯一约束会让两个实例互相覆盖。
        需要按实例分开存放的，混入 app.db.plugin.instance.PluginInstanceMixin
        取得 instance_id 列与索引，并把 self.instance_id 带进唯一约束与查询条件。

        [XxxModel, YyyModel, ...]
        """
        return []

    def provides_migration_location(self) -> Optional[Path]:
        """
        【可选】声明本插件 Alembic 迁移目录（启用 per-plugin 迁移链而非 create_all）。

        返回包含 env.py（用 app.db.plugin.migration.write_plugin_alembic_env 生成）
        与 versions/ 迁移脚本的目录路径；框架启动插件时自动 upgrade 到 head。
        返回 None（默认）则走 create_all 直接建表，适合无需演进表结构的插件。
        """
        return None

    def get_agent_tools(self) -> List[Type]:
        """
        获取插件智能体工具
        返回工具类列表，每个工具类必须继承自 MoviePilotTool
        [ToolClass1, ToolClass2, ...]

        对工具类的要求：
        1、工具类必须继承自 app.agent.tools.base.MoviePilotTool
        2、工具类需要实现 run 方法（异步方法）
        3、工具类需要定义 name 和 description 属性
        4、工具类可以定义 args_schema 来指定输入参数模型

        该方式无契约校验，不合契约的工具类要到智能体实际调用时才暴露，
        请改用 provides_agent_tools()
        """
        pass

    def provides_agent_tools(self) -> List[Type]:
        """
        声明本插件提供的智能体工具，注册后与内建工具同权参与智能体调用

        返回继承自 app.agent.tools.base.MoviePilotTool 的工具【类】列表（非实例）。
        工具类需实现异步的 run，并定义非空的 name 与 description；未通过校验的会被拒绝
        注册，而不是等到智能体实际调用时才失败。可定义 args_schema 指定输入参数模型。

        【多实例】工具按声明来源的实例键归组，同一插件的多个实例声明同一个工具类时各占
        一份，工具名相同则以后到者覆盖，需要并存的分身请让各实例的工具名带上实例标识。

        :return: 工具类列表
        """
        return []

    @abstractmethod
    def stop_service(self):
        """
        停止插件
        """
        pass

    def update_config(self, config: dict, plugin_id: Optional[str] = None) -> bool:
        """
        更新配置信息
        :param config: 配置信息字典
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        return self.pluginconfig.set(plugin_id, config, self.instance_id)

    def get_config(self, plugin_id: Optional[str] = None) -> Any:
        """
        获取配置信息
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        return self.pluginconfig.get(plugin_id, self.instance_id)

    def get_data_path(self, plugin_id: Optional[str] = None) -> Path:
        """
        获取插件数据保存目录

        默认实例直接使用插件目录，其余实例在插件目录下按实例分隔。
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        data_path = settings.PLUGIN_DATA_PATH / f"{plugin_id}"
        if self.instance_id != DEFAULT_INSTANCE_ID:
            data_path = data_path / "instances" / self.instance_id
        if not data_path.exists():
            data_path.mkdir(parents=True)
        return data_path

    def get_plugin_db(self):
        """
        获取本插件【独立】的数据库容器（按插件标识自动注册，幂等）。

        返回 app.db.plugin.PluginDatabase（持有插件专属 Engine + ScopedSession，
        落 PLUGIN_DATA_PATH/<plugin_id>/<plugin_id>.db）。配合 provides_models()
        声明的模型，用 `self.get_plugin_db().session()` 进行读写（自会话管理）。

        【多实例】容器按插件标识注册，同一插件的全部实例拿到同一个容器、共享同一个库，
        实例标识不参与寻址。需要按实例分开存放的表，见 provides_models() 的说明。
        """
        from app.db.plugin import db_manager
        return db_manager.register_plugin(self.plugin_id)

    def save_data(self, key: str, value: Any, plugin_id: Optional[str] = None):
        """
        保存插件数据
        :param key: 数据key
        :param value: 数据值
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        self.plugindata.save(plugin_id, key, value, self.instance_id)

    async def async_save_data(
        self, key: str, value: Any, plugin_id: Optional[str] = None
    ) -> None:
        """
        异步保存插件数据

        :param key: 数据键
        :param value: 数据值
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        await self.plugindata.async_save(plugin_id, key, value, self.instance_id)

    def get_data(self, key: Optional[str] = None, plugin_id: Optional[str] = None) -> Any:
        """
        获取插件数据
        :param key: 数据key
        :param plugin_id: plugin_id
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        return self.plugindata.get_data(plugin_id, key, self.instance_id)

    async def async_get_data(
        self, key: Optional[str] = None, plugin_id: Optional[str] = None
    ) -> Any:
        """
        异步获取插件数据

        :param key: 数据键
        :param plugin_id: 插件ID
        :return: 指定键的数据值或插件的全部数据
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        return await self.plugindata.async_get_data(plugin_id, key, self.instance_id)

    def del_data(self, key: str, plugin_id: Optional[str] = None) -> Any:
        """
        删除插件数据
        :param key: 数据key
        :param plugin_id: plugin_id
        """
        if not plugin_id:
            plugin_id = self.plugin_id
        return self.plugindata.del_data(plugin_id, key, self.instance_id)

    def post_message(self, channel: MessageChannel = None, mtype: NotificationType = None, title: Optional[str] = None,
                     text: Optional[str] = None, image: Optional[str] = None, link: Optional[str] = None,
                     userid: Optional[str] = None, username: Optional[str] = None,
                     **kwargs):
        """
        发送消息
        """
        if not link:
            link = settings.MP_DOMAIN(f"#/plugins?tab=installed&id={self.plugin_id}")
        self.chain.post_message(Notification(
            channel=channel, mtype=mtype, title=title, text=text,
            image=image, link=link, userid=userid, username=username, **kwargs
        ))

    def close(self):
        pass
