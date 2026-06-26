from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Any, List, Dict, Tuple, Optional, Type

from app.chain import ChainBase
from app.core.config import settings
from app.core.event import EventManager
from app.db.plugindata_oper import PluginDataOper
from app.db.systemconfig_oper import SystemConfigOper
from app.helper.message import MessageHelper
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
    # 是否为插件分身
    is_clone: bool = False

    def __init__(self):
        # 插件数据
        self.plugindata = PluginDataOper()
        # 处理链
        self.chain = PluginChian()
        # 系统配置
        self.systemconfig = SystemConfigOper()
        # 系统消息
        self.systemmessage = MessageHelper()
        # 事件管理器
        self.eventmanager = EventManager()

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
        【已废弃，将移除】获取插件模块声明，用于胁持系统模块实现（方法名：方法实现）。

        本「方法胁持/注入」路径无契约校验、易与内建实现冲突，已废弃；
        请改用 provides_modules() 走「验证注册」——框架统一注册到 ModuleManager
        并参与 chain 分发，无需 monkey-patch app.modules。
        {
            "id1": self.xxx1,
            "id2": self.xxx2,
        }
        """
        pass

    def provides_modules(self) -> List[Type]:
        """
        声明本插件向模块层【新增】的系统模块类（区别于 get_module 的方法胁持：
        get_module 改既有方法，本钩子新增一个完整模块，如新的下载器/媒体服务器/消息渠道）。

        返回模块【类】列表（非实例），每个类需实现 _ModuleBase 契约：
        init_module / init_setting / stop / test，以及 get_type / get_subtype（或
        get_subtype_id 返回枚举外字符串如 "aria2"）/ get_priority。
        由框架（PluginManager 启停）统一注册到 ModuleManager 并参与 chain 分发，
        无需插件自行 monkey-patch app.modules。默认不新增任何模块。

        [DownloaderModuleClass, MediaServerModuleClass, ...]
        """
        return []

    def provides_storages(self) -> List[Type]:
        """
        声明本插件向文件整理层【新增】的存储器类（provides_modules 的语法糖，
        内部经 FileManager 注册）。返回 StorageBase 子类列表（非实例）。默认不新增。

        [StorageClass1, StorageClass2, ...]
        """
        return []

    def provides_channel_capabilities(self) -> List[Any]:
        """
        声明本插件新增的消息渠道的能力矩阵（配合 provides_modules 新增消息渠道模块使用）。
        返回 ChannelCapabilities 实例列表，每个实例的 channel 字段为该渠道的字符串 id
        （无需扩展封闭 MessageChannel 枚举）。由框架注册到 ChannelCapabilityManager，
        使插件渠道获得正确的按钮/Markdown/分段等能力声明（不声明则走降级默认）。默认不新增。

        [ChannelCapabilities(channel="mychannel", capabilities={...}), ...]
        """
        return []

    def provides_data_sources(self) -> List[Type]:
        """
        声明本插件向模块层【新增】的数据源（媒体识别/信息源，MediaRecognize 域）类，
        如新的 TMDB / IMDB / 豆瓣式来源。provides_modules 的语法糖 + 数据源契约校验：
        返回的【类】（非实例）须实现 _ModuleBase 契约且 get_type()==ModuleType.MediaRecognize。
        识别能力方法（recognize_media / search_medias / obtain_images 等）按需实现——
        框架经 ModuleManager 注册（owner=plugin_id）后按方法名分发，实现哪个就参与哪个
        识别/搜索/取图流水线；子类型用 get_subtype_id() 返回字符串 id（无需扩展封闭枚举）。默认不新增。

        [TmdbLikeSourceClass, ImdbLikeSourceClass, ...]
        """
        return []

    def provides_downloaders(self) -> List[Type]:
        """
        声明本插件向模块层【新增】的下载器（Downloader 域）类，如新的 BT/PT 下载器。
        provides_modules 的语法糖 + 下载器契约校验：返回的【类】（非实例）须实现 _ModuleBase
        契约且 get_type()==ModuleType.Downloader，并实现 download / list_torrents / remove_torrents
        等下载器操作（完整 IDownloader 操作面由 run_module 按方法名分发、按需实现）。
        子类型用 get_subtype_id() 返回字符串 id（无需扩展封闭 DownloaderType 枚举）。默认不新增。

        [MyDownloaderClass, ...]
        """
        return []

    def provides_notifications(self) -> List[Type]:
        """
        声明本插件向模块层【新增】的消息渠道（Notification 域）类，如新的 IM/推送渠道。
        provides_modules 的语法糖 + 消息渠道契约校验：返回的【类】（非实例）须实现 _ModuleBase
        契约且 get_type()==ModuleType.Notification，并实现 post_message（其余 post_medias /
        post_torrents / delete_message / register_commands 等由 run_module 按方法名分发、按需实现）。
        子类型用 get_subtype_id() 返回字符串 id（无需扩展封闭 MessageChannel 枚举）；
        渠道的按钮/Markdown/分段等能力矩阵另经 provides_channel_capabilities() 声明。默认不新增。

        [MyNotificationClass, ...]
        """
        return []

    def provides_mediaservers(self) -> List[Type]:
        """
        声明本插件向模块层【新增】的媒体服务器（MediaServer 域）类，如新的影音库服务端。
        provides_modules 的语法糖 + 媒体服务器契约校验：返回的【类】（非实例）须实现 _ModuleBase
        契约且 get_type()==ModuleType.MediaServer。能力方法（mediaserver_librarys /
        media_statistic / mediaserver_playing / mediaserver_items 等）由 run_module 按方法名
        分发、按需实现（实现哪个就参与哪个媒体库流水线）。子类型用 get_subtype_id() 返回字符串 id
        （无需扩展封闭 MediaServerType 枚举）。默认不新增。

        [MyMediaServerClass, ...]
        """
        return []

    def provides_discover_sources(self) -> List[Any]:
        """
        声明本插件向探索页【新增】的数据源（Discover 域，声明式注册，与现有
        ChainEventType.DiscoverSource 事件扩展并存、由框架去重合并）。返回 DiscoverMediaSource
        实例列表，每个含 name / mediaid_prefix / api_path（指向本插件自有 API）/ filter_params /
        filter_ui 等；由 /api/v1/discover/source 端点聚合后供前端枚举。默认不新增。

        [DiscoverMediaSource(name=..., mediaid_prefix=..., api_path=...), ...]
        """
        return []

    def provides_recommend_sources(self) -> List[Any]:
        """
        声明本插件向推荐页【新增】的数据源（Recommend 域，声明式注册，与现有
        ChainEventType.RecommendSource 事件扩展并存、由框架去重合并）。返回 RecommendMediaSource
        实例列表，每个含 name / api_path（指向本插件自有 API）/ type；由 /api/v1/recommend/source
        端点聚合后供前端枚举。默认不新增。

        [RecommendMediaSource(name=..., api_path=..., type=...), ...]
        """
        return []

    def provides_auth_providers(self) -> List[Any]:
        """
        声明本插件向登录页【新增】的 SSO 登录提供方（外部 IdP 单点登录，声明式注册）。
        返回实现 app.core.auth.redirect.IAuthProvider 契约的【实例】列表，每个含 provider_id / provider_name /
        provider_icon + authorize_url(state, redirect_uri) / fetch_identity(code, redirect_uri)。
        框架统一负责 CSRF state、回调端点、用户解析/建号与铸票（消除每个 SSO 插件重复的这套样板），
        插件只实现 IdP 特定的「授权 URL 构造」与「授权码换身份」两件事。默认不新增。

        [GithubAuthProvider(...), FeishuAuthProvider(...), ...]
        """
        return []

    def provides_auth_flows(self) -> List[Any]:
        """
        声明本插件向登录【新增】的自定义流程形状（组合策略），而不止于贡献单个步骤。
        返回实现 app.core.auth.flow_registry.IFlowSpec 契约的【实例】列表，每个含 flow_id +
        mfa_requirement(factor_steps)，可据已装配因子返回 AnyOf / NOf / AllOf 组合（如 2-of-3 强 MFA、
        强制多因子）。上层端点按 flow_id 选用。默认不新增（即沿用任一因子满足的默认策略）。

        [HighAssuranceFlowSpec(...), ...]
        """
        return []

    def provides_auth_steps(self) -> List[Any]:
        """
        声明本插件向登录流程【新增】的认证步骤（**统一 SPI**：主认证 provider / MFA 因子 / SSO 重定向
        统一收口为「认证步骤」一条声明）。返回实现 app.core.auth.flow.IAuthStep 契约的【实例】列表 ——
        通常是把现有认证构件包装成步骤的适配器：CredentialProviderStep(provider) / FactorStep(factor) / RedirectStep(provider)，
        各含 step_id / step_kind / priority + applies_to(context) / advance(context, submission)。
        框架以 owner=plugin_id 注册到全局步骤注册表（register_auth_step），装配桥按 step_kind 切分
        （credential / directory / federated_direct / redirect → 凭证步；factor → 第二因子步）后入多步
        登录流程。默认不新增。

        [CredentialProviderStep(LdapProvider(...)), FactorStep(SmsFactor(...)), ...]
        """
        return []

    def provides_models(self) -> List[Type]:
        """
        声明本插件【自管理】的数据库模型类（插件自有表，声明式注册）。

        返回继承自 build_plugin_base(本插件ID) 的 ORM 模型【类】列表（非实例）。
        这些模型挂在插件专属的独立 MetaData 上，落到插件独立的 .db 文件 / schema，
        与核心库及其它插件完全隔离；框架（PluginManager 启停）据此自动建表/卸载删库，
        无需插件自行管理 Engine/Session。默认不声明任何表。

        用法：在插件模块内 `PluginBase = build_plugin_base(self.__class__.__name__)`，
        定义 `class XxxModel(PluginBase): ...`，再于此返回 `[XxxModel, ...]`；
        读写用 `self.get_plugin_db().session()`（即「自会话管理」）。

        [XxxModel, YyyModel, ...]
        """
        return []

    def provides_migration_location(self) -> Optional[Path]:
        """
        【可选】声明本插件 Alembic 迁移目录（启用 per-plugin 迁移链而非 create_all）。

        返回包含 env.py（用 app.db.plugin_migration.write_plugin_alembic_env 生成）
        与 versions/ 迁移脚本的目录路径；框架启动插件时自动 upgrade 到 head。
        返回 None（默认）则走 create_all 直接建表，适合无需演进表结构的插件。
        """
        return None

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
        """
        pass

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
            plugin_id = self.__class__.__name__
        return self.systemconfig.set(f"plugin.{plugin_id}", config)

    def get_config(self, plugin_id: Optional[str] = None) -> Any:
        """
        获取配置信息
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.__class__.__name__
        return self.systemconfig.get(f"plugin.{plugin_id}")

    def get_data_path(self, plugin_id: Optional[str] = None) -> Path:
        """
        获取插件数据保存目录
        """
        if not plugin_id:
            plugin_id = self.__class__.__name__
        data_path = settings.PLUGIN_DATA_PATH / f"{plugin_id}"
        if not data_path.exists():
            data_path.mkdir(parents=True)
        return data_path

    def get_plugin_db(self):
        """
        获取本插件【独立】的数据库容器（按插件类名自动注册，幂等）。

        返回 app.db.manager.PluginDatabase（持有插件专属 Engine + ScopedSession，
        落 PLUGIN_DATA_PATH/<plugin_id>/<plugin_id>.db）。配合 provides_models()
        声明的模型，用 `self.get_plugin_db().session()` 进行读写（自会话管理）。
        """
        from app.db.manager import db_manager
        return db_manager.register_plugin(self.__class__.__name__)

    def save_data(self, key: str, value: Any, plugin_id: Optional[str] = None):
        """
        保存插件数据
        :param key: 数据key
        :param value: 数据值
        :param plugin_id: 插件ID
        """
        if not plugin_id:
            plugin_id = self.__class__.__name__
        self.plugindata.save(plugin_id, key, value)

    def get_data(self, key: Optional[str] = None, plugin_id: Optional[str] = None) -> Any:
        """
        获取插件数据
        :param key: 数据key
        :param plugin_id: plugin_id
        """
        if not plugin_id:
            plugin_id = self.__class__.__name__
        return self.plugindata.get_data(plugin_id, key)

    def del_data(self, key: str, plugin_id: Optional[str] = None) -> Any:
        """
        删除插件数据
        :param key: 数据key
        :param plugin_id: plugin_id
        """
        if not plugin_id:
            plugin_id = self.__class__.__name__
        return self.plugindata.del_data(plugin_id, key)

    def post_message(self, channel: MessageChannel = None, mtype: NotificationType = None, title: Optional[str] = None,
                     text: Optional[str] = None, image: Optional[str] = None, link: Optional[str] = None,
                     userid: Optional[str] = None, username: Optional[str] = None,
                     **kwargs):
        """
        发送消息
        """
        if not link:
            link = settings.MP_DOMAIN(f"#/plugins?tab=installed&id={self.__class__.__name__}")
        self.chain.post_message(Notification(
            channel=channel, mtype=mtype, title=title, text=text,
            image=image, link=link, userid=userid, username=username, **kwargs
        ))

    def close(self):
        pass
