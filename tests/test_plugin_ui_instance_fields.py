"""侧栏与仪表板条目携带实例标识，供前端自行决定如何区分同插件的多个实例。"""


from app import schemas
from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.runtime.extensions.plugin_ui import get_plugin_dashboard_meta, get_plugin_sidebar_nav

PLUGIN_ID = "UiDemo"
CLONE_KEY = f"{PLUGIN_ID}@alpha"


class DemoPlugin:
    """声明侧栏入口的插件替身"""

    def __init__(self, title: str):
        """记录显示标题"""
        self.plugin_name = title

    def get_state(self) -> bool:
        """运行状态"""
        return True

    def get_render_mode(self):
        """渲染模式"""
        return "vue", None

    def get_sidebar_nav(self):
        """侧栏入口声明"""
        return [{"nav_key": "main", "title": self.plugin_name, "section": "system"}]

    def get_dashboard(self):
        """仪表板内容"""
        return {}, {}, []


class MetaPlugin(DemoPlugin):
    """额外声明多仪表板的插件替身"""

    def get_dashboard_meta(self):
        """仪表板入口声明"""
        return [{"name": self.plugin_name, "key": "board"}]


def make_plugin(title: str, with_meta: bool = False):
    """
    构造声明侧栏入口与仪表板的插件替身

    :param title: 侧栏标题
    :param with_meta: 是否声明多仪表板
    :return: 插件实例替身
    """
    return MetaPlugin(title) if with_meta else DemoPlugin(title)


def test_sidebar_items_carry_their_instance_identity():
    """侧栏条目带出所属实例的实例标识与实例键。"""
    running = {PLUGIN_ID: make_plugin("默认"), CLONE_KEY: make_plugin("分身")}

    items = {item["plugin_id"]: item for item in get_plugin_sidebar_nav(running)}

    assert items[PLUGIN_ID]["instance_id"] == DEFAULT_INSTANCE_ID
    assert items[PLUGIN_ID]["instance_key"] == PLUGIN_ID
    assert items[CLONE_KEY]["instance_id"] == "alpha"
    assert items[CLONE_KEY]["instance_key"] == CLONE_KEY


def test_sidebar_titles_are_left_untouched():
    """后端不改显示文案，标题原样交给前端。"""
    running = {PLUGIN_ID: make_plugin("影视刮削"), CLONE_KEY: make_plugin("影视刮削")}

    titles = [item["title"] for item in get_plugin_sidebar_nav(running)]

    assert titles == ["影视刮削", "影视刮削"]


def test_dashboard_meta_carries_its_instance_identity():
    """仪表板入口摘要带出所属实例的实例标识与实例键。"""
    running = {PLUGIN_ID: make_plugin("默认", with_meta=True),
               CLONE_KEY: make_plugin("分身", with_meta=True)}

    items = {item["id"]: item for item in get_plugin_dashboard_meta(running)}

    assert items[PLUGIN_ID]["instance_id"] == DEFAULT_INSTANCE_ID
    assert items[CLONE_KEY]["instance_id"] == "alpha"
    assert items[CLONE_KEY]["instance_key"] == CLONE_KEY


def test_single_dashboard_entry_also_carries_it():
    """未声明多仪表板的插件，其单条入口同样带出实例标识。"""
    running = {CLONE_KEY: make_plugin("分身")}

    item = get_plugin_dashboard_meta(running)[0]

    assert item["instance_id"] == "alpha"
    assert item["instance_key"] == CLONE_KEY


def test_the_response_model_keeps_the_instance_fields():
    """响应模型声明了这两个字段，序列化时不会被丢弃。"""
    running = {CLONE_KEY: make_plugin("分身", with_meta=True)}

    nav = schemas.PluginSidebarNavItem.model_validate(get_plugin_sidebar_nav(running)[0])
    meta = schemas.PluginDashboardMetaItem.model_validate(get_plugin_dashboard_meta(running)[0])

    assert nav.model_dump()["instance_key"] == CLONE_KEY
    assert meta.model_dump()["instance_key"] == CLONE_KEY
