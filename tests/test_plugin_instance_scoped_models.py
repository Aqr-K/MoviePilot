"""插件自管理表在多实例下的共享契约与按实例隔离的可选手段。

同一插件的多个实例共享一个库、一套表——这是 ORM 类与 MetaData 一对一绑死换来的代价，
决定本身保留。风险在于其余每一个存储面（配置、数据、数据目录）都按实例隔离，唯独这里
不是：插件作者按直觉写个 primary_key，两个实例就会撞车，而且撞车前没有任何提示。
"""
import sqlalchemy as sa

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID
from app.db.plugin import build_plugin_base
from app.db.plugin.instance import PluginInstanceMixin
from app.plugins import _PluginBase

PLUGIN_ID = "SharedTablePlugin"


class SharedTablePlugin(_PluginBase):
    """用于验证自管理表共享行为的最小插件实现。"""

    plugin_name = "自管理表示例插件"

    def init_plugin(self, config: dict = None):
        pass

    def get_state(self) -> bool:
        return True

    def get_api(self):
        return []

    def get_form(self):
        return [], {}

    def get_page(self):
        return None

    def stop_service(self):
        pass


# --------------------------------------------------------------------------- #
# 共享契约必须写在公开 docstring 里
# --------------------------------------------------------------------------- #

def test_provides_models_docstring_states_the_sharing_contract():
    """provides_models 的公开说明必须点明同插件多实例共享同一套表。"""
    doc = _PluginBase.provides_models.__doc__ or ""

    assert "实例" in doc
    assert "共享" in doc
    assert "PluginInstanceMixin" in doc


def test_get_plugin_db_docstring_states_the_sharing_contract():
    """get_plugin_db 的公开说明同样要点明库按插件而非按实例划分。"""
    doc = _PluginBase.get_plugin_db.__doc__ or ""

    assert "实例" in doc
    assert "共享" in doc


# --------------------------------------------------------------------------- #
# 共享行为
# --------------------------------------------------------------------------- #

def test_two_instances_share_one_plugin_database():
    """两个实例拿到的是同一个库容器，按插件而非按实例划分。"""
    default_instance = SharedTablePlugin()
    alpha = SharedTablePlugin(instance_id="alpha")

    assert default_instance.get_plugin_db() is alpha.get_plugin_db()


# --------------------------------------------------------------------------- #
# 按实例隔离的可选手段
# --------------------------------------------------------------------------- #

def test_mixin_adds_an_indexed_instance_column():
    """混入要带来 instance_id 列与其索引，插件无需自己拼这两样。"""
    base = build_plugin_base(f"{PLUGIN_ID}Indexed")

    class Record(PluginInstanceMixin, base):
        __tablename__ = "record"
        id: sa.orm.Mapped[int] = sa.orm.mapped_column(primary_key=True)
        key: sa.orm.Mapped[str] = sa.orm.mapped_column(sa.String)

    table = Record.__table__
    assert "instance_id" in table.c
    assert table.c.instance_id.nullable is False
    assert any(
        tuple(index.columns.keys()) == ("instance_id",) for index in table.indexes
    )


def test_mixin_defaults_rows_to_the_default_instance():
    """不显式赋值时行归入默认实例，与其余存储面的缺省一致。"""
    base = build_plugin_base(f"{PLUGIN_ID}Default")

    class Record(PluginInstanceMixin, base):
        __tablename__ = "record"
        id: sa.orm.Mapped[int] = sa.orm.mapped_column(primary_key=True)
        key: sa.orm.Mapped[str] = sa.orm.mapped_column(sa.String)

    engine = sa.create_engine("sqlite://")
    base.metadata.create_all(engine)
    with sa.orm.Session(engine) as session:
        session.add(Record(key="k1"))
        session.commit()
        stored = session.execute(sa.select(Record.instance_id)).scalar_one()

    assert stored == DEFAULT_INSTANCE_ID


def test_mixin_lets_two_instances_hold_the_same_business_key():
    """带上实例维度后，两个实例可以各自持有同一个业务键而不撞车。"""
    base = build_plugin_base(f"{PLUGIN_ID}Scoped")

    class Record(PluginInstanceMixin, base):
        __tablename__ = "record"
        id: sa.orm.Mapped[int] = sa.orm.mapped_column(primary_key=True)
        key: sa.orm.Mapped[str] = sa.orm.mapped_column(sa.String)
        __table_args__ = (sa.UniqueConstraint("instance_id", "key"),)

    engine = sa.create_engine("sqlite://")
    base.metadata.create_all(engine)
    with sa.orm.Session(engine) as session:
        session.add(Record(instance_id=DEFAULT_INSTANCE_ID, key="k1"))
        session.add(Record(instance_id="alpha", key="k1"))
        session.commit()
        rows = session.execute(
            sa.select(Record.instance_id).where(Record.key == "k1")
        ).scalars().all()

    assert sorted(rows) == ["alpha", DEFAULT_INSTANCE_ID]


def test_models_without_the_mixin_are_untouched():
    """不使用混入的插件模型保持原样，混入是可选项而非强制。"""
    base = build_plugin_base(f"{PLUGIN_ID}Plain")

    class Record(base):
        __tablename__ = "record"
        id: sa.orm.Mapped[int] = sa.orm.mapped_column(primary_key=True)

    assert "instance_id" not in Record.__table__.c
