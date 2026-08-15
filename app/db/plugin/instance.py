"""
插件自管理表的实例维度。

同一插件的多个实例共享一个库、一套表：ORM 模型类与 MetaData 一对一绑死，模型又必须
在插件模块顶层声明，因此无法每实例一份 MetaData。配置、插件数据与数据目录都按实例
隔离，自管理表不在此列——需要按实例分开存放的插件，让模型混入 ``PluginInstanceMixin``
取得 ``instance_id`` 列与其索引，并在读写时带上 ``self.instance_id``。
"""
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.pluginconfig import DEFAULT_INSTANCE_ID


class PluginInstanceMixin:
    """
    为插件自管理表补上实例维度的混入

    用法：``class XxxModel(PluginInstanceMixin, PluginBase): ...``，
    唯一约束与查询条件都把 ``instance_id`` 算进去，例如
    ``__table_args__ = (UniqueConstraint("instance_id", "key"),)``。
    不赋值时行归入默认实例，与单实例插件的存量数据落在同一维度上。
    """

    # 行所属的插件实例，缺省为默认实例
    instance_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_INSTANCE_ID,
        server_default=DEFAULT_INSTANCE_ID,
    )
