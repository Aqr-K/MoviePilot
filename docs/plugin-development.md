# 插件开发指南

面向插件作者。约定与代码同源，实现见 `app/plugins/__init__.py`（基类）、
`app/runtime/extensions/`（注册与聚合）、`app/db/plugin/`（自管理库）。

## 一、实例模型

一个插件类可以同时跑多个实例。实例由**实例键**唯一标识：

| 实例 | 实例键 | 数据目录 |
|---|---|---|
| 默认实例 | `MyPlugin` | `PLUGIN_DATA_PATH/MyPlugin/` |
| 分身 `alpha` | `MyPlugin@alpha` | `PLUGIN_DATA_PATH/MyPlugin/instances/alpha/` |

**默认实例的实例键退化为裸插件标识**，所以只跑一个实例的插件，取值与不区分实例时完全一致，
存量插件无需改动。

基类提供三个只读属性：

```python
self.plugin_id      # 插件标识，缺省取类名
self.instance_id    # 实例标识，默认实例为 "default"
self.instance_key   # 实例键，默认实例即 plugin_id
```

### 向框架登记「本实例」时一律用 `self.instance_key`

不要传 `self.plugin_id` 或 `self.__class__.__name__`。裸插件标识只解析到默认实例，
分身用它登记的输入会话，用户回复会被投递给默认实例而不是自己。典型场景：

```python
plugin_input_interaction_manager.create_or_replace(..., plugin_id=self.instance_key, ...)
```

### 按实例隔离的资源

`get_config()` / `update_config()`、`save_data()` / `get_data()`、`get_data_path()`
都按实例寻址，各实例互不可见。

**例外**：`get_plugin_db()` 返回的自管理库**按插件划分**，同一插件的全部实例共享同一个库
与同一套表。原因是 ORM 类与 MetaData 一一对应，做不到按实例分库。

## 二、声明式注册钩子

在插件类上实现下列钩子即可向框架登记能力。全部为可选，缺省返回空。

框架在插件启停与配置生效时按实例键重新聚合，停用时自动回收，**无需插件自行反注册**。
声明在注册阶段做契约校验，不合契约的会被拒绝并记日志，而不是等到运行时才失败。

| 钩子 | 返回 | 说明 |
|---|---|---|
| `provides_modules()` | 模块类或 `ProvidedModule` 列表 | 通用系统模块，与内建模块同权参与分发 |
| `provides_downloaders()` | 同上 | 额外校验模块类型为 `Downloader` |
| `provides_mediaservers()` | 同上 | 额外校验模块类型为 `MediaServer` |
| `provides_notifications()` | 同上 | 额外校验模块类型为 `Notification` |
| `provides_data_sources()` | 同上 | 额外校验模块类型为 `MediaRecognize` |
| `provides_storages()` | `StorageBase` 子类列表 | 存储实现，与内建存储同权参与文件整理 |
| `provides_agent_tools()` | `MoviePilotTool` 子类列表 | 智能体工具 |
| `provides_channel_capabilities()` | `ChannelCapabilities` 列表 | 消息渠道能力，可覆盖内建取值 |
| `provides_models()` | ORM 模型类列表 | 插件自管理表 |
| `provides_migration_location()` | 目录路径 | 插件自有 Alembic 迁移链 |

### 存储

`schema` 即存储标识，与内建存储和其它插件不得重名。**可以是普通字符串**，不必是
`StorageSchema` 枚举成员——枚举是内建存储的封闭集合。

```python
class MyCloud(StorageBase):
    schema = "mycloud"
    transtype = {"copy": "复制"}

    def init_storage(self):
        ...
    # 其余抽象方法必须全部落地，否则注册阶段即被拒
```

同一插件的多个实例声明同一个存储类时后者被拒（schema 冲突）。需要多份配置的存储，
让各实例声明各自 schema 不同的存储类。

### 智能体工具

工具类需继承 `MoviePilotTool`、实现**异步**的 `run`、定义非空的 `name` 与 `description`。
同一插件的多个实例声明同一工具类时各占一份，**工具名相同则后到者覆盖**——需要并存的
分身，请让各实例的工具名带上实例标识。

### 自管理数据库

```python
PluginBase = build_plugin_base(self.plugin_id)


class MyRecord(PluginBase):
    __tablename__ = "my_record"
    ...


def provides_models(self):
    return [MyRecord]


# 读写
with self.get_plugin_db().session() as session:
    ...
```

落到 `PLUGIN_DATA_PATH/<plugin_id>/<plugin_id>.db`，与核心库及其它插件完全隔离，
框架负责建表与卸载删库。

**多实例注意**：全部实例共享同一套表。只按业务键建唯一约束会让两个实例互相覆盖。
需要按实例分开存放的，混入 `app.db.plugin.instance.PluginInstanceMixin` 取得
`instance_id` 列与索引，并把 `self.instance_id` 带进唯一约束与查询条件。

## 三、已废弃的方式

废弃分三阶段推进：**标记预警 → 默认关闭 → 物理删除**。处于「默认关闭」阶段的能力，
需把其 key 列入 `DEPRECATION_ENABLED` 才临时恢复。全部登记见
`app/runtime/deprecation/notices.py`。

| 废弃项 | 阶段 | 替代 |
|---|---|---|
| `get_module()` | 标记预警 | `provides_modules()` 等声明式钩子 |
| `get_agent_tools()` | 标记预警 | `provides_agent_tools()` |
| 复制源码目录创建分身 | 已删除 | 插件实例分身（按 `instance_id` 跑多实例） |

`get_module()` 按方法名胁持内建模块实现，无契约校验、无归属记账、卸载不可回收。
`get_agent_tools()` 无契约校验，不合契约的工具类要到智能体实际调用时才暴露。

## 四、其它约定

- **接口路由**以声明来源的实例键为前缀，各实例互不冲突。
- **定时服务**的 `pid` 携带声明来源的实例键，调用方据此区分。
- **工作流动作**按归属实例精确匹配。
- **事件**投递给该插件订阅了对应事件且已启用的每一个实例。
