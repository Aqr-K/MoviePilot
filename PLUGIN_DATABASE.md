# Plugin Database System

MoviePilot插件数据库管理系统，提供解耦、隔离、可维护的插件数据库模型管理功能。

## 功能特性

### 1. 插件数据库隔离
- 每个插件拥有独立的Base类和metadata
- 插件表名强制前缀：`plugin_{插件id小写}_{表名小写}`
- 独立的数据库会话管理
- 避免不同插件之间的数据干扰

### 2. Alembic迁移管理
- 插件专用的Alembic配置和迁移目录
- 复用主程序的templates和env.py模板
- 支持插件独立的分支管理
- 自动生成插件特定的迁移脚本

### 3. 孤儿版本清理
- 自动检测已删除插件的版本记录
- 支持批量清理孤儿版本号
- 分支隔离，确保插件迁移只读取相关版本

### 4. 配置文件管理
- 每个插件目录下的JSON配置文件
- 记录模型目录、Base类名、versions目录等信息
- 支持自定义配置选项

## 目录结构

```
app/plugins/{plugin_id}/
├── __init__.py                    # 插件主文件
├── plugin_db_config.json         # 数据库配置文件
├── models/                        # 数据库模型目录
│   ├── __init__.py
│   └── {plugin_id}_models.py      # 模型定义文件
└── alembic/                       # Alembic迁移目录
    ├── alembic.ini                # Alembic配置文件
    ├── env.py                     # 插件专用环境配置
    ├── script.py.mako             # 迁移脚本模板
    └── versions/                  # 迁移版本目录
        └── {revision_id}_{message}.py
```

## 使用方法

### 1. 插件中使用数据库

```python
from app.plugins import _PluginBase
from app.core.plugin_db_utils import with_plugin_db
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import Session

class MyPlugin(_PluginBase):
    def init_plugin(self, config: dict = None):
        # 初始化插件数据库
        self.init_plugin_database()
        
        # 创建迁移脚本
        # self.create_plugin_migration("Initial tables")
        
        # 升级数据库
        # self.upgrade_plugin_database()
    
    @with_plugin_db()
    def my_database_operation(self, db: Session):
        # 使用插件专用数据库会话
        results = db.query(MyModel).all()
        return results
```

### 2. 定义数据库模型

```python
from sqlalchemy import Column, Integer, String
from app.core.plugin_db import plugin_db_manager
from app.core.plugin_db_utils import PluginModel

# 获取插件Base类
MyPluginBase = plugin_db_manager.get_plugin_base('myplugin')

class MyModel(MyPluginBase, PluginModel):
    # 表名必须遵循命名约定
    __tablename__ = 'plugin_myplugin_mymodel'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    
    def __repr__(self):
        return f"<MyModel(name='{self.name}')>"
```

### 3. 命令行工具

```bash
# 初始化插件数据库
python plugin_db_cli.py init myplugin

# 创建迁移脚本
python plugin_db_cli.py migration myplugin "Add new table"

# 升级数据库
python plugin_db_cli.py upgrade myplugin

# 验证插件数据库
python plugin_db_cli.py validate myplugin

# 查看插件信息
python plugin_db_cli.py info myplugin

# 清理孤儿版本
python plugin_db_cli.py cleanup --dry-run

# 列出所有插件数据库状态
python plugin_db_cli.py list
```

## API文档

### 核心类

#### `PluginDBConfig`
插件数据库配置管理类
- `models_dir`: 模型文件目录
- `base_class_name`: Base类名称
- `versions_dir`: 版本目录
- `alembic_dir`: Alembic目录
- `branch_label`: 分支标签

#### `PluginBaseFactory`
插件Base类工厂
- `get_base(plugin_id)`: 获取插件专用Base类

#### `PluginDBManager`
插件数据库管理器
- `get_plugin_config(plugin_id)`: 获取配置
- `get_plugin_base(plugin_id)`: 获取Base类
- `get_plugin_session(plugin_id)`: 获取会话工厂
- `initialize_plugin_db(plugin_id)`: 初始化数据库

#### `PluginAlembicManager`
插件Alembic管理器
- `create_plugin_alembic_config(plugin_id)`: 创建配置
- `generate_plugin_revision(plugin_id, message)`: 生成迁移
- `upgrade_plugin_database(plugin_id, revision)`: 升级数据库

### 装饰器

#### `@with_plugin_db(plugin_id=None)`
自动提供插件专用数据库会话的装饰器

```python
@with_plugin_db('myplugin')
def my_function(db: Session):
    # db 是插件专用的数据库会话
    return db.query(MyModel).all()
```

### 工具函数

#### `validate_table_name(plugin_id, table_name)`
验证表名是否符合命名约定

#### `initialize_plugin_database(plugin_id)`
初始化插件数据库系统

#### `cleanup_plugin_database(plugin_id, remove_tables=False)`
清理插件数据库

#### `validate_plugin_database(plugin_id)`
验证插件数据库设置

## 命名约定

### 表名规则
- 格式：`plugin_{plugin_id_lowercase}_{model_name_lowercase}`
- 只允许小写字母、数字和下划线
- 必须以字母开头
- 示例：`plugin_example_user`, `plugin_mytest_user_profile`

### 类名规则
- 格式：`Plugin{PluginId}{ModelName}`
- 使用帕斯卡命名法
- 示例：`PluginExampleUser`, `PluginMytestUserProfile`

### 文件名规则
- 配置文件：`plugin_db_config.json`
- 模型文件：`{plugin_id}_models.py`
- 迁移脚本：`{revision_id}_{message}.py`

## 配置文件示例

`plugin_db_config.json`:
```json
{
  "models_dir": "/path/to/plugin/models",
  "base_class_name": "PluginExampleBase",
  "versions_dir": "/path/to/plugin/alembic/versions",
  "alembic_dir": "/path/to/plugin/alembic",
  "branch_label": "plugin_example"
}
```

## 注意事项

1. **表名约定必须严格遵循**：所有模型的表名都必须以`plugin_{plugin_id}_`为前缀
2. **独立的metadata**：每个插件有独立的metadata，避免干扰
3. **版本隔离**：插件迁移只会影响自己的版本号，不会干扰主程序或其他插件
4. **自动清理**：定期运行孤儿版本清理，保持数据库整洁
5. **配置管理**：插件目录下会自动生成配置文件，可以根据需要调整

## 故障排除

### 常见错误

1. **表名不符合约定**
   ```
   ValueError: Invalid table name 'user' for plugin 'myplugin'. 
   Must follow pattern 'plugin_myplugin_{model_name_lowercase}'
   ```
   解决：修改表名为正确格式

2. **孤儿版本问题**
   ```
   Error: Version not found in current branch
   ```
   解决：运行清理命令 `python plugin_db_cli.py cleanup`

3. **配置文件缺失**
   ```
   Warning: Plugin database config file does not exist
   ```
   解决：运行初始化命令 `python plugin_db_cli.py init {plugin_id}`

### 调试技巧

1. 使用`validate`命令检查配置
2. 使用`info`命令查看详细信息
3. 使用`list`命令查看所有插件状态
4. 使用`--dry-run`选项预览清理操作

## 示例插件

参见 `app/plugins/example/` 目录下的示例插件，展示了完整的数据库集成用法。