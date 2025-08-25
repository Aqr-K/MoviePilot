# SiteUserData表userid字段类型迁移说明

## 概述

本次迁移将 `SiteUserData` 表中的 `userid` 字段从 `Integer` 类型改为 `String` 类型，以支持更灵活的用户ID格式。

## 变更内容

### 1. 数据模型变更

**文件**: `app/db/models/siteuserdata.py`

```python
# 变更前
userid = Column(Integer)

# 变更后  
userid = Column(String)
```

### 2. Schema定义变更

**文件**: `app/schemas/site.py`

```python
# 变更前
userid: Optional[Union[int, str]] = None

# 变更后
userid: Optional[str] = None
```

### 3. 数据库迁移脚本

**文件**: `database/versions/a946dae52526_2_2_1.py`

- **版本号**: 2.2.1
- **修订ID**: a946dae52526
- **前置版本**: 5b3355c964bb (2.2.0)

#### 迁移功能

1. **PostgreSQL数据库迁移**:
   - 创建临时列 `userid_new` (VARCHAR类型)
   - 将现有数据转换为字符串并复制到新列
   - 删除旧列 `userid`
   - 重命名新列为 `userid`

2. **SQLite数据库迁移**:
   - 创建新表结构，userid字段为VARCHAR类型
   - 复制现有数据，将userid转换为字符串
   - 删除旧表并重命名新表
   - 重新创建索引

#### 降级功能

1. **PostgreSQL数据库降级**:
   - 创建临时列 `userid_old` (INTEGER类型)
   - 将字符串转换为整数（仅转换数字字符串）
   - 删除旧列并重命名新列

2. **SQLite数据库降级**:
   - 创建新表结构，userid字段为INTEGER类型
   - 复制数据，仅转换数字字符串为整数
   - 删除旧表并重命名新表
   - 重新创建索引

### 4. 代码兼容性修复

#### 修复的文件

1. **app/modules/indexer/parser/nexus_rabbit.py**
   ```python
   # 修复前
   "data": {"type": "seeding", "id": int(self.userid)},
   
   # 修复后
   "data": {"type": "seeding", "id": int(self.userid) if self.userid and str(self.userid).isdigit() else 0},
   ```

2. **app/modules/synologychat/synologychat.py**
   ```python
   # 修复前
   payload_data['user_ids'] = [int(userid)]
   
   # 修复后
   payload_data['user_ids'] = [int(userid) if str(userid).isdigit() else userid]
   ```

## 迁移步骤

### 1. 备份数据库

在执行迁移前，请务必备份数据库：

```bash
# SQLite数据库备份
cp user.db user.db.backup

# PostgreSQL数据库备份
pg_dump -h localhost -U username -d database_name > backup.sql
```

### 2. 执行迁移

```bash
# 进入项目目录
cd /path/to/project

# 执行数据库迁移
python -m alembic upgrade head
```

### 3. 验证迁移

运行测试脚本验证迁移是否成功：

```bash
python test_migration.py
```

## 影响分析

### 正面影响

1. **灵活性提升**: 支持非数字格式的用户ID
2. **兼容性增强**: 适应不同站点的用户ID格式
3. **数据完整性**: 保持原有数据不丢失

### 潜在风险

1. **性能影响**: 字符串类型可能比整数类型占用更多存储空间
2. **查询性能**: 字符串比较可能比整数比较稍慢
3. **数据验证**: 需要确保应用程序正确处理字符串类型的userid

### 兼容性说明

1. **向后兼容**: 迁移脚本包含降级功能，可以回滚到Integer类型
2. **代码兼容**: 已修复所有直接使用userid的代码
3. **API兼容**: Schema变更保持了API的向后兼容性

## 测试验证

### 功能测试

1. **数据插入测试**: 验证整数和字符串类型的userid都能正常插入
2. **数据查询测试**: 验证按域名、日期等条件查询功能正常
3. **数据更新测试**: 验证userid字段更新功能正常
4. **API测试**: 验证相关API接口正常工作

### 性能测试

1. **查询性能**: 验证查询性能无明显下降
2. **存储空间**: 验证存储空间使用情况
3. **并发性能**: 验证并发操作正常

## 回滚方案

如果迁移出现问题，可以执行降级操作：

```bash
# 降级到上一个版本
python -m alembic downgrade 5b3355c964bb
```

## 注意事项

1. **备份重要**: 执行迁移前必须备份数据库
2. **测试环境**: 建议先在测试环境验证迁移
3. **监控日志**: 迁移过程中注意观察日志输出
4. **数据验证**: 迁移完成后验证数据完整性

## 联系信息

如有问题，请联系开发团队或查看项目文档。