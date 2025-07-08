# 工作流分享功能

## 概述

基于订阅分享的相关API接口和helper类，新增了工作流分享相关接口和helper，以实现共享公共服务器的相关接口给前端调用，与订阅使用的是同一个服务器。

## 功能特性

1. **工作流分享** - 将本地工作流分享到公共服务器
2. **分享管理** - 查看、删除已分享的工作流
3. **工作流复用** - 从公共服务器复用其他用户分享的工作流
4. **缓存机制** - 使用缓存提高查询性能

## 文件结构

### 新增文件
- `app/schemas/workflow.py` - 新增 `WorkflowShare` schema类
- `app/helper/workflow.py` - 新增工作流分享helper类

### 修改文件
- `app/api/endpoints/workflow.py` - 新增工作流分享相关API接口，使用WorkflowOper进行数据库操作
- `app/db/workflow_oper.py` - 新增list方法
- `app/db/models/workflow.py` - 新增list静态方法
- `app/core/config.py` - 新增WORKFLOW_STATISTIC_SHARE配置项

## API接口

### 1. 分享工作流
```
POST /api/v1/workflow/share
```

**请求参数:**
```json
{
  "id": 1,
  "share_title": "我的工作流",
  "share_comment": "这是一个自动化工作流",
  "share_user": "用户名"
}
```

**响应:**
```json
{
  "success": true,
  "message": "success"
}
```

### 2. 删除分享
```
DELETE /api/v1/workflow/share/{share_id}
```

**响应:**
```json
{
  "success": true,
  "message": "success"
}
```

### 3. 复用工作流
```
POST /api/v1/workflow/fork
```

**请求参数:**
```json
{
  "id": 1,
  "name": "工作流名称",
  "description": "工作流描述",
  "timer": "0 0 * * *",
  "actions": "[{\"id\": \"action1\", \"type\": \"test\"}]",
  "flows": "[{\"id\": \"flow1\", \"source\": \"action1\"}]",
  "context": "{}"
}
```

**响应:**
```json
{
  "success": true,
  "message": "复用成功"
}
```

### 4. 查询分享的工作流
```
GET /api/v1/workflow/shares?name=关键词&page=1&count=30
```

**响应:**
```json
[
  {
    "id": 1,
    "share_title": "我的工作流",
    "share_comment": "这是一个自动化工作流",
    "share_user": "用户名",
    "share_uid": "user_uuid",
    "name": "工作流名称",
    "description": "工作流描述",
    "timer": "0 0 * * *",
    "actions": "[{\"id\": \"action1\", \"type\": \"test\"}]",
    "flows": "[{\"id\": \"flow1\", \"source\": \"action1\"}]",
    "context": "{}",
    "date": "2024-01-01 12:00:00",
    "count": 5
  }
]
```

## 配置说明

工作流分享功能使用独立的配置项 `WORKFLOW_STATISTIC_SHARE`，当该配置为 `true` 时，工作流分享功能才会启用。

### 配置项
- `WORKFLOW_STATISTIC_SHARE`: 工作流数据共享开关，默认为 `true`

## 服务器接口

工作流分享功能与订阅分享使用同一个服务器，服务器接口定义如下：

```python
class WorkflowShareItem(BaseModel):
    id: Optional[int] = None
    share_title: Optional[str] = None
    share_comment: Optional[str] = None
    share_user: Optional[str] = None
    share_uid: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    timer: Optional[str] = None
    actions: Optional[str] = None  # JSON字符串
    flows: Optional[str] = None  # JSON字符串
    context: Optional[str] = None  # JSON字符串
    date: Optional[str] = None

# 工作流分享相关接口
@App.post("/workflow/share")
def workflow_share(workflow: WorkflowShareItem, db: Session = Depends(get_db)):
    """新增工作流分享"""

@App.delete("/workflow/share/{sid}")
def workflow_share_delete(sid: int, share_uid: str, db: Session = Depends(get_db)):
    """删除工作流分享"""

@App.get("/workflow/shares")
def workflow_shares(name: str = None, page: int = 1, count: int = 30, db: Session = Depends(get_db)):
    """查询分享的工作流"""

@App.get("/workflow/fork/{shareid}")
def workflow_fork(shareid: int, db: Session = Depends(get_db)):
    """复用分享的工作流"""
```

## 使用说明

1. **启用功能**: 确保 `WORKFLOW_STATISTIC_SHARE` 配置为 `true`
2. **分享工作流**: 通过API接口分享本地工作流到公共服务器
3. **查看分享**: 查询公共服务器上的工作流分享
4. **复用工作流**: 将其他用户分享的工作流复制到本地使用
5. **管理分享**: 删除自己分享的工作流

## 技术改进

1. **独立配置**: 工作流分享功能使用独立的配置开关，不再依赖订阅分享配置
2. **数据访问层**: 使用WorkflowOper进行数据库操作，提高代码的可维护性和一致性
3. **错误处理**: 完善的错误处理和参数验证
4. **类型安全**: 修复了所有类型相关的linter错误

## 注意事项

1. 工作流分享功能需要网络连接才能访问公共服务器
2. 复用的工作流默认状态为暂停，需要手动启用
3. 工作流名称不能重复，复用时会检查本地是否存在同名工作流
4. 分享的工作流数据以JSON字符串形式存储，包含actions、flows、context等字段