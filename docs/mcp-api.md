# MoviePilot 工具API文档

MoviePilot的智能体工具已通过HTTP API暴露，可以通过RESTful API调用所有工具。

## API端点

所有工具相关的API端点都在 `/api/v1/mcp` 路径下（保持向后兼容）。

### 1. 列出所有工具

**GET** `/api/v1/mcp/tools`

获取所有可用的MCP工具列表。

**认证**: 需要API KEY，从 URL 查询参数中获取 `apikey=xxx`，或请求头中获取 `X-API-KEY`

**响应示例**:
```json
[
  {
    "name": "add_subscribe",
    "description": "Add media subscription to create automated download rules...",
    "inputSchema": {
      "type": "object",
      "properties": {
        "title": {
          "type": "string",
          "description": "The title of the media to subscribe to"
        },
        "year": {
          "type": "string",
          "description": "Release year of the media"
        },
        ...
      },
      "required": ["title", "year", "media_type"]
    }
  },
  ...
]
```

### 2. 调用工具

**POST** `/api/v1/mcp/tools/call`

调用指定的MCP工具。

**认证**: 需要Bearer Token

**请求体**:
```json
{
  "tool_name": "add_subscribe",
  "arguments": {
    "title": "流浪地球",
    "year": "2019",
    "media_type": "电影"
  }
}
```

**响应示例**:
```json
{
  "success": true,
  "result": "成功添加订阅：流浪地球 (2019)",
  "error": null
}
```

**错误响应示例**:
```json
{
  "success": false,
  "result": null,
  "error": "调用工具失败: 参数验证失败"
}
```

### 3. 获取工具详情

**GET** `/api/v1/mcp/tools/{tool_name}`

获取指定工具的详细信息。

**认证**: 需要Bearer Token

**路径参数**:
- `tool_name`: 工具名称

**响应示例**:
```json
{
  "name": "add_subscribe",
  "description": "Add media subscription to create automated download rules...",
  "inputSchema": {
    "type": "object",
    "properties": {
      "title": {
        "type": "string",
        "description": "The title of the media to subscribe to"
      },
      ...
    },
    "required": ["title", "year", "media_type"]
  }
}
```

### 4. 获取工具参数Schema

**GET** `/api/v1/mcp/tools/{tool_name}/schema`

获取指定工具的参数Schema（JSON Schema格式）。

**认证**: 需要Bearer Token

**路径参数**:
- `tool_name`: 工具名称

**响应示例**:
```json
{
  "type": "object",
  "properties": {
    "title": {
      "type": "string",
      "description": "The title of the media to subscribe to"
    },
    "year": {
      "type": "string",
      "description": "Release year of the media"
    },
    ...
  },
  "required": ["title", "year", "media_type"]
}
```

## 使用示例

### 使用curl调用工具

```bash
# 1. 获取访问令牌（通过登录API）
TOKEN=$(curl -X POST "http://localhost:3001/api/v1/login/access-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=your_password" | jq -r '.access_token')

# 2. 列出所有工具
curl -X GET "http://localhost:3001/api/v1/mcp/tools" \
  -H "Authorization: Bearer $TOKEN"

# 3. 调用工具
curl -X POST "http://localhost:3001/api/v1/mcp/tools/call" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "query_subscribes",
    "arguments": {
      "status": "all",
      "media_type": "all"
    }
  }'

# 4. 获取工具详情
curl -X GET "http://localhost:3001/api/v1/mcp/tools/add_subscribe" \
  -H "Authorization: Bearer $TOKEN"
```

### 使用Python调用

```python
import requests

# 配置
BASE_URL = "http://localhost:3001/api/v1"
TOKEN = "your_access_token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# 1. 列出所有工具
response = requests.get(f"{BASE_URL}/mcp/tools", headers=HEADERS)
tools = response.json()
print(f"可用工具数量: {len(tools)}")

# 2. 调用工具
tool_call = {
    "tool_name": "add_subscribe",
    "arguments": {
        "title": "流浪地球",
        "year": "2019",
        "media_type": "电影"
    }
}
response = requests.post(
    f"{BASE_URL}/mcp/tools/call",
    headers=HEADERS,
    json=tool_call
)
result = response.json()
print(f"执行结果: {result['result']}")

# 3. 获取工具Schema
response = requests.get(
    f"{BASE_URL}/mcp/tools/add_subscribe/schema",
    headers=HEADERS
)
schema = response.json()
print(f"工具Schema: {schema}")
```

### 使用JavaScript/TypeScript调用

```typescript
const BASE_URL = 'http://localhost:3001/api/v1';
const TOKEN = 'your_access_token';

// 列出所有工具
async function listTools() {
  const response = await fetch(`${BASE_URL}/mcp/tools`, {
    headers: {
      'Authorization': `Bearer ${TOKEN}`
    }
  });
  return await response.json();
}

// 调用工具
async function callTool(toolName: string, arguments: Record<string, any>) {
  const response = await fetch(`${BASE_URL}/mcp/tools/call`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      tool_name: toolName,
      arguments: arguments
    })
  });
  return await response.json();
}

// 使用示例
const result = await callTool('query_subscribes', {
  status: 'all',
  media_type: 'all'
});
console.log(result);
```

## 认证

所有MCP API端点都需要认证。支持以下认证方式：

1. **Bearer Token**: 在请求头中添加 `Authorization: Bearer <token>`
2. **API Key**: 在请求头中添加 `X-API-KEY: <api_key>` 或在查询参数中添加 `apikey=<api_key>`

获取Token的方式：
- 通过登录API: `POST /api/v1/login/access-token`
- 通过API Key: 在系统设置中生成API Key

## 错误处理

API会返回标准的HTTP状态码：

- `200 OK`: 请求成功
- `400 Bad Request`: 请求参数错误
- `401 Unauthorized`: 未认证或Token无效
- `404 Not Found`: 工具不存在
- `500 Internal Server Error`: 服务器内部错误

错误响应格式：
```json
{
  "detail": "错误描述信息"
}
```

## 架构说明

工具API通过FastAPI端点暴露，使用HTTP协议与客户端通信。所有工具共享相同的实现，确保功能一致性。

## 注意事项

1. **用户上下文**: API调用会使用当前认证用户的ID作为工具执行的用户上下文
2. **会话隔离**: 每个API请求使用独立的会话ID
3. **参数验证**: 工具参数会根据JSON Schema进行验证
4. **错误日志**: 所有工具调用错误都会记录到MoviePilot日志系统

