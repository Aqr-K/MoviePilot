# MoviePilot 工具API文档

MoviePilot的智能体工具已通过HTTP API暴露，可以通过RESTful API调用所有工具。

## API端点

所有工具相关的API端点都在 `/api/v1/mcp` 路径下（保持向后兼容）。

### 1. 列出所有工具

**GET** `/api/v1/mcp/tools`

获取所有可用的MCP工具列表。

**认证**: 需要API KEY，在请求头中添加 `X-API-KEY: <api_key>` 或在查询参数中添加 `apikey=<api_key>`

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

**认证**: 需要API KEY，在请求头中添加 `X-API-KEY: <api_key>` 或在查询参数中添加 `apikey=<api_key>`

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

**认证**: 需要API KEY，在请求头中添加 `X-API-KEY: <api_key>` 或在查询参数中添加 `apikey=<api_key>`

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

**认证**: 需要API KEY，在请求头中添加 `X-API-KEY: <api_key>` 或在查询参数中添加 `apikey=<api_key>`

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

## MCP客户端配置

MoviePilot的MCP工具可以通过HTTP协议在支持MCP的客户端中使用。以下是常见MCP客户端的配置方法：

### Claude Desktop (Anthropic)

在Claude Desktop的配置文件中添加MoviePilot的MCP服务器配置：

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "moviepilot": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-http",
        "http://localhost:3001/api/v1/mcp"
      ],
      "env": {
        "X-API-KEY": "your_api_key_here"
      }
    }
  }
}
```

**注意**: 如果MCP HTTP服务器不支持环境变量传递API Key，可以使用查询参数方式：

```json
{
  "mcpServers": {
    "moviepilot": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-http",
        "http://localhost:3001/api/v1/mcp?apikey=your_api_key_here"
      ]
    }
  }
}
```

### 其他支持MCP的聊天客户端

对于其他支持MCP协议的聊天客户端（如其他AI聊天助手、对话机器人等），通常可以通过配置文件或设置界面添加HTTP协议的MCP服务器。配置格式可能因客户端而异，但通常需要以下信息：

**配置参数**：
1. **服务器类型**: HTTP
2. **服务器地址**: `http://your-moviepilot-host:3001/api/v1/mcp`
3. **认证方式**: 
   - 在HTTP请求头中添加 `X-API-KEY: <your_api_key>`
   - 或在URL查询参数中添加 `apikey=<your_api_key>`

**示例配置**（通用格式）：

使用请求头方式：
```json
{
  "mcpServers": {
    "moviepilot": {
      "url": "http://localhost:3001/api/v1/mcp",
      "headers": {
        "X-API-KEY": "your_api_key_here"
      }
    }
  }
}
```

或使用查询参数方式：
```json
{
  "mcpServers": {
    "moviepilot": {
      "url": "http://localhost:3001/api/v1/mcp?apikey=your_api_key_here"
    }
  }
}
```

**支持的端点**:
- `GET /tools` - 列出所有工具
- `POST /tools/call` - 调用工具
- `GET /tools/{tool_name}` - 获取工具详情
- `GET /tools/{tool_name}/schema` - 获取工具参数Schema

配置完成后，您就可以在聊天对话中使用MoviePilot的各种工具，例如：
- 添加媒体订阅
- 查询下载历史
- 搜索媒体资源
- 管理媒体服务器
- 等等...

### 获取API Key

API Key可以在MoviePilot的系统设置中生成和查看。请妥善保管您的API Key，不要泄露给他人。

## 认证

所有MCP API端点都需要认证。**仅支持API Key认证方式**：

- **请求头方式**: 在请求头中添加 `X-API-KEY: <api_key>`
- **查询参数方式**: 在URL查询参数中添加 `apikey=<api_key>`

**获取API Key**: 在MoviePilot系统设置中生成和查看API Key。请妥善保管您的API Key，不要泄露给他人。

## 错误处理

API会返回标准的HTTP状态码：

- `200 OK`: 请求成功
- `400 Bad Request`: 请求参数错误
- `401 Unauthorized`: 未认证或API Key无效
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

