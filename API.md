# DS2API 接口文档（Go 实现）

语言 / Language: [中文](API.md) | [English](API.en.md)

本文档描述当前代码库的实际 API 行为（Go 后端）。

## 基础信息

- Base URL：`http://localhost:5001` 或你的部署域名
- 默认返回：`application/json`
- 健康检查：`GET /healthz`、`GET /readyz`

### 鉴权规则

业务接口（`/v1/*`、`/anthropic/*`）支持两种传参：

1. `Authorization: Bearer <token>`
2. `x-api-key: <token>`（无 `Bearer` 前缀）

Admin 接口：

- `POST /admin/login` 无需鉴权
- `GET /admin/verify` 需要 `Authorization: Bearer <jwt>`（仅 JWT）
- 其他 `/admin/*` 保护接口支持：
- `Authorization: Bearer <jwt>`
- `Authorization: Bearer <admin_key>`（直传管理密钥）

## 路由总览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 存活探针 |
| GET | `/readyz` | 就绪探针 |
| GET | `/v1/models` | OpenAI 模型列表 |
| POST | `/v1/chat/completions` | OpenAI 对话补全 |
| GET | `/anthropic/v1/models` | Claude 模型列表 |
| POST | `/anthropic/v1/messages` | Claude 消息接口 |
| POST | `/anthropic/v1/messages/count_tokens` | Claude token 计数 |
| POST | `/admin/login` | 管理登录 |
| GET | `/admin/verify` | 校验管理 JWT |
| GET | `/admin/vercel/config` | 读取 Vercel 预配置 |
| GET | `/admin/config` | 读取配置（脱敏） |
| POST | `/admin/config` | 更新配置 |
| POST | `/admin/keys` | 添加 API key |
| DELETE | `/admin/keys/{key}` | 删除 API key |
| GET | `/admin/accounts` | 分页账号列表 |
| POST | `/admin/accounts` | 添加账号 |
| DELETE | `/admin/accounts/{identifier}` | 删除账号 |
| GET | `/admin/queue/status` | 账号队列状态 |
| POST | `/admin/accounts/test` | 测试单个账号 |
| POST | `/admin/accounts/test-all` | 测试全部账号 |
| POST | `/admin/import` | 批量导入 keys/accounts |
| POST | `/admin/test` | 测试当前 API 可用性 |
| POST | `/admin/vercel/sync` | 同步配置到 Vercel |
| GET | `/admin/vercel/status` | Vercel 同步状态 |
| GET | `/admin/export` | 导出配置 JSON/Base64 |

## 健康检查

### `GET /healthz`

响应：

```json
{"status":"ok"}
```

### `GET /readyz`

响应：

```json
{"status":"ready"}
```

## OpenAI 兼容接口

### `GET /v1/models`

无需鉴权。

响应示例：

```json
{
  "object": "list",
  "data": [
    {"id": "deepseek-chat", "object": "model", "created": 1677610602, "owned_by": "deepseek", "permission": []},
    {"id": "deepseek-reasoner", "object": "model", "created": 1677610602, "owned_by": "deepseek", "permission": []},
    {"id": "deepseek-chat-search", "object": "model", "created": 1677610602, "owned_by": "deepseek", "permission": []},
    {"id": "deepseek-reasoner-search", "object": "model", "created": 1677610602, "owned_by": "deepseek", "permission": []}
  ]
}
```

### `POST /v1/chat/completions`

请求头示例：

```http
Authorization: Bearer your-api-key
Content-Type: application/json
```

请求体核心字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `model` | string | 是 | `deepseek-chat` / `deepseek-reasoner` / `deepseek-chat-search` / `deepseek-reasoner-search` |
| `messages` | array | 是 | OpenAI 风格消息数组 |
| `stream` | boolean | 否 | 默认 `false` |
| `tools` | array | 否 | Function Calling 定义 |
| `temperature` 等 | any | 否 | 兼容透传字段（最终是否生效由上游决定） |

非流式响应示例：

```json
{
  "id": "<chat_session_id>",
  "object": "chat.completion",
  "created": 1738400000,
  "model": "deepseek-reasoner",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "最终回复",
        "reasoning_content": "思考内容（reasoner 模型）"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 20,
    "total_tokens": 30,
    "completion_tokens_details": {
      "reasoning_tokens": 5
    }
  }
}
```

### OpenAI 流式（`stream=true`）

SSE 格式：每段为 `data: <json>\n\n`，结束为 `data: [DONE]`。

- 首次 delta 可能包含 `role: assistant`
- reasoner 模型会输出 `delta.reasoning_content`
- 普通文本输出 `delta.content`
- 最后一段包含 `finish_reason`，并附带 usage

示例：

```text
data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant"},"index":0}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"reasoning_content":"..."},"index":0}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"content":"..."},"index":0}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{...}}

data: [DONE]
```

### Tool Calls（重点）

请求中带 `tools` 时，服务端会注入工具提示并尝试解析模型输出。

- 非流式：若识别到工具调用，返回 `message.tool_calls`，并设置 `finish_reason=tool_calls`，`message.content=null`
- 流式：为防止原始 toolcall JSON 泄漏，正文会先缓冲；若识别到工具调用，仅输出结构化 `delta.tool_calls`
- 流式 `delta.tool_calls` 兼容严格客户端：每个 tool call 对象都带 `index`（从 `0` 开始）

工具调用响应示例：

```json
{
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": null,
        "tool_calls": [
          {
            "id": "call_xxx",
            "type": "function",
            "function": {
              "name": "get_weather",
              "arguments": "{\"city\":\"beijing\"}"
            }
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ]
}
```

## Claude 兼容接口

### `GET /anthropic/v1/models`

无需鉴权。

响应示例：

```json
{
  "object": "list",
  "data": [
    {"id": "claude-sonnet-4-20250514", "object": "model", "created": 1715635200, "owned_by": "anthropic"},
    {"id": "claude-sonnet-4-20250514-fast", "object": "model", "created": 1715635200, "owned_by": "anthropic"},
    {"id": "claude-sonnet-4-20250514-slow", "object": "model", "created": 1715635200, "owned_by": "anthropic"}
  ]
}
```

### `POST /anthropic/v1/messages`

请求头可用：

```http
x-api-key: your-api-key
Content-Type: application/json
anthropic-version: 2023-06-01
```

请求体核心字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `model` | string | 是 | `claude-sonnet-4-20250514` / `-fast` / `-slow` |
| `messages` | array | 是 | Claude 风格消息数组 |
| `max_tokens` | number | 否 | 当前实现不会硬性截断上游输出 |
| `stream` | boolean | 否 | 默认 `false` |
| `system` | string | 否 | 可选系统提示 |
| `tools` | array | 否 | Claude tool 定义 |

非流式响应示例：

```json
{
  "id": "msg_1738400000000000000",
  "type": "message",
  "role": "assistant",
  "model": "claude-sonnet-4-20250514",
  "content": [
    {"type": "text", "text": "回复内容"}
  ],
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 12,
    "output_tokens": 34
  }
}
```

若识别到工具调用，`stop_reason=tool_use`，并在 `content` 中返回 `tool_use` block。

### Claude 流式（`stream=true`）

返回同样是 SSE，但当前实现仅写入 `data:` 行，不输出 `event:` 行。每条 JSON 内包含 `type` 字段。

示例：

```text
data: {"type":"message_start","message":{...}}

data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

data: {"type":"content_block_stop","index":0}

data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":12}}

data: {"type":"message_stop"}
```

### `POST /anthropic/v1/messages/count_tokens`

请求示例：

```json
{
  "model": "claude-sonnet-4-20250514",
  "messages": [
    {"role": "user", "content": "你好"}
  ]
}
```

响应示例：

```json
{
  "input_tokens": 5
}
```

## Admin 接口

### `POST /admin/login`

请求：

```json
{
  "admin_key": "admin",
  "expire_hours": 24
}
```

说明：`expire_hours` 可省略，默认 24。

响应：

```json
{
  "success": true,
  "token": "<jwt>",
  "expires_in": 86400
}
```

### `GET /admin/verify`

请求头：`Authorization: Bearer <jwt>`

响应：

```json
{
  "valid": true,
  "expires_at": 1738400000,
  "remaining_seconds": 72000
}
```

### `GET /admin/vercel/config`

返回是否存在 Vercel 预配置：

```json
{
  "has_token": true,
  "project_id": "prj_xxx",
  "team_id": null
}
```

### `GET /admin/config`

返回脱敏配置：

```json
{
  "keys": ["k1", "k2"],
  "accounts": [
    {
      "email": "user@example.com",
      "mobile": "",
      "has_password": true,
      "has_token": true,
      "token_preview": "abcde..."
    }
  ],
  "claude_mapping": {
    "fast": "deepseek-chat",
    "slow": "deepseek-reasoner"
  }
}
```

### `POST /admin/config`

可更新 `keys`、`accounts`、`claude_mapping`。

请求示例：

```json
{
  "keys": ["k1", "k2"],
  "accounts": [
    {"email": "user@example.com", "password": "pwd", "token": ""}
  ],
  "claude_mapping": {
    "fast": "deepseek-chat",
    "slow": "deepseek-reasoner"
  }
}
```

### `POST /admin/keys`

请求：

```json
{"key":"new-api-key"}
```

响应：

```json
{"success":true,"total_keys":3}
```

### `DELETE /admin/keys/{key}`

响应：

```json
{"success":true,"total_keys":2}
```

### `GET /admin/accounts`

查询参数：

- `page`（默认 1）
- `page_size`（默认 10，最大 100）

响应：

```json
{
  "items": [
    {
      "email": "user@example.com",
      "mobile": "",
      "has_password": true,
      "has_token": true,
      "token_preview": "abc..."
    }
  ],
  "total": 25,
  "page": 1,
  "page_size": 10,
  "total_pages": 3
}
```

### `POST /admin/accounts`

请求示例：

```json
{"email":"user@example.com","password":"pwd"}
```

响应：

```json
{"success":true,"total_accounts":6}
```

### `DELETE /admin/accounts/{identifier}`

`identifier` 为 email 或 mobile。

响应：

```json
{"success":true,"total_accounts":5}
```

### `GET /admin/queue/status`

响应：

```json
{
  "available": 3,
  "in_use": 1,
  "total": 4,
  "available_accounts": ["a@example.com"],
  "in_use_accounts": ["b@example.com"],
  "max_inflight_per_account": 2,
  "recommended_concurrency": 8
}
```

字段说明：

- `max_inflight_per_account`：每个账号允许的并发 in-flight 请求上限（默认 `2`，可由环境变量覆盖）
- `recommended_concurrency`：建议客户端并发值，按 `账号数量 × max_inflight_per_account` 动态计算

### `POST /admin/accounts/test`

请求字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `identifier` | 是 | email 或 mobile |
| `model` | 否 | 默认 `deepseek-chat` |
| `message` | 否 | 空字符串时仅测试建会话 |

响应示例：

```json
{
  "account": "user@example.com",
  "success": true,
  "response_time": 1240,
  "message": "API 测试成功（仅会话创建）",
  "model": "deepseek-chat"
}
```

### `POST /admin/accounts/test-all`

请求可选：`model`

响应示例：

```json
{
  "total": 5,
  "success": 4,
  "failed": 1,
  "results": []
}
```

### `POST /admin/import`

请求支持同时导入 `keys` 与 `accounts`：

```json
{
  "keys": ["k1", "k2"],
  "accounts": [
    {"email":"user@example.com","password":"pwd","token":""}
  ]
}
```

响应：

```json
{
  "success": true,
  "imported_keys": 2,
  "imported_accounts": 1
}
```

### `POST /admin/test`

请求字段（均可选）：

- `model`（默认 `deepseek-chat`）
- `message`（默认 `你好`）
- `api_key`（默认使用配置中第一个 key）

响应示例：

```json
{
  "success": true,
  "status_code": 200,
  "response": {"id":"..."}
}
```

### `POST /admin/vercel/sync`

请求字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `vercel_token` | 否 | 传空或 `__USE_PRECONFIG__` 则读环境变量 |
| `project_id` | 否 | 为空则读 `VERCEL_PROJECT_ID` |
| `team_id` | 否 | 为空则读 `VERCEL_TEAM_ID` |
| `auto_validate` | 否 | 默认 `true` |
| `save_credentials` | 否 | 默认 `true` |

成功响应示例：

```json
{
  "success": true,
  "validated_accounts": 3,
  "message": "配置已同步，正在重新部署...",
  "deployment_url": "https://..."
}
```

或：

```json
{
  "success": true,
  "validated_accounts": 3,
  "message": "配置已同步到 Vercel，请手动触发重新部署",
  "manual_deploy_required": true
}
```

### `GET /admin/vercel/status`

响应：

```json
{
  "synced": true,
  "last_sync_time": 1738400000,
  "has_synced_before": true
}
```

### `GET /admin/export`

响应：

```json
{
  "json": "{...}",
  "base64": "ey4uLn0="
}
```

## 错误响应格式

不同模块错误格式不完全一致（按当前实现）：

- OpenAI 接口：`{"error":{"message":"...","type":"..."}}`
- Claude 接口常见：`{"error":{"type":"...","message":"..."}}`
- Admin 接口常见：`{"detail":"..."}`

建议客户端至少处理：HTTP 状态码 + `error` / `detail` 字段。

## cURL 示例

### OpenAI 非流式

```bash
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "你好"}],
    "stream": false
  }'
```

### OpenAI 流式

```bash
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-reasoner",
    "messages": [{"role": "user", "content": "解释一下量子纠缠"}],
    "stream": true
  }'
```

### Claude

```bash
curl http://localhost:5001/anthropic/v1/messages \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "你好"}]
  }'
```
