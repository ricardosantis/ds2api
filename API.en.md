# DS2API API Reference (Go Implementation)

Language: [中文](API.md) | [English](API.en.md)

This document describes the actual behavior of the current Go codebase.

## Basics

- Base URL: `http://localhost:5001` or your deployment domain
- Default content type: `application/json`
- Health probes: `GET /healthz`, `GET /readyz`

### Authentication Rules

Business endpoints (`/v1/*`, `/anthropic/*`) accept either:

1. `Authorization: Bearer <token>`
2. `x-api-key: <token>` (without `Bearer`)

Admin endpoints:

- `POST /admin/login` is public
- `GET /admin/verify` requires `Authorization: Bearer <jwt>` (JWT only)
- Other protected `/admin/*` endpoints accept:
- `Authorization: Bearer <jwt>`
- `Authorization: Bearer <admin_key>`

## Route Index

| Method | Path | Description |
| --- | --- | --- |
| GET | `/healthz` | Liveness probe |
| GET | `/readyz` | Readiness probe |
| GET | `/v1/models` | OpenAI model list |
| POST | `/v1/chat/completions` | OpenAI chat completions |
| GET | `/anthropic/v1/models` | Claude model list |
| POST | `/anthropic/v1/messages` | Claude messages |
| POST | `/anthropic/v1/messages/count_tokens` | Claude token counting |
| POST | `/admin/login` | Admin login |
| GET | `/admin/verify` | Verify admin JWT |
| GET | `/admin/vercel/config` | Read preconfigured Vercel creds |
| GET | `/admin/config` | Read sanitized config |
| POST | `/admin/config` | Update config |
| POST | `/admin/keys` | Add API key |
| DELETE | `/admin/keys/{key}` | Delete API key |
| GET | `/admin/accounts` | Paginated account list |
| POST | `/admin/accounts` | Add account |
| DELETE | `/admin/accounts/{identifier}` | Delete account |
| GET | `/admin/queue/status` | Account queue status |
| POST | `/admin/accounts/test` | Test one account |
| POST | `/admin/accounts/test-all` | Test all accounts |
| POST | `/admin/import` | Batch import keys/accounts |
| POST | `/admin/test` | Test API through current service |
| POST | `/admin/vercel/sync` | Sync config to Vercel |
| GET | `/admin/vercel/status` | Vercel sync status |
| GET | `/admin/export` | Export config JSON/Base64 |

## Health Endpoints

### `GET /healthz`

```json
{"status":"ok"}
```

### `GET /readyz`

```json
{"status":"ready"}
```

## OpenAI-Compatible API

### `GET /v1/models`

No auth required.

Example response:

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

Headers:

```http
Authorization: Bearer your-api-key
Content-Type: application/json
```

Core request fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `model` | string | yes | `deepseek-chat` / `deepseek-reasoner` / `deepseek-chat-search` / `deepseek-reasoner-search` |
| `messages` | array | yes | OpenAI-style messages |
| `stream` | boolean | no | default `false` |
| `tools` | array | no | Function calling schema |
| `temperature`, etc. | any | no | accepted in request; final behavior depends on upstream |

Non-stream example:

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
        "content": "final response",
        "reasoning_content": "reasoning trace"
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

### OpenAI Streaming (`stream=true`)

SSE format: each frame is `data: <json>\n\n`, terminated by `data: [DONE]`.

- First delta may include `role: assistant`
- Reasoning models emit `delta.reasoning_content`
- Text emits `delta.content`
- Last chunk includes `finish_reason` and usage

Example:

```text
data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant"},"index":0}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"reasoning_content":"..."},"index":0}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"content":"..."},"index":0}]}

data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{...}}

data: [DONE]
```

### Tool Calls (Important)

When `tools` is present, DS2API injects a tool prompt and parses tool-call payloads.

- Non-stream: if detected, returns `message.tool_calls`, `finish_reason=tool_calls`, and `message.content=null`
- Stream: to avoid leaking raw tool-call JSON, DS2API buffers text first; if tool call is detected, only structured `delta.tool_calls` is emitted
- Stream `delta.tool_calls` is strict-client compatible: each tool call object includes `index` (starting from `0`)

Tool-call response example:

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

## Claude-Compatible API

### `GET /anthropic/v1/models`

No auth required.

Example response:

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

Headers can be:

```http
x-api-key: your-api-key
Content-Type: application/json
anthropic-version: 2023-06-01
```

Core request fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `model` | string | yes | `claude-sonnet-4-20250514` / `-fast` / `-slow` |
| `messages` | array | yes | Claude-style messages |
| `max_tokens` | number | no | currently not strictly enforced by upstream bridge |
| `stream` | boolean | no | default `false` |
| `system` | string | no | optional system prompt |
| `tools` | array | no | Claude tool schema |

Non-stream example:

```json
{
  "id": "msg_1738400000000000000",
  "type": "message",
  "role": "assistant",
  "model": "claude-sonnet-4-20250514",
  "content": [
    {"type": "text", "text": "response"}
  ],
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 12,
    "output_tokens": 34
  }
}
```

If tool use is detected, `stop_reason` becomes `tool_use` and `content` contains `tool_use` blocks.

### Claude Streaming (`stream=true`)

Still SSE, but current implementation writes `data:` lines only (no `event:` lines). Event type is carried in JSON `type`.

Example:

```text
data: {"type":"message_start","message":{...}}

data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

data: {"type":"content_block_stop","index":0}

data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":12}}

data: {"type":"message_stop"}
```

### `POST /anthropic/v1/messages/count_tokens`

Request example:

```json
{
  "model": "claude-sonnet-4-20250514",
  "messages": [
    {"role": "user", "content": "Hello"}
  ]
}
```

Response example:

```json
{
  "input_tokens": 5
}
```

## Admin API

### `POST /admin/login`

Request:

```json
{
  "admin_key": "admin",
  "expire_hours": 24
}
```

`expire_hours` is optional, default 24.

Response:

```json
{
  "success": true,
  "token": "<jwt>",
  "expires_in": 86400
}
```

### `GET /admin/verify`

Header: `Authorization: Bearer <jwt>`

Response:

```json
{
  "valid": true,
  "expires_at": 1738400000,
  "remaining_seconds": 72000
}
```

### `GET /admin/vercel/config`

```json
{
  "has_token": true,
  "project_id": "prj_xxx",
  "team_id": null
}
```

### `GET /admin/config`

Sanitized config response:

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

Updatable fields: `keys`, `accounts`, `claude_mapping`.

Request example:

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

```json
{"key":"new-api-key"}
```

Response:

```json
{"success":true,"total_keys":3}
```

### `DELETE /admin/keys/{key}`

```json
{"success":true,"total_keys":2}
```

### `GET /admin/accounts`

Query params:

- `page` (default 1)
- `page_size` (default 10, max 100)

Response:

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

```json
{"email":"user@example.com","password":"pwd"}
```

```json
{"success":true,"total_accounts":6}
```

### `DELETE /admin/accounts/{identifier}`

`identifier` is email or mobile.

```json
{"success":true,"total_accounts":5}
```

### `GET /admin/queue/status`

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

Field notes:

- `max_inflight_per_account`: per-account in-flight limit (default `2`, override via env)
- `recommended_concurrency`: suggested client concurrency, dynamically computed as `account_count * max_inflight_per_account`

### `POST /admin/accounts/test`

Request fields:

| Field | Required | Notes |
| --- | --- | --- |
| `identifier` | yes | email or mobile |
| `model` | no | default `deepseek-chat` |
| `message` | no | if empty, only session creation is tested |

Response example:

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

Optional request field: `model`.

```json
{
  "total": 5,
  "success": 4,
  "failed": 1,
  "results": []
}
```

### `POST /admin/import`

```json
{
  "keys": ["k1", "k2"],
  "accounts": [
    {"email":"user@example.com","password":"pwd","token":""}
  ]
}
```

```json
{
  "success": true,
  "imported_keys": 2,
  "imported_accounts": 1
}
```

### `POST /admin/test`

Optional request fields:

- `model` (default `deepseek-chat`)
- `message` (default `你好`)
- `api_key` (default first key in config)

Response example:

```json
{
  "success": true,
  "status_code": 200,
  "response": {"id":"..."}
}
```

### `POST /admin/vercel/sync`

Request fields:

| Field | Required | Notes |
| --- | --- | --- |
| `vercel_token` | no | if empty or `__USE_PRECONFIG__`, read env |
| `project_id` | no | fallback: `VERCEL_PROJECT_ID` |
| `team_id` | no | fallback: `VERCEL_TEAM_ID` |
| `auto_validate` | no | default `true` |
| `save_credentials` | no | default `true` |

Success response example:

```json
{
  "success": true,
  "validated_accounts": 3,
  "message": "配置已同步，正在重新部署...",
  "deployment_url": "https://..."
}
```

Or manual deploy required:

```json
{
  "success": true,
  "validated_accounts": 3,
  "message": "配置已同步到 Vercel，请手动触发重新部署",
  "manual_deploy_required": true
}
```

### `GET /admin/vercel/status`

```json
{
  "synced": true,
  "last_sync_time": 1738400000,
  "has_synced_before": true
}
```

### `GET /admin/export`

```json
{
  "json": "{...}",
  "base64": "ey4uLn0="
}
```

## Error Payloads

Error payload formats are not fully unified in current code:

- OpenAI routes return: `{"error":{"message":"...","type":"..."}}`
- Claude routes often return: `{"error":{"type":"...","message":"..."}}`
- Admin routes often return: `{"detail":"..."}`

Clients should handle HTTP status code plus `error` / `detail` fields.

## cURL Examples

### OpenAI non-stream

```bash
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": false
  }'
```

### OpenAI stream

```bash
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-reasoner",
    "messages": [{"role": "user", "content": "Explain quantum entanglement"}],
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
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```
