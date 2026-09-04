# ADONWORD HTTP Protocol / ADONWORD HTTP 协议

ADONWORD `serve` mode exposes a small HTTP API on `127.0.0.1:8754` by default (`--host/--port` overridable). All responses are JSON.

ADONWORD `serve` 模式默认在 `127.0.0.1:8754` 提供一个小型 HTTP API（可用 `--host/--port` 覆盖）。所有响应均为 JSON。

## Endpoints / 端点

| Endpoint / 端点 | Method / 方法 | Auth / 认证 | Description / 说明 |
| --- | --- | --- | --- |
| `/health` | GET | none / 无 | Liveness probe. Returns / 返回 `{"ok":true}` |
| `/report` | GET | Bearer (optional / 可选) | Last persisted scan result / 最近一次持久化扫描结果 |
| `/invoke` | POST | Bearer (optional / 可选) | BIT Remote protocol entry / BIT Remote 协议入口 |

With `serve --token <TOKEN>`, `/report` and `/invoke` require `Authorization: Bearer <TOKEN>` (401 otherwise). `/health` stays open. / 使用 `serve --token <TOKEN>` 后，`/report` 与 `/invoke` 需要 `Authorization: Bearer <TOKEN>`（否则 401）；`/health` 保持开放。

## POST /invoke

Request body (BIT Remote payload) / 请求体（BIT Remote 载荷）:

```json
{
  "tool_id": "tool-uuid",
  "tool": "adonword",
  "invoked_by": "bit-agent",
  "params": { "action": "scan" }
}
```

Routing reads `params.action`, falling back to `params.tool`. Valid actions / 路由读取 `params.action`（回退 `params.tool`）。合法 action：

| action | Response payload / 响应载荷 |
| --- | --- |
| `scan` | Runs a live inspection, persists it to `state.json`. Returns / 实时巡检并持久化，返回 `{scanned_at, findings:[{kind,severity,detail,triggered_at}], summary:{total,warn,crit}}` |
| `baseline_check` | Returns / 返回 `{status:"clean"\|"changed"\|"missing", added:[], removed:[], modified:[], warnings:[]}` |
| `report` | Returns / 返回 `{status:"ok", report:{...}}` or / 或 `{status:"no_report", report:null}` |

Errors / 错误:

| HTTP | Meaning / 含义 |
| --- | --- |
| 400 | Unknown `action` / 未知 action |
| 401 | Missing or invalid Bearer token / 缺失或错误的 Bearer token |
| 500 | Internal error (walk/hash/IO failure) / 内部错误 |

## Example session / 示例会话

```bash
# health
curl http://127.0.0.1:8754/health
# -> {"ok":true}

# run a scan via BIT Remote protocol
curl -X POST http://127.0.0.1:8754/invoke \
     -H 'content-type: application/json' \
     -d '{"tool_id":"t1","tool":"adonword","invoked_by":"bit","params":{"action":"scan"}}'

# baseline check
curl -X POST http://127.0.0.1:8754/invoke \
     -H 'content-type: application/json' \
     -d '{"params":{"action":"baseline_check"}}'
# -> {"added":[],"modified":["a.txt"],"removed":[],"status":"changed","warnings":[]}

# last persisted report
curl http://127.0.0.1:8754/report
```

## Finding kinds / Finding 类型

| kind | severity | Trigger / 触发条件 |
| --- | --- | --- |
| `file_added` / `file_removed` / `file_modified` | warn | File tree differs from baseline / 文件树与基线不一致 |
| `baseline_missing` | warn | Scan without a baseline / 无基线时扫描 |
| `walk_warning` | warn | Skipped symlink / unreadable path / 跳过的符号链接或无权限路径 |
| `blocked_process` | crit | `[process].blocklist` match / 命中进程黑名单 |
| `unallowlisted_process` | warn | Outside a non-empty `[process].allowlist` / 非空白名单之外 |
| `unlisted_port` | warn | TCP LISTEN outside `[ports].allowed` / 监听端口不在白名单 |
| `config` / `port_scan_error` | warn | Config or port-enumeration warning / 配置或端口枚举告警 |

## CLI exit codes / CLI 退出码

| Command / 命令 | Codes / 退出码 |
| --- | --- |
| `baseline check` | `0` clean / `1` changed / `2` baseline missing / 基线缺失 |
| `scan` | `0` (findings are data, not errors) / findings 是数据不是错误 |
| other commands / 其他命令 | `0` success / `2` error |
