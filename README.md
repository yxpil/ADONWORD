# ADONWORD

Active-defense sentinel for AI agents — file-integrity baselines, suspicious-process monitoring and listening-port alerts, built for the BIT ecosystem.

[![Release](https://img.shields.io/github/v/release/yxpil/ADONWORD?style=flat-square)](https://github.com/yxpil/ADONWORD/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/yxpil/ADONWORD/total?style=flat-square)](https://github.com/yxpil/ADONWORD/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/yxpil/ADONWORD/ci.yml?style=flat-square&label=CI)](https://github.com/yxpil/ADONWORD/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-black?style=flat-square)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-black?style=flat-square)](https://github.com/yxpil/ADONWORD/releases)

---

## English

### About

ADONWORD is a local security-posture sentinel for AI agents (especially [BIT](https://github.com/yxpil/bit)). It watches the directories an agent works in, detects tampering against a sha256 file-integrity baseline, flags blacklisted processes and alerts on listening ports that are outside the allowlist.

**Scope**: observation + alerting only. ADONWORD never kills processes and never modifies your files (v0.1 policy).

### Features

- **File-integrity baseline** — full sha256 baseline over `[watch].paths` (relative path → hash → mtime), stored in `<data_dir>/baseline.json`. `baseline check` reports `added` / `removed` / `modified`; every current file is re-hashed (mtime is never trusted).
- **Process monitoring** — `[process].blocklist` (case-insensitive, `*` glob supported) produces `crit` findings; a non-empty `[process].allowlist` produces `warn` findings for processes outside it. Empty allowlist = no restriction.
- **Listening-port alerts** — TCP LISTEN sockets (via `netstat2`) are checked against `[ports].allowed` (single ports and `"8000-8100"` ranges).
- **Scan daemon** — `watch` runs a scan every N seconds (default 30), alerts to **stderr**, optionally POSTs each finding to a webhook (10 s timeout) and deduplicates the same finding for 5 minutes.
- **BIT integration** — CLI exec contract (JSON over stdin), Remote tool over HTTP, plain REST API.
- **Cross-platform** — macOS / Linux / Windows; symlinks and unreadable paths are skipped and recorded as warnings, never fatal.
- Rust (edition 2021), single static binary, data stored under `~/.adonword/` (override with `ADONWORD_DATA_DIR`).

### Install

Download a release binary:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `adonword-v0.1.0-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `adonword-v0.1.0-x86_64-apple-darwin.tar.gz` |
| Linux x64 | `adonword-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x64 | `adonword-v0.1.0-x86_64-pc-windows-msvc.zip` |

```bash
tar xzf adonword-v0.1.0-aarch64-apple-darwin.tar.gz
sudo mv adonword-v0.1.0-aarch64-apple-darwin/adonword /usr/local/bin/
adonword --version
```

Or build from source: `cargo install --git https://github.com/yxpil/ADONWORD` (checksums are produced by the release CI).

### Quick start

Configuration lives at `~/.adonword/adonword.toml` (create the file, or pass `-c/--config`). Full example:

```toml
[watch]
paths = ["/Users/me/agent-workspace"]   # recursive; target/ node_modules/ .git/ always skipped
exclude = ["*.log"]                     # extra name globs to skip (e.g. ".*" to skip hidden files)

[process]
blocklist = ["keylogger.exe"]           # presence => crit alert
allowlist = []                          # empty = no restriction

[ports]
allowed = [8751, 8752, 8753, 8754, 8755]  # listening-port allowlist; ranges: "8000-8100"
alert_unlisted = true

[alert]
webhook_url = ""                        # non-empty => POST JSON per finding (10s timeout)
```

```bash
adonword baseline update          # build the sha256 baseline
adonword baseline check           # exit 0 clean / 1 changed / 2 missing baseline (CI friendly)
adonword scan --json              # one full inspection, JSON findings on stdout
adonword watch --interval 30      # daemon: scan + alert (stderr + webhook, 5min dedup)
adonword report                   # latest scan result (state.json)
adonword serve --port 8754        # HTTP API, see below
```

Every subcommand accepts `--json`. When stdin is piped (not a TTY), a JSON object is read from stdin and merged over CLI args and config (stdin wins) — that is the BIT exec contract. Accepted stdin keys: `interval`, `host`, `port`, `token` (CLI overrides) and `watch`, `process`, `ports`, `alert` (config overrides), e.g. `echo '{"watch":{"paths":["/tmp/ws"]}}' | adonword scan --json`.

Findings kinds: `file_added` / `file_removed` / `file_modified` / `baseline_missing` / `walk_warning` (warn), `blocked_process` (crit), `unallowlisted_process` (warn), `unlisted_port` (warn), `config` / `port_scan_error` (warn).

### BIT Integration

Three ways to attach ADONWORD to BIT ([bit](https://github.com/yxpil/bit) tools.json snippets — paste-ready).

**1) CLI (BIT "exec" runtime)** — BIT spawns the binary and sends `params` as JSON on stdin; stdout returns JSON:

```json
{
  "name": "adonword-scan",
  "kind": "Script",
  "runtime": "exec",
  "code": "scan",
  "command": "adonword",
  "args": ["scan", "--json"],
  "description": "Run one full inspection: file integrity, suspicious processes, listening ports"
}
```

`params` are merged over the config, so BIT can point the scan at its own workspace without touching the TOML file, e.g. `params`: `{"watch": {"paths": ["/path/to/bit/workspace"]}}`.

**2) Remote tool (HTTP serve mode)** — start `adonword serve` (default `127.0.0.1:8754`), then register:

```json
{
  "name": "adonword",
  "kind": "Remote",
  "url": "http://127.0.0.1:8754/invoke",
  "access_key": "",
  "description": "ADONWORD sentinel: params.action = scan | baseline_check | report"
}
```

BIT POSTs `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {"action": "scan"}}` and receives the corresponding JSON.

**3) Plain HTTP API (curl)**:

```bash
curl http://127.0.0.1:8754/health
curl -X POST http://127.0.0.1:8754/invoke \
     -H 'content-type: application/json' \
     -d '{"params":{"action":"baseline_check"}}'
curl http://127.0.0.1:8754/report
```

**Typical scenario**: the BIT agent periodically calls `adonword scan` (exec or Remote) with `watch.paths` pointed at its own workspace. Any unexpected file modification, removal or addition — and any blacklisted process or unapproved listening port — surfaces as a finding the agent can report and act on.

### API

| Endpoint | Method | Description |
| --- | --- | --- |
| `/health` | GET | Liveness probe, returns `{"ok":true}` |
| `/report` | GET | Last persisted scan result (`{"status":"ok","report":{...}}` or `{"status":"no_report","report":null}`) |
| `/invoke` | POST | BIT Remote protocol; `params.action` = `scan` \| `baseline_check` \| `report` |

- `POST /invoke` body: `{"tool_id":"...","tool":"...","invoked_by":"...","params":{"action":"scan"}}`. Routing falls back to `params.tool`. Unknown action → HTTP 400; missing/invalid body → treated as empty params.
- `action=scan` runs a live inspection and persists it to `state.json` (so `/report` reflects it). `action=baseline_check` returns `{status, added, removed, modified, warnings}` with `status` = `clean` / `changed` / `missing`.
- `serve --token <TOKEN>` protects `/report` and `/invoke` with `Authorization: Bearer <TOKEN>` (401 otherwise). `/health` stays open.
- Serve binds `127.0.0.1:8754` by default; override with `--host/--port`. The BIT ecosystem ports are: memorypool 8751, howcueme 8752, neton 8753, **adonword 8754**, firelin 8755.

---

## 中文

### 简介

ADONWORD 是面向 AI 智能体（尤其是 [BIT](https://github.com/yxpil/bit)）的本机安全态势哨兵。它守护智能体工作的目录，基于 sha256 文件完整性基线检测篡改，识别黑名单进程，并对监听端口白名单之外的端口发出告警。

**定位**：只做观察 + 告警。ADONWORD 不会杀进程，也不会修改你的文件（v0.1 明确策略）。

### 功能

- **文件完整性基线** — 对 `[watch].paths` 计算全量 sha256 基线（相对路径 → hash → mtime），存于 `<data_dir>/baseline.json`。`baseline check` 输出 `added` / `removed` / `modified`；每次 check 都重新计算哈希，不信任 mtime。
- **进程监控** — `[process].blocklist`（大小写不敏感，支持 `*` 通配）命中即产生 `crit` 告警；`[process].allowlist` 非空时，白名单之外的进程产生 `warn` 告警。留空 = 不限制。
- **监听端口告警** — TCP LISTEN 套接字（基于 `netstat2`）对照 `[ports].allowed` 白名单（支持单端口与 `"8000-8100"` 范围写法）。
- **巡检守护** — `watch` 每 N 秒（默认 30s）执行一轮 scan：告警打印到 **stderr**，可按 finding POST webhook（超时 10s），同一 finding 5 分钟内去重。
- **BIT 集成** — CLI exec 契约（stdin JSON 合并）、Remote 工具（HTTP）、纯 REST API 三种方式。
- **跨平台** — macOS / Linux / Windows；符号链接与无权限路径跳过并记 warning，不会崩溃。
- Rust（edition 2021）单一静态二进制；数据存于 `~/.adonword/`（可用环境变量 `ADONWORD_DATA_DIR` 覆盖）。

### 安装

从 Release 下载对应平台的二进制：

| 平台 | 资产 |
| --- | --- |
| macOS Apple Silicon | `adonword-v0.1.0-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `adonword-v0.1.0-x86_64-apple-darwin.tar.gz` |
| Linux x64 | `adonword-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x64 | `adonword-v0.1.0-x86_64-pc-windows-msvc.zip` |

```bash
tar xzf adonword-v0.1.0-aarch64-apple-darwin.tar.gz
sudo mv adonword-v0.1.0-aarch64-apple-darwin/adonword /usr/local/bin/
adonword --version
```

或从源码安装：`cargo install --git https://github.com/yxpil/ADONWORD`（校验和由 Release CI 生成）。

### 快速上手

配置文件位于 `~/.adonword/adonword.toml`（也可用 `-c/--config` 指定）。完整示例：

```toml
[watch]
paths = ["/Users/me/agent-workspace"]   # 递归目录；target/ node_modules/ .git/ 始终忽略
exclude = ["*.log"]                     # 额外按文件名跳过（如 ".*" 跳过隐藏文件）

[process]
blocklist = ["keylogger.exe"]           # 出现即 crit 告警
allowlist = []                          # 留空不限制

[ports]
allowed = [8751, 8752, 8753, 8754, 8755]  # 监听端口白名单；范围写法 "8000-8100"
alert_unlisted = true

[alert]
webhook_url = ""                        # 非空则每个 finding POST JSON（超时 10s）
```

```bash
adonword baseline update          # 构建基线
adonword baseline check           # 退出码：0 无变化 / 1 有变化 / 2 基线缺失（可用于 CI）
adonword scan --json              # 单次全量巡检，findings 以 JSON 输出到 stdout
adonword watch --interval 30      # 守护模式：巡检 + 告警（stderr + webhook，5 分钟去重）
adonword report                   # 最近一次 scan 结果（state.json）
adonword serve --port 8754        # HTTP API，见下文
```

所有子命令均支持 `--json`。当 stdin 是管道（非 TTY）时，会从 stdin 读取一个 JSON 对象并合并覆盖 CLI 参数与配置（stdin 优先）——即 BIT exec 契约。可用的 stdin 键：`interval`、`host`、`port`、`token`（CLI 覆盖）与 `watch`、`process`、`ports`、`alert`（配置覆盖），例如 `echo '{"watch":{"paths":["/tmp/ws"]}}' | adonword scan --json`。

Finding 类型：`file_added` / `file_removed` / `file_modified` / `baseline_missing` / `walk_warning`（warn）、`blocked_process`（crit）、`unallowlisted_process`（warn）、`unlisted_port`（warn）、`config` / `port_scan_error`（warn）。

### BIT 集成

三种方式接入 BIT（以下为 [bit](https://github.com/yxpil/bit) tools.json 片段，可直接粘贴）。

**1) CLI（BIT "exec" 运行时）** — BIT 拉起二进制并通过 stdin 发送 `params` JSON；stdout 返回 JSON：

```json
{
  "name": "adonword-scan",
  "kind": "Script",
  "runtime": "exec",
  "code": "scan",
  "command": "adonword",
  "args": ["scan", "--json"],
  "description": "一次全量巡检：文件完整性、可疑进程、监听端口"
}
```

`params` 会合并覆盖配置，BIT 无需改动 TOML 即可把扫描指向自己的工作区，例如 `params`：`{"watch": {"paths": ["/path/to/bit/workspace"]}}`。

**2) Remote 工具（HTTP serve 模式）** — 先启动 `adonword serve`（默认 `127.0.0.1:8754`），再注册：

```json
{
  "name": "adonword",
  "kind": "Remote",
  "url": "http://127.0.0.1:8754/invoke",
  "access_key": "",
  "description": "ADONWORD 哨兵：params.action = scan | baseline_check | report"
}
```

BIT 会 POST `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {"action": "scan"}}` 并收到对应 JSON 响应。

**3) 纯 HTTP API（curl）**：

```bash
curl http://127.0.0.1:8754/health
curl -X POST http://127.0.0.1:8754/invoke \
     -H 'content-type: application/json' \
     -d '{"params":{"action":"baseline_check"}}'
curl http://127.0.0.1:8754/report
```

**典型场景**：BIT 智能体定期（exec 或 Remote 方式）调用 `adonword scan`，`watch.paths` 指向自己的工作区。任何意外的文件新增 / 删除 / 修改，以及任何黑名单进程或白名单之外的监听端口，都会作为 finding 呈现给智能体，由其上报并处置。

### API

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/health` | GET | 存活探针，返回 `{"ok":true}` |
| `/report` | GET | 最近一次持久化的扫描结果（`{"status":"ok","report":{...}}` 或 `{"status":"no_report","report":null}`） |
| `/invoke` | POST | BIT Remote 协议；`params.action` = `scan` \| `baseline_check` \| `report` |

- `POST /invoke` 请求体：`{"tool_id":"...","tool":"...","invoked_by":"...","params":{"action":"scan"}}`。路由会回退读取 `params.tool`。未知 action → HTTP 400；缺失/非法请求体 → 按空 params 处理。
- `action=scan` 会实时巡检并持久化到 `state.json`（`/report` 随之更新）。`action=baseline_check` 返回 `{status, added, removed, modified, warnings}`，`status` 为 `clean` / `changed` / `missing`。
- `serve --token <TOKEN>` 后 `/report` 与 `/invoke` 需要 `Authorization: Bearer <TOKEN>`（否则 401）。`/health` 保持开放。
- serve 默认绑定 `127.0.0.1:8754`，可用 `--host/--port` 覆盖。BIT 生态默认端口：memorypool 8751、howcueme 8752、neton 8753、**adonword 8754**、firelin 8755。

### 安全与合规

- ADONWORD 只读取文件元数据与内容哈希、进程名与监听端口，**不采集、不外传**任何其他数据；仅在 `[alert].webhook_url` 非空时向用户配置的地址 POST 告警 JSON。
- 基线与状态文件（`baseline.json`、`state.json`）保存在本机数据目录中，包含文件相对路径与哈希，不含文件内容。
- v0.1 不做任何阻断或查杀（不 kill 进程、不隔离文件），符合"观察 + 告警"的最小干预原则；请将 webhook 地址与 token 保管在自己的受信环境中。

---

Part of the [BIT](https://github.com/yxpil/bit) ecosystem — agents watching over agents.

License: [Apache-2.0](./LICENSE)
