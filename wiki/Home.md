# ADONWORD Wiki / ADONWORD 维基

**ADONWORD** — Active-defense sentinel for AI agents around the [BIT](https://github.com/yxpil/bit) ecosystem: file-integrity baselines, suspicious-process monitoring, listening-port alerts. Observation + alerting only — it never kills processes.

**ADONWORD** —— 面向 [BIT](https://github.com/yxpil/bit) 生态 AI 智能体的本机主动防御哨兵：文件完整性基线、可疑进程监控、监听端口告警。只做观察 + 告警，绝不杀进程。

- Repo / 仓库: <https://github.com/yxpil/ADONWORD>
- Releases / 发行版: <https://github.com/yxpil/ADONWORD/releases>
- Binary name / 二进制名: `adonword`
- Default port / 默认端口: `8754`
- Data dir / 数据目录: `~/.adonword`（env / 环境变量 `ADONWORD_DATA_DIR` 可覆盖）

---

## Install / 安装

Grab a per-platform binary from the [latest release](https://github.com/yxpil/ADONWORD/releases/latest) (`tar.gz` for macOS/Linux, `zip` for Windows), or:

从 [最新 Release](https://github.com/yxpil/ADONWORD/releases/latest) 下载对应平台二进制（macOS/Linux 为 `tar.gz`，Windows 为 `zip`），或：

```bash
cargo install --git https://github.com/yxpil/ADONWORD
```

## Usage / 使用

```bash
# 1. write ~/.adonword/adonword.toml (see README) / 先写配置文件
adonword baseline update          # build the sha256 baseline / 构建基线
adonword baseline check           # exit 0 clean / 1 changed / 2 missing baseline
adonword scan --json              # one full inspection / 单次全量巡检
adonword watch --interval 30      # daemon + alerts (stderr + webhook, 5-min dedup) / 守护 + 告警
adonword report                   # last scan result / 最近一次扫描结果
adonword serve --port 8754        # HTTP API (BIT Remote compatible) / HTTP API
```

Every subcommand accepts `--json`; piped stdin JSON merges over args/config (stdin wins — the BIT exec contract):

所有子命令支持 `--json`；管道 stdin 的 JSON 会合并覆盖参数与配置（stdin 优先，即 BIT exec 契约）：

```bash
echo '{"watch":{"paths":["/tmp/ws"]}}' | adonword scan --json
```

## BIT integration / BIT 集成

Three ways / 三种方式:

1. **CLI (exec runtime)** — BIT spawns `adonword scan --json`, sends `params` JSON via stdin, reads JSON from stdout.
2. **Remote tool** — run `adonword serve`, register URL `http://127.0.0.1:8754/invoke`; BIT POSTs `{"tool_id":"...","tool":"...","invoked_by":"...","params":{"action":"scan"}}`.
3. **Plain REST** — `GET /health`, `GET /report`, `POST /invoke` (see [Protocol](Protocol)).

Typical scenario / 典型场景: the BIT agent periodically calls `adonword scan` with `watch.paths` pointed at its own workspace, so any tampering, blacklisted process or unapproved listening port surfaces as a finding.

BIT 智能体定期调用 `adonword scan`（`watch.paths` 指向自己的工作区），任何篡改、黑名单进程或白名单外端口都会作为 finding 呈现。

## FAQ

**Q: Where is the baseline stored? / 基线存在哪里？**
`~/.adonword/baseline.json` (or `$ADONWORD_DATA_DIR/baseline.json`). Relative paths are the keys, `/`-separated; with multiple watch roots the normalized root path prefixes the key.

`~/.adonword/baseline.json`（或 `$ADONWORD_DATA_DIR/baseline.json`）。键为相对路径（统一 `/` 分隔符）；多根目录时用规范化的根路径作前缀。

**Q: Does ADONWORD kill processes or delete files? / 会杀进程或删文件吗？**
No. v0.1 is observation + alerting only.

不会。v0.1 只做观察 + 告警。

**Q: Are symlinks / unreadable paths fatal? / 符号链接或无权限路径会崩溃吗？**
No — they are skipped and recorded as `walk_warning` findings.

不会 —— 跳过并记为 `walk_warning` finding。

**Q: Why does `baseline check` exit 1? / 为什么 `baseline check` 退出码是 1？**
Exit 1 means "changes found" (CI-friendly). Exit 2 = baseline missing / config error.

退出码 1 表示"检测到变化"（便于 CI）。退出码 2 表示基线缺失 / 配置错误。

**Q: Webhook payload? / Webhook 载荷？**
`POST {"kind","severity","detail","triggered_at"}` with a 10 s timeout; the same finding repeats at most once per 5 minutes in `watch` mode.

`POST {"kind","severity","detail","triggered_at"}`，超时 10s；`watch` 模式下同一 finding 5 分钟内最多告警一次。

---

Part of the [BIT](https://github.com/yxpil/bit) ecosystem.
