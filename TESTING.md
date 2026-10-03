# ADONWORD 测试说明

- 测试完成：是（2026-10-04）
- 测试日期：2026-10-04
- 测试内容：单元覆盖 config（TOML 解析/端口范围/stdin JSON 合并）、engine（glob/进程匹配/目录收集/扫描）、baseline/watch/mcp（工具注册表）；集成覆盖 CLI 与 MCP 全链路；注入测试覆盖白名单键过滤、相对键不 `../` 逃逸 root、恶意端口、畸形 HTTP/JSON-RPC/stdin 载荷；钩子测试覆盖 MCP 工具注册表的注册→触发→失败隔离。
- 运行命令：`cargo test`
- 测试框架：Rust #[cfg(test)]
- 模型：豆包（Doubao）生成

单 crate（`src/main.rs` 二进制 + 内嵌模块）。单元测试留在各 `src/*.rs` 的 `#[cfg(test)]`，
集成测试放仓库根 `tests/`（`cli.rs`、`mcp.rs` 既有；本次新增 `injection.rs`、`hooks.rs`）。

## 测试放在哪里

| 位置 | 类型 | 覆盖 |
|---|---|---|
| `src/config.rs` | 单元 | TOML 解析、端口范围展开、stdin JSON 合并 |
| `src/engine.rs` | 单元 | glob/进程匹配、目录收集、扫描结果 |
| `src/baseline.rs` / `src/watch.rs` / `src/mcp.rs` | 单元 | 基线往返、去重、工具注册表 |
| `tests/cli.rs` | 集成 | 基线增删改、CLI、serve/invoke/token 全链路 |
| `tests/mcp.rs` | 集成 | MCP 握手/tools 列表/协议错误/token |
| `tests/injection.rs` | **集成（注入）** | 畸形/恶意 HTTP·JSON-RPC·stdin 载荷 |
| `tests/hooks.rs` | **集成（钩子）** | MCP 工具注册表的注册/触发/拒绝/隔离 |

## 怎么运行

```powershell
# 全量（注意：在交互式终端里要给空 stdin，否则既有 serve harness 会阻塞读 stdin）
cargo test < NUL

# 仅单元测试
cargo test --bin adonword

# 仅新增的两类集成
cargo test --test injection    # 注入安全
cargo test --test hooks       # 钩子/工具注册表
```

> 说明：`main.rs` 在 stdin 非 TTY 时会先 `read_to_string` 等待 stdin EOF。
> 本次新增的 harness 已显式给被拉起的 serve 子进程 `.stdin(Stdio::null())`；
> 在真实 CI（非交互）里 stdin 本来就是关闭的，故 `cargo test` 直接可跑。
> 本机交互式 PowerShell 下用 `cargo test < NUL` 复现同样效果。

## 预期结果（本地基线）

`cargo test < NUL` 应全部通过、0 失败：

- 单元（`adonword-*`）：20 passed（Windows；含 `#[cfg(unix)]` 的一个用例在 win 下自动跳过）
- 集成：`cli` 8 + `mcp` 4 + `injection` 5 + `hooks` 4

### 本次补强新增（相对原有 28 个用例）

**单元 +5**（`src`）：
- `config::tests::unknown_stdin_sections_are_ignored_not_merged` — 白名单外/原型污染键被丢弃
- `config::tests::wrong_typed_stdin_paths_is_rejected_not_panicked` — paths 类型错误干净报错
- `config::tests::expand_ports_handles_garbage_and_overflow_ranges` — 越界/非法端口范围转 warning
- `engine::tests::relative_keys_never_contain_dotdot_or_escape_root` — 记录键不 `../` 逃逸 root
- `engine::tests::collect_files_tolerates_nonexistent_and_traversal_roots` — 不存在/穿越根只记 warning

**集成（注入）+5**（`tests/injection.rs`）：
`malformed_body_to_invoke_is_400_not_a_crash`、`malformed_body_to_mcp_is_parse_error_32700`、
`command_like_action_name_is_rejected_as_unknown_not_shelled`、
`xss_tool_name_is_safely_embedded_in_json_error`、
`garbage_and_typed_wrong_stdin_does_not_crash_cli`。
断言：畸形/命令注入/XSS 载荷被 400 / -32700 / -32602 拒绝，不打 shell、不写文件，错误始终是合法 JSON。

**集成（钩子）+4**（`tests/hooks.rs`，MCP 工具注册表即钩子机制）：
`registered_tools_listed_in_stable_order_and_each_routes`（注册→稳定顺序→按名触发）、
`unregistered_tool_call_is_rejected`（未注册工具 -32602 拒绝）、
`failed_tool_call_does_not_break_sibling_tools`（失败/未注册钩子不影响兄弟钩子）、
`forged_arguments_cannot_rebind_action_or_privilege`（伪造参数不能重绑动作/提权）。

## 测试风格约定

- 断言 HTTP 状态码区段与 JSON-RPC 错误码（400/-32601/-32602/-32700/401），不只是"返回错误"；
- 注入用例同时断言"无副作用"（不写文件、不打 shell、响应仍合法 JSON）；
- 每个集成测试用独立临时数据目录 + 随机端口，结束即 kill 子进程。
