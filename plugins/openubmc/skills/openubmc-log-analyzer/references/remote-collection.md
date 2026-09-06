# 远端日志包采集

## 目标

用一条命令从远端主机拉取 openUBMC 一键日志包，然后基于返回的 `BUNDLE_ROOT` 在本地继续分析。这里的远端访问只用于“采集日志包”，不是让你去 SSH/Telnet 上环境手工排查。

## 传输方式选择

推荐顺序：

1. `--transport auto`
2. `--transport redfish`
3. `--transport ssh`

`auto` 会优先尝试 Redfish 一键采集，只有在 Redfish 不可用或平台不支持时才回退到 SSH。只有当平台只提供 shell 侧采集命令，或者只能通过远端 tar 包路径下载时，才建议直接用 `ssh`。

## 推荐输入形态

优先使用以下三类输入之一：

1. 只给主机/IP，让 Redfish 直接触发一键采集
2. 已知远端日志包路径
3. 需要通过 SSH 执行远端命令生成日志包

内部研发模式可以直接传账号密码；需要重复使用时也可以选择环境变量。

人工终端使用时，`--ip` 可以不传；脚本会提示：

```text
目标 BMC IP 或主机名:
```

如果使用机器可读模式（`--json`），必须显式传 `--ip`，避免脚本阻塞在交互输入上。

SSH/Redfish 密码不再内置默认值。可以直接传入，也可以使用 `--ssh-password-env` /
`--redfish-password-env`；非 JSON 模式缺失时脚本会交互提示输入，JSON 模式缺失时会直接返回 `missing_secret`。

Redfish 登录阶段如果遇到瞬时 `HTTP 502/503/504`，脚本会自动重试；这种网关错误先按临时管理面抖动处理，不需要立刻切换到 SSH。

对于私网、loopback 或解析到私网地址的 BMC 主机名，Redfish 路径默认会自动绕过 `HTTP(S)_PROXY` / `ALL_PROXY`，避免本地管理流量误走工作站代理。特殊网络环境可通过 `--redfish-proxy inherit|disable|auto` 控制：

- `auto`：默认值，私网管理地址自动绕过代理。
- `inherit`：完全继承系统代理环境。
- `disable`：强制 Redfish 请求不走代理。

## 命令示例

### 1) Redfish 一键采集

```bash
export RF_USER=Administrator
export RF_PASS='<Redfish 密码>'
python scripts/pull_bundle.py \
  --transport redfish \
  --ip <ip> \
  --redfish-proxy auto \
  --redfish-user-env RF_USER \
  --redfish-password-env RF_PASS \
  --json
```

默认行为：

- Action：`dump`
- Manager id：`1`
- Redfish proxy：`auto`
- 远端生成路径：`/tmp/codex_dump_<timestamp>.tar.gz`

如果平台更适合轻量采集，可以用 `--redfish-action quickdump`。部分平台虽然暴露了 `#Manager.QuickDump`，但实际会返回 `FeatureDisabledAndNotSupportOperation`；脚本遇到这种响应时会自动回退到 `dump`，不需要手工重跑。

任务轮询期间如果出现瞬时 TLS/连接错误，例如 `SSL_ERROR_SYSCALL`、`EOF occurred in violation of protocol`、`Connection reset by peer`，脚本会在 `--redfish-task-timeout` 窗口内继续重试，不会把一次抖动直接判成采集失败。

如果希望拉包后立即按问题做本地分析，再加上 `--problem '<现象>'`：

```bash
python scripts/pull_bundle.py \
  --transport redfish \
  --ip <ip> \
  --redfish-user-env RF_USER \
  --redfish-password-env RF_PASS \
  --problem 'BMC 登录失败' \
  --json
```

如果用户给了明确故障时间，可以加时间窗，只返回该范围内带时间戳的证据：

```bash
python scripts/pull_bundle.py \
  --transport redfish \
  --ip <ip> \
  --redfish-user-env RF_USER \
  --redfish-password-env RF_PASS \
  --problem 'BMC 登录失败' \
  --analysis-since '2026-03-31T00:00:00' \
  --analysis-until '2026-03-31T23:59:59' \
  --json
```

### 2) 已知远端日志包路径

如果日志包已经存在于 BMC 文件系统，可以直接让 Redfish 下载：

```bash
export RF_USER=Administrator
export RF_PASS='<Redfish 密码>'
python scripts/pull_bundle.py \
  --transport redfish \
  --ip <ip> \
  --redfish-user-env RF_USER \
  --redfish-password-env RF_PASS \
  --remote-path /tmp/openUBMC_20260402-1015.tar.gz \
  --json
```

如果 Redfish 不可用，但 SSH/SCP 可以拿到同一路径，就强制走 SSH：

```bash
export BMC_USER=Administrator
export BMC_PASS='<SSH 密码>'
python scripts/pull_bundle.py \
  --transport ssh \
  --ip <ip> \
  --ssh-user-env BMC_USER \
  --ssh-password-env BMC_PASS \
  --remote-path /tmp/openUBMC_20260402-1015.tar.gz \
  --json
```

### 3) 通过 SSH 执行远端生成命令

最佳实践是：远端命令执行完成后打印 `BUNDLE_PATH=/path/to/archive.tar.gz`。

```bash
export BMC_USER=Administrator
export BMC_PASS='<SSH 密码>'
python scripts/pull_bundle.py \
  --transport ssh \
  --ip <ip> \
  --ssh-user-env BMC_USER \
  --ssh-password-env BMC_PASS \
  --remote-command 'bundle=/tmp/openUBMC_$(date +%Y%m%d-%H%M).tar.gz; /path/to/collect_oneclick.sh "$bundle"; echo BUNDLE_PATH=$bundle' \
  --json
```

如果远端命令没有输出 `BUNDLE_PATH=...`，脚本会在命令结束后自动回退到 SSH 侧日志包发现逻辑。

### 4) Auto 模式

```bash
export RF_USER=Administrator
export RF_PASS='<Redfish 密码>'
python scripts/pull_bundle.py \
  --transport auto \
  --ip <ip> \
  --redfish-user-env RF_USER \
  --redfish-password-env RF_PASS \
  --json
```

如果不加 `--json`，也可以不传 `--ip`，等脚本交互提示时再输入。

### 5) SSH 自动发现最新日志包

```bash
export BMC_USER=Administrator
export BMC_PASS='<SSH 密码>'
python scripts/pull_bundle.py \
  --transport ssh \
  --ip <ip> \
  --ssh-user-env BMC_USER \
  --ssh-password-env BMC_PASS \
  --json
```

默认 SSH 搜索目录：

- `/tmp`
- `/var/tmp`
- `/data`
- `/home`
- `/opt`

默认 SSH 文件名匹配模式：

- `*openUBMC*.tar.gz`
- `*openUBMC*.tar`
- `*oneclick*.tar.gz`
- `*dump*.tar.gz`
- `*log*.tar.gz`

如果平台的输出目录或命名方式不同，可以覆盖这些参数：

```bash
python scripts/pull_bundle.py \
  --transport ssh \
  --ip <ip> \
  --ssh-user-env BMC_USER \
  --ssh-password-env BMC_PASS \
  --search-root /custom/path \
  --name-glob 'bundle-*.tar.gz' \
  --json
```

## 输出字段

人类可读模式会输出：

- `REMOTE_BUNDLE_PATH=...`
- `LOCAL_BUNDLE_PATH=...`
- `EXTRACT_DIR=...`
- `BUNDLE_ROOT=...`
- `NEXT_STEP=...`

JSON 模式会返回：

- `schema_version`
- `tool`
- `ok`
- `code`
- `error`
- `request`
- `result.remote_bundle_path`
- `result.local_bundle_path`
- `result.extract_dir`
- `result.bundle_root`
- `result.transport`
- `result.analysis.summary`
- `result.analysis.selected_logs`
- `result.analysis.time_window`
- `result.analysis.selected_logs[].existing_path_count`
- `result.analysis.selected_logs[].existing_paths_truncated`
- `result.analysis.selected_logs[].evidence_lines[].timestamp`

后续分析应以 `result.bundle_root` 作为输入。

如果要解释这些字段的含义和排序原因，直接看 `references/analysis.md`。尤其是下面几项：

- `result.analysis.time_window`
  - 说明本次证据是按哪个时间范围裁剪出来的。
- `result.analysis.selected_logs[].existing_path_count`
  - 表示这类日志实际展开命中了多少个文件，常见于 `AppDump/*/...` 这类通配路径。
- `result.analysis.selected_logs[].existing_paths_truncated`
  - 为 `true` 说明输出里只展示了部分路径，避免结果过长。
- `result.analysis.selected_logs[].evidence_lines[].timestamp`
  - 只有该行能解析出时间戳时才会返回，时间窗分析也只会保留这类可定时的证据。

## Redfish 细节

默认 Redfish 路径：

- 登录：`POST /redfish/v1/SessionService/Sessions`
- Manager：`GET /redfish/v1/Managers/1`
- 全量采集：`POST /redfish/v1/Managers/1/Actions/Oem/openUBMC/Manager.Dump`
- 快速采集：`POST /redfish/v1/Managers/1/Actions/Oem/openUBMC/Manager.QuickDump`
- 任务轮询：`GET /redfish/v1/TaskService/Tasks/<id>`
- 下载：`POST /redfish/v1/Managers/1/Actions/Oem/openUBMC/Manager.GeneralDownload`

采集请求体：

```json
{
  "Type": "URI",
  "Content": "/tmp/codex_dump_<timestamp>.tar.gz"
}
```

下载请求体：

```json
{
  "TransferProtocol": "HTTPS",
  "Path": "/tmp/codex_dump_<timestamp>.tar.gz"
}
```

## 失败处理

- `remote_bundle_not_found`
  - 没找到日志包。请显式传 `--remote-path`，或者增加 `--remote-command`，或者扩大 `--search-root` / `--name-glob`。
- `redfish_auth_failed`
  - Redfish 登录失败，或者没有拿到 session token。脚本已经自动吸收了 session 建立阶段的瞬时 `HTTP 502/503/504` 与常见 TLS/连接抖动。
- `redfish_action_missing`
  - 目标平台没有暴露预期的 OEM dump/download action。
- `redfish_task_failed`
  - dump 任务进入 `Exception`、`Killed` 或 `Cancelled`。
- `redfish_task_timeout`
  - Redfish 任务在 `--redfish-task-timeout` 时间内没有完成；脚本已经自动吸收了轮询阶段的瞬时 TLS/连接抖动。
- `redfish_download_failed`
  - `Manager.GeneralDownload` 失败。
- `auto_transport_failed`
  - Redfish 和 SSH 都失败了；要同时看错误信息里的两段失败原因。
- `remote_collect_failed`
  - 远端生成日志包命令执行失败。先修命令，再考虑是否切到实时调试。
- `bundle_download_failed`
  - SSH/SCP 下载路径或认证失败。
- `bundle_layout_invalid`
  - 下载下来的压缩包不是 openUBMC 一键日志，因为里面找不到 `dump_info/`。
- `extract_failed`
  - 日志包无法安全解压。

## 何时回退到 `openubmc-debug`

- 平台没有可靠的一键采集命令，也没有现成日志包可下载。
- 日志包采集多次失败，而用户更希望直接拿实时证据。
- 日志包分析已经完成，但仍然需要做实时 DBus / object state 校验。
