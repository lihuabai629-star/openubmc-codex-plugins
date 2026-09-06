---
name: openubmc-log-analyzer
description: Diagnose openUBMC/BMC issues from a one-click log bundle (.tar/.tar.gz), an extracted log directory, or a BMC/server entry point where the bundle should be collected first and analyzed locally. Use when the requested evidence source is a diagnostic bundle or offline logs. Do not use for direct live MDB/D-Bus/alarm comparison or multi-surface runtime diagnosis without a bundle workflow; route those tasks to openubmc-debug.
---

# OpenUBMC 日志分析

## 概述
这个 skill 采用“先拉包、后分析”的方式。如果用户给的是 BMC/服务器入口，而不是本地日志包，先用 `scripts/pull_bundle.py` 拉取一键日志包，再在本地对解压后的内容做分析。

优先使用 Redfish 的一键采集能力。SSH 在这个 skill 里只是兜底手段，仅用于“远端已有 tar 包”或“平台只能通过命令生成日志包”的场景。不要把“拉一键日志并分析”变成手工 SSH/Telnet 上环境排查。如果日志包拉取失败，或者本地分析后仍然缺少实时证据，再切到 `openubmc-debug`。

## 工作流（先日志包、后分析）

1. 收集输入。必须有问题描述，并且至少满足以下一种输入：
   - 本地日志包路径
   - 已解压日志目录
   - BMC/服务器 IP 或主机名
2. 如果只有远端主机入口，先调用 `scripts/pull_bundle.py` 做远端采集。
   - 通过统一 MCP 工作流调用时，断开后沿用同一任务 ID 即可继承目标和问题意图；
     Redfish/SSH 会话不会恢复，重连后会新建会话并重新采集，不复用旧日志包结果。
     当前任务和 Case 工作流可继续使用已提供的直接 SSH/Redfish 凭据。
     通过托管 Target Runtime 调用时，它会自动读取
     `OPENUBMC_CREDENTIALS_FILE` 并把所需 SSH/Redfish 值传入本域，无需手动
     导出用户名或密码环境变量。
   - 终端人工使用时，`--ip` 可以不传，脚本会交互提示输入。
   - SSH/Redfish 密码默认不再内置。内部研发可直接传入密码，也可使用 `--ssh-password-env` / `--redfish-password-env`；非 JSON 模式缺失时会交互提示输入。
   - 默认模式是 `--transport auto`：优先走 Redfish 一键采集，失败时再回退到 SSH 发现/下载。
   - 用 `--transport redfish` 强制走 Redfish 一键采集。默认触发 `Manager.Dump`；如果显式指定 `--redfish-action quickdump` 但平台返回 `FeatureDisabledAndNotSupportOperation`，脚本会自动回退到 `Manager.Dump`，然后继续轮询任务并调用 `Manager.GeneralDownload`。
   - Redfish 代理策略默认是 `--redfish-proxy auto`：私网管理地址自动绕过代理；如有特殊网络环境，可切 `inherit` 或 `disable`。
   - 用 `--transport ssh` 处理“平台只给远端 tar 路径”或“只能靠 shell 命令生成一键日志”的场景。
   - 如果已知远端压缩包路径，优先传 `--remote-path`。
   - 如果平台必须靠 shell 命令生成日志包，传 `--remote-command`。这个参数只支持 SSH。
   - 如果没有传 `--remote-path` 和 `--remote-command`，脚本会在默认目录下发现最新候选日志包。
   - 如果结果要给其他脚本/agent 消费，使用 `--json`；此时必须显式传 `--ip`，不能走交互输入。
   - 传 `--problem '<现象>'` 可以在解压后立即执行问题驱动的日志分析；如果用户给了故障时间，继续传 `--analysis-since` / `--analysis-until` 收敛证据窗口。
3. 解包并做目录确认。如果输入是 `.tar` 或 `.tar.gz`，先解压到临时目录；如果 `pull_bundle.py` 已经解压，直接从返回的 `BUNDLE_ROOT` 开始。重点关注 `dump_info/LogDump`、`dump_info/AppDump`、`dump_info/RTOSDump`。
4. 根据问题挑日志。先读取 `references/logs.json`，按关键词规则选日志；“运行状态、近期错误、异常检查、健康检查”等泛化检查只兜底到 `app.log`、`framework.log` 和 `journalctl.log`。不要默认去扫无关的“优先日志”或整个日志包。
5. 分析选中的日志。抽取错误、告警和时间点。只有当问题明显指向组件/服务异常时，才额外关联 `app.log` 和 `framework.log`。如果是“数据不更新”“对象缺失”这类问题，优先看 AppDump 里的 `mdb_info.log`、`sync_property_trace.log`、`rpc_records.log`。解析输出字段和排序逻辑见 `references/analysis.md`。
6. 输出结论。至少包括：问题摘要、证据片段（命令或日志行）、可能原因、下一步验证建议。
7. 只有在遇到未知日志类型时，才去查 NotebookLM。若查询后确认了新日志含义，要把结果补到 `references/logs.md` 和 `references/logs.json`，避免下次重复查询。

MCP 任务默认最多保留 32 个目标连接租约。它不限制 Case 中的环境数量；旧租约被 LRU
淘汰后，再次选择该环境会重新连接并重新采集日志包。

## 快速参考

| 任务 | 文件 / 命令 |
| --- | --- |
| 远端一键拉包 | `python scripts/pull_bundle.py [--ip <ip>] [--transport auto|redfish|ssh] ...` |
| 一条命令拉包并分析 | `python scripts/pull_bundle.py --ip <ip> --problem '<现象>' --json` |
| 远端采集示例 | `references/remote-collection.md` |
| 日志含义说明 | `references/logs.md` |
| 解析行为说明 | `references/analysis.md` |
| 问题到日志的映射规则 | `references/logs.json` |
| 核心目录 | `dump_info/LogDump`, `dump_info/AppDump`, `dump_info/RTOSDump` |

## 示例（只有远端入口）

用户：“BMC 登录失败，服务器是 `192.0.2.10`，直接拉一键日志分析。”

处理方式：
- 先拉一键日志包。
- 一条命令完成拉包和分析：
  - `python scripts/pull_bundle.py --ip 192.0.2.10 --transport redfish --problem 'BMC 登录失败' --json`
- 读取 `result.bundle_root` 和 `result.analysis`。
- 根据 `logs.json`，脚本会把 login/auth 相关问题优先映射到 `security.log`、`operation.log`。
- 先看返回的证据行，只有在还需要更深关联时再继续人工分析。
- 如果怀疑还有系统级异常，再补看 `framework.log` 和 `journalctl.log`。

## 示例（已知远端日志包路径）

用户：“日志包已经在机器上，路径是 `/data/openUBMC_20260402-1015.tar.gz`，帮我拉下来分析。”

处理方式：
- `python scripts/pull_bundle.py --ip <ip> --transport redfish --remote-path /data/openUBMC_20260402-1015.tar.gz --json`
- 读取 `BUNDLE_ROOT`。
- 再按问题驱动方式选日志并分析。

## 常见自我说服

| 借口 | 事实 |
| --- | --- |
| “已经有 BMC IP 了，直接切 `openubmc-debug` 上环境看就行。” | 如果用户要的是一键日志，就先拉日志包并在本地分析。实时调试只能作为失败兜底或补充证据。 |
| “SSH 都能进了，顺手看下 `/var/log` 就完了。” | 在这个 skill 里，Redfish/SSH 只是为了把日志包拉下来，不是让你手工浏览远端日志。 |
| “先把整个包全扫一遍再说。” | 先根据问题和 `logs.json` 选日志；无关日志会浪费时间。 |
| “NotebookLM 反正能查，所有文件都查一遍。” | 只在未知日志上查一次，并把结果缓存到本地参考文件。 |

## 红线

- 把远端日志采集变成手工 SSH/Telnet 排查。
- 拉下一个任意 tar 包，却不检查里面是否有 `dump_info/`。
- 默认去看和问题无关的“重点日志”。
- 对已经知道含义的日志反复查询 NotebookLM。
- 跳过 `logs.json` 的映射规则。

## 常见错误

- 用户只给了主机入口，但流程没有尝试远端一键采集。
- 自定义远端命令生成了日志包，却没有输出 `BUNDLE_PATH=/path/to/archive.tar.gz`。
- 发现了一个 tar 包，但它并不是 openUBMC 一键日志，且没有验证 `dump_info/`。
- 忽略问题描述，直接扫描整个日志包。
- 发现了新日志类型，却没有回写 `logs.md` / `logs.json`。
- 混用了不同时段的日志，却没有说明时间范围假设。

## 资源

### scripts/
- `scripts/pull_bundle.py`：面向远端主机的 Redfish 优先拉包脚本，SSH 为兜底。支持 session 建立阶段的瞬时 `HTTP 502/503/504` 自动重试、`Manager.Dump`、`Manager.QuickDump` 禁用时自动回退、任务轮询期间的瞬时 TLS/连接错误重试、`Manager.GeneralDownload`、已知远端路径、SSH 自定义生成命令、本地解压，以及 JSON 结构化输出。

### references/
- `references/remote-collection.md`：远端采集命令写法、默认行为、输出字段说明。
- `references/logs.md`：日志文件的中文含义、常见问题到日志、直接证据和辅助证据边界。
- `references/analysis.md`：问题驱动选日志、路径展开、证据排序、时间窗和输出字段说明。
- `references/logs.json`：问题关键词到日志文件的映射规则。
