# 活动告警访问卡

当用户要看“当前告警 / 活动告警 / 健康状态 / 还在不在报”时，读这个文件。

保持任务仓库为当前目录，并从 `$HOME/.agents/skills/openubmc-debug` 调用辅助脚本。

## 边界

- `GetAlarmList` 是当前活动告警面，优先用于判断现在还在报什么。
- `GetEventList` 是历史事件面，只能辅助看发生过什么；不要把历史 `Deasserted` 或 `Minor` 事件直接当当前根因。
- 如果用户说“现在 / 重新 / 再看一下 / 换了 / 重启了”，先重新取当前快照，再解释旧证据。

## 快速路径

```
python "$HOME/.agents/skills/openubmc-debug/scripts/preflight_remote.py" --ip <ip> --skip-telnet --json
python "$HOME/.agents/skills/openubmc-debug/scripts/active_alarms.py" --ip <ip> --json --compact-json
```

`active_alarms.py` 默认先对标准端点 `bmc.kepler.event` + `/bmc/kepler/Systems/1/Events`
执行一次 metadata-only XML introspect。该端点唯一暴露 `GetAlarmList` 时立即使用；否则才用
service-independent `busctl list` 有界枚举名称含 alarm/event/alert 的候选服务，再从每个候选
服务的对象树中有界枚举所有合法路径（包括根路径 `/`）并逐项 introspect。快速路径和回退
路径都只接受 XML 接口元数据，不读取属性当前值，也不会把普通表格 introspect 当作 live
fallback。只有唯一端点暴露 `GetAlarmList` 时才调用；候选过多、XML 无效、发现不完整或端点
歧义都会失败关闭并要求显式 `--service`/`--path`。随后它按现场签名使用远端
`busctl --json=short` 调用并输出 `result.records`。`result.search_terms` 提取稳定的
`EventName` 和 `EventCode`，用于回查源码；不要默认拿 `Event_<type>_<instance>` 这类运行时
实例名直接搜索。如果镜像暴露未知签名，它返回 `unsupported_alarm_signature`，不会猜参数。

同一 TargetRun 会缓存自动发现得到的 service/path/interface/signature 元数据，但每次仍重新
调用 `GetAlarmList` 读取当前告警，不缓存告警记录。若调用返回 unknown interface/method/object、
service unknown 或 name has no owner，reader 只清除该端点元数据，在同一全局 deadline 内自动
重发现并重试一次；SSH ControlMaster、D-Bus 环境和其他 capability 缓存继续复用。显式
`--service`/`--path` 不写入共享端点缓存，也不被自动改写。

默认 MCP 暂未开放 object/alarm selector；此类窄查询先使用本只读 CLI。需要验证变化边界、
形成跨证据根因或继续修复流程时使用 `execute`，不要新增顶层 Agent 工具。

只读信任谓词必须同时成立：候选 service 名称属于 alarm/event/alert 范围、XML introspection 在有界搜索内唯一暴露精确的 `GetAlarmList` 方法、方法签名属于允许集合，并且调用参数由专用 reader 的固定只读请求生成。方法名命中本身不构成授权，也不能把通用 `busctl_remote.py --action call` 当作替代入口。

每个 XML 元数据结果最多 1 MiB。introspection transport 只保留 `1 MiB + 1 byte` 的 stdout 探针，候选发现 stdout 最多 4 MiB，最终活动告警结果 stdout 最多 8 MiB，所有 SSH stderr 最多 64 KiB；任一流继续增长都会立即终止 SSH。公开 JSON 返回 `ssh_output_limit_exceeded`/`125`，不回显超限正文，只保留每流 byte counts 和 limit flags；debug dump 也只接收有界内容，XML parser 不会收到超过探针上限的输入。`--deadline` 约束环境探测、候选枚举、逐路径 introspection 和最终读取的总时长；`--timeout` 仍是单个 SSH 命令上限。任一边界耗尽都返回明确失败，不能把未检查的候选当作不存在。

源码关联不能停在事件定义。找到 `EventName` / `EventCode` 后，继续用 `collect_logs.py --since-boot --grep <运行时实例,EventName,EventCode>` 对齐 Assert/Deassert 时间，再把活动告警中的 `ComponentInstance`、`ComponentLocation`、`ComponentName` 与源码触发对象、属性和槽位映射交叉验证。源码根只从 Developer handoff、显式参数、`OPENUBMC_SOURCE_ROOT` 或能够通过 remote 识别为 openUBMC 的当前 Git 仓库发现；无法验证时把本地关联标记为未完成，不能搜索控制仓或 Skill 仓后形成源码阴性。

需要手工复现发现过程时再执行：

```
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> \
  --action introspect \
  --service <introspected-service> \
  --path <introspected-object-path>
```

先以 metadata-only XML introspect 返回的接口名和方法签名为准，不要假设所有镜像都使用相同版本，也不要退回会显示属性 `RESULT/VALUE` 的普通表格 introspect。

`busctl_remote.py` 的通用入口不执行任何 `call`，即使方法名是 `GetAlarmList` 或 `GetEventList` 也不会放行。完成手工 introspect 后，仍应回到 `active_alarms.py`；它把唯一的现场 service/path/interface、实际签名与受支持的固定参数绑定在同一次专用流程中。

内置的分页签名 `a{ss}qqa(ss)` 只有在 `active_alarms.py` 的现场 introspect 完全匹配时才会使用。参数含义是空 context、起始位置 `0`、最多 `100` 条、空过滤数组。`result.record_count` 是活动告警数量，`result.records` 是按告警分组后的属性对象；不要再让 Agent 手工拆解一整行 `qa(a(ss))` 文本。

不同镜像可能暴露不同接口或签名。只有 introspect 确认后才使用；不要从旧文档直接复制接口名。

如果 introspect 返回尚未内置的签名，在确认该版本的参数语义后，可显式提供覆盖；覆盖签名必须与现场 introspect 完全一致：

```bash
python "$HOME/.agents/skills/openubmc-debug/scripts/active_alarms.py" --ip <ip> \
  --call-signature '<introspected-signature>' \
  --call-arg '<arg-1>' \
  --call-arg '<arg-2>' \
  --json --compact-json
```

签名不一致时返回 `signature_override_mismatch`；未提供覆盖的未知签名返回 `unsupported_alarm_signature`。覆盖机制用于适配已确认的版本差异，不用于试错或猜参数。

需要看历史事件时再查 `GetEventList`，并在输出中标明它不是当前活动告警。当前 Skill 不通过通用 `busctl_remote.py` 暴露历史事件方法调用；优先使用已有日志证据或产品提供的只读历史接口。若需要新增自动化查询，应实现一个同样绑定现场 introspection、精确签名和固定参数的专用 helper，不能复用方法名 allowlist。

如果仍尝试 `mdbctl_remote.py`：
- stdout 出现 `Failed:`、`Object does not exist`、`Object not found`、无输出或服务未知，都属于失败
- 不能因为 SSH 返回码为 0 就判断调用成功
- 立即切到 `busctl_remote.py introspect`，不要把 mdbctl 失败解释成“当前没有告警”

## 输出要求

- 先列当前活动告警数量和关键告警码/对象。
- 区分“当前仍在 Asserted”与“历史已 Deasserted”。
- 多条 Major 告警不要机械并列；检查是否共享同一硬件链路、背板、线缆、卡槽或上游对象。
- 告警结论要绑定现场快照时间，避免把旧状态当当前状态。
- 输出命令中记录实际使用的 interface、signature、分页范围，便于跨版本复现。
