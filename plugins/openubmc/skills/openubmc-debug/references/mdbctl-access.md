# mdbctl 访问卡

当你已经确定要先用 `mdbctl` 时，读这个文件。

保持任务仓库为当前目录，并从 `$HOME/.agents/skills/openubmc-debug` 调用辅助脚本。

## 什么时候优先用 mdbctl

- 还在 openUBMC 微组件对象模型里做快速探索
- 先想看 class / object / property / method 全貌
- 想用 `getprop` / `lsprop` / `lsobj` 这类更贴近对象模型的命令
- 需要查看模块列表、只读属性或方法定义

## 原生命令

优先使用单条命令模式，每条命令前都带 `mdbctl`，避免交互卡住：

```
mdbctl lsclass
mdbctl lsobj <class>
mdbctl lsprop <object> [interface]
mdbctl getprop <object> <interface> <property>
mdbctl lsmethod <object> [interface]
mdbctl lsmc
```

`call`、`attach`、`setprop`、`traceprop` 及其他未列入只读集合的命令不属于本 Skill。`mdbctl_remote.py` 对它们固定返回 `write-operation-blocked`，没有 `--allow-write` 旁路。需要改变远端状态时切到动作 owner Skill，并携带明确授权、目标和回滚边界。

`getprop` 不按成员名称阻断；只要命令符合只读语法，属性名和值都会原样返回。`lsprop`、`lsobj` 等宽查询仍应受对象范围、输出上限和任务相关性约束。

脚本严格按上面的参数个数校验命令，并只接受以 ASCII 字母、数字、`_` 或 `/` 开头，后续由这些字符及 `.`、`:`、`@`、`+`、`-` 组成的对象标识 token。换行、分号、空白、shell 元字符、控制字符、命令行选项和未文档化命令全部在凭据解析及 SSH 之前拒绝；direct-skynet 不能用来绕过此门禁。

如果非交互 SSH 找不到 `mdbctl`，优先用 POSIX 登录 shell：

```
sh -lc '. /etc/profile >/dev/null 2>&1; mdbctl lsclass'
```

如果仍失败，再切脚本化方式：

```
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> lsclass
```

只有确实需要 mdbctl 语义、且其他方式都不稳定时，再尝试 direct skynet：

```
printf 'lsclass\n' | /opt/bmc/skynet/lua /opt/bmc/apps/mdbctl/service/mdbctl.lua
```

## 常见失败与切换动作

| 现象 | 常见原因 | 立即动作 |
|------|----------|----------|
| `mdbctl: command not found` | 非交互 SSH 未加载 alias 或 profile | 改用 `sh -lc '. /etc/profile >/dev/null 2>&1; mdbctl ...'` |
| 命令无输出或一直卡住 | 进入了交互模式、stdout 未返回、服务未就绪 | 只用单条命令模式；避免交互会话；必要时切 direct skynet |
| `ServiceUnknown` | mdb 服务未注册、DBUS 环境异常、服务仍在启动 | 不要盲重试 raw skynet；优先切 `python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" ...` 验证服务和对象树 |
| `Failed: Object does not exist.` / `Object not found.` | 当前查询对象不存在 | 对已审查的 `lsprop` / `getprop` / `lsmethod`，仅在 SSH 成功、stdout 明确且完整、无 stderr 错误时返回 `observed_absent` 事实；不重复 fallback。`lsclass` / `lsobj` 或 transport、权限、ServiceUnknown 错误仍为失败 |
| 同一命令在交互 SSH 成功、非交互失败 | shell 环境差异 | 统一改成 `sh -lc '. /etc/profile >/dev/null 2>&1; mdbctl ...'` 或 direct skynet |
| 对象或属性查不到，但服务存在 | 路径、class、interface 不确定 | 先 `mdbctl lsclass`、`lsobj` 缩小范围；再切 `busctl introspect` / `get-property` 做交叉验证 |

`observed_absent` 的 `result.fact` 绑定原查询和对象身份。Runtime 将它作为可评估的 AVAILABLE 结果，事实值仍是“对象不存在”；它不等于未采集、transport 不可用或属性值为空。

推荐排障顺序：

```
# 1) 先试最轻量的单条命令
mdbctl lsclass

# 2) 非交互失败时，切 POSIX 登录 shell
sh -lc '. /etc/profile >/dev/null 2>&1; mdbctl lsclass'

# 3) 仍失败时，优先切 busctl script
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action list
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action tree --service <service>

# 4) 只有确实需要 mdbctl 语义时，再显式试 direct skynet
printf 'lsclass\n' | /opt/bmc/skynet/lua /opt/bmc/apps/mdbctl/service/mdbctl.lua
```

## 脚本化 mdbctl（推荐）

```
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> lsclass
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> lsobj DiscreteSensor
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> --mode login-shell lsclass
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> --mode direct-skynet lsclass
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> --print-classification lsclass

export OPENUBMC_SSH_USER='<your-ssh-user>'
export OPENUBMC_SSH_PASSWORD='<your-ssh-password>'
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> --ssh-port <ssh-port> --ssh-user-env OPENUBMC_SSH_USER --ssh-password-env OPENUBMC_SSH_PASSWORD lsclass
python "$HOME/.agents/skills/openubmc-debug/scripts/mdbctl_remote.py" --ip <ip> --ssh-user-env OPENUBMC_SSH_USER --ssh-password-env OPENUBMC_SSH_PASSWORD --json lsclass
```

同一个诊断任务需要多条查询时，不要逐条启动上述 CLI。改用组合 workflow：

```
python "$HOME/.agents/skills/openubmc-debug/scripts/workflow_remote.py" --ip <ip> \
  --mdb-only \
  --mdb-query 'lsobj BusinessConnector' \
  --mdb-query 'lsobj PcieAddrInfo' \
  --mdb-expand-class PCIeDevice \
  --mdb-concurrency auto \
  --json --compact-json
```

每条查询仍经过本页定义的只读语法和敏感属性门禁，但共享一次凭据解析和 SSH 主连接。
`--mdb-expand-class` 会在同一次 workflow 中先发现当前对象名，再读取每个对象属性，避免
`lsobj` 后重新开一次 workflow。`auto` 只限制同一时刻的并发查询，不限制查询或对象总数。

如果 auto 模式仍失败，下一步应切 `busctl_remote.py`，不要继续手工试多种 raw skynet 变体。

注意：远端 `mdbctl` 可能在业务失败时仍返回 shell exit code 0。脚本必须同时检查 stdout/stderr 中的 `Failed:`、`Object does not exist`、`Object not found` 等失败文本，不能只看 return code。

`mdbctl_remote.py` 对 stdout 设 8 MiB、stderr 设 64 KiB 的 SSH transport 上限。超限返回稳定的 `ssh_output_limit_exceeded`/`125`，不会把已截断前缀误当成完整对象证据，也不会在公开 JSON 中回显该前缀；只保留 byte counts、limits 和 per-stream flags。遇到此结果应缩小 class/object/property 查询，而不是提高核心 Skill 的硬上限。
