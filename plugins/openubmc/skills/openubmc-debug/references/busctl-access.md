# busctl 访问卡

当你已经确定要用 `busctl` 时，读这个文件。

保持任务仓库为当前目录，并从 `$HOME/.agents/skills/openubmc-debug` 调用辅助脚本。

## 什么时候优先用 busctl

- 已经知道 service、object path、interface
- 需要精确 `list`、`tree`、`introspect` 或 `get-property` 证据
- 需要 `monitor` 这类原始 D-Bus 视图
- 需要稳定脚本化、机器可读输出

## 原生命令

交互 SSH 会话里通常已经自动设置 DBUS/XDG 环境变量，因此可以直接 `busctl --user ...`。如果失败，请先读取当前会话的 DBUS/XDG，再导出后执行。

```
printenv | grep -E 'DBUS|XDG_RUNTIME_DIR'

XDG_RUNTIME_DIR=<detected-xdg-runtime-dir> \
DBUS_SESSION_BUS_ADDRESS=<detected-session-bus-address> \
busctl --user --no-pager list
```

常见用法：

```
busctl --user tree <service>
busctl --user --xml-interface introspect <service> <object-path>
busctl --user get-property <service> <path> <interface> <property>
busctl --user monitor <service>
```

`monitor` 仅用于明确的短时观察窗口，必须由外部 timeout 或采集时限约束；不要留下长期运行的监听进程。

说明：openUBMC 方法签名常以 `a{ss}` 开头（上下文参数）。

`openubmc-debug` 不把方法名当成只读授权：同名方法可以挂在完全不同且会修改状态的 service/path/interface 上。通用 `busctl_remote.py` 对所有 `call` 都在凭据解析和 SSH 之前失败关闭，并返回 `write_operation_blocked`。它的 `introspect` 固定使用 `--xml-interface`，只返回接口元数据；`get-property` 不按成员名称阻断，属性名和值都原样返回。当前活动告警只走 `active_alarms.py`，由它现场 introspect 唯一端点、校验签名并绑定固定参数。其他方法调用切到动作 owner Skill，并携带目标和回滚边界。

脚本化 `busctl_remote.py` 对 stdout 设 4 MiB、stderr 设 64 KiB 的 SSH transport 上限。超限立即终止进程并返回 `ssh_output_limit_exceeded`/`125`；JSON 不包含超限正文，只保留安全的 byte counts 和 per-stream flags。需要更小结果时继续使用 `--grep` 与 `--head`/`--tail`，但这些本地过滤不是放宽 transport 上限的理由。

如果 `busctl --user` 仍看不到服务：
- 先在同一交互会话里再次 `printenv`
- 再用 `python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --print-env` 检查脚本看到的 DBUS/XDG

## 脚本化 busctl（推荐）

```
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action list --head 20
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action tree --service <service> --head 20
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action introspect --service <service> --path <path>
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action get-property --service <service> --path <path> --interface <interface> --property <property>
python "$HOME/.agents/skills/openubmc-debug/scripts/active_alarms.py" --ip <ip> --json --compact-json
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --dbus '<detected-session-bus-address>' --xdg <detected-xdg-runtime-dir> --action list
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --action tree --service <service> --grep <literal> --head 20

export OPENUBMC_SSH_USER='<your-ssh-user>'
export OPENUBMC_SSH_PASSWORD='<your-ssh-password>'
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --ssh-port <ssh-port> --ssh-user-env OPENUBMC_SSH_USER --ssh-password-env OPENUBMC_SSH_PASSWORD --action tree --service <service>
python "$HOME/.agents/skills/openubmc-debug/scripts/busctl_remote.py" --ip <ip> --ssh-user-env OPENUBMC_SSH_USER --ssh-password-env OPENUBMC_SSH_PASSWORD --action tree --service <service> --grep <literal> --head 20 --json
```

在有远端登录 banner 的环境里，优先用 `busctl_remote.py`，不要先手工拼 `DBUS_SESSION_BUS_ADDRESS` 再跑 `busctl --user`。
