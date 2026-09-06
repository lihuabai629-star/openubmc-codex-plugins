---
name: openubmc-qemu-testing
description: >-
  Launch, observe, stop, and smoke-test an openUBMC QEMU instance using the
  repository-selected launcher. Use for launcher discovery, PID/process identity,
  serial evidence, forwarded-port checks, image identity, guest readiness, and
  service smoke classification. Route platform-specific ARM/KVM setup, resource
  tree diagnosis, component fixes, and package delivery to their owners.
---

# OpenUBMC QEMU Testing

## Role

本 Skill 是通用 QEMU verification owner。它拥有 launcher discovery、PID identity、serial evidence、port mapping、image identity、guest readiness 和 smoke classification；不拥有平台环境搭建、镜像构建、资源树专项根因或组件代码修复。

## Accepted Input

Accept a direct request or concise handoff containing the QEMU intent, image or launcher hints,
requested smoke checks, and explicit process or network authorization. One authorization does not
imply another.

## Hard Gates

1. **launcher 来自事实**：只使用 handoff、用户或仓库脚本/配置明确的 launcher；从其 help/源码确认参数，不发明启动命令。
2. **authorization 必须可强制执行**：本 Skill 不提供通用 launcher adapter。`launch`、`stop`、非 loopback exposure 或 verification weakening 只有在所选 repository launcher 或 `reviewed wrapper` 提供 `enforceable authorization seam` 时可执行；否则保持 `read-only/blocked`，不得把 payload 中的 authorization boolean 当作执行门禁。
3. **先 image identity，后 launch**：解析 kernel/rootfs/dtb/flash 等实际输入，记录路径、size/mtime、checksum 或 manifest build identity。
4. **进程按身份拥有**：launch/stop 使用 task-scoped runtime directory；记录 PID、process start time、executable/argv 和 image identity。停止前全部复核，不按进程名批量终止。
5. **证据分层**：launcher exit、PID、serial、ports、guest readiness 和 service smoke 分别判断；某层失败不自动改写成组件失败。
6. **验证默认保持强度**：优先 CA bundle、exact certificate fingerprint 或协议原生验证。只有 `qemu_testing_intent.weaken_verification=true` 与 `qemu_authorization.weaken_verification=true` 同时成立，且范围为隔离测试、有限时长、有恢复步骤时才允许降低验证。
7. **端口暴露独立双门禁**：非 loopback bind 或新增 host exposure 同时需要 `qemu_testing_intent.expose_non_loopback_ports=true`、`qemu_authorization.expose_non_loopback_ports=true` 和冲突/回滚证据。

## Workflow

### 0. Classify the Request

读取 repositories、toolchain、artifact、requested verification、authorization、`qemu_testing_intent` 和用户改动。把请求分类为 discover、launch、observe、smoke、stop 或 diagnose-existing-instance。

完成条件：每个请求动作、QEMU root、runtime root 和不能触碰的外部状态均明确。

### 1. Discover Launcher and Inputs

- 从 handoff/user/repository 查找实际 launcher、config、machine/accelerator 选择和 image references。
- 读取 launcher help/源码，列出 inputs、PID/log handling、serial sink、network/port mapping 和 monitor/control channel。
- 检查 launcher 或 wrapper 是否在 mutation 发生前校验 normalized intent、同名 authorization 与目标范围；记录 seam、拒绝路径和测试证据。
- 解析 symlink/relative path，生成 image identity；输入不存在、身份冲突或来源不明时停止。
- 检查 task-scoped runtime directory、拟用 host ports 和现有 PID ownership。

完成条件：final argv 的每个值有来源，image identity 和 port plan 可复核；`qemu_testing_result.launcher.authorization_enforcement` 已能证明 mutation 可门禁，或明确为 `read_only_blocked`。

### 2. Launch or Attach

- `launch=true` 还要求 `qemu_authorization.local_process_control=true`；非 loopback 方案另需 exposure intent 与 authorization。
- 启动前写 task-owned run manifest；启动后记录 PID/start time/executable/argv，而不是只相信旧 PID 文件。
- attach 到现有实例时只读收集身份；没有 ownership 时不得 stop/restart。
- 串口日志写入本次 run path，并保存 start offset，避免把旧 boot 日志当作新证据。

完成条件：实例身份与本次 image/launcher 匹配，或结果明确为 blocked/attached-read-only。

### 3. Inspect and Smoke

按 `references/qemu-verification.md` 依次检查：

1. launcher/process identity；
2. serial boot progression 与 fatal signature；
3. host bind/forwarded port identity 和冲突；
4. guest readiness；
5. 用户要求的 SSH/Web/IPMI/MDB/service smoke；
6. 连续重启、coredump 或资源压力迹象。

证书或协议验证失败时保留 failure；先配置可信 CA 或精确 fingerprint。弱验证必须同时有 weaken intent 与 authorization，不能仅凭执行方式或授权字段推断 intent。

完成条件：每个 smoke 项有时间、endpoint、verification mode 和结果；失败已落入一个 classification。

### 4. Stop and Clean Up

- `stop=true` 还要求 local process control authorization。
- 对比 PID、start time、executable/argv 和 run manifest 后，只停止当前 run 拥有的实例。
- 等待退出并验证端口释放；保留请求的 serial/run manifest，清理其余 task-owned runtime 文件。
- 身份不匹配时拒绝停止并报告 stale PID/ownership conflict。

完成条件：实例/端口/运行目录状态可证明，且没有影响其他 QEMU 进程。

### 5. Return Result

Return launcher, process identity, serial, port, image, readiness, smoke, and cleanup results.
`completed` requires fresh evidence for every requested intent and smoke item.

## Smoke Classification and Routing

| Classification | Evidence boundary | 下一 owner |
| --- | --- | --- |
| launcher/config/image mismatch | QEMU 未形成匹配进程 | 当前 Skill；ARM/KVM 平台缺口转 `openubmc-qemu-arm-kvm` |
| PID/serial/port ownership | host orchestration 失败 | 当前 Skill |
| resource-tree/MDB scanner/chip/sensor | guest 已启动但资源树异常 | `openubmc-qemu-resource-tree-debug` |
| component coredump/service behavior | instance identity 正确且 guest evidence 指向组件 | `openubmc-debug` / 实现 owner |
| artifact missing/stale | image 与本次代码/包不匹配 | `openubmc-build` |
| complex test scenario | launcher 已稳定，需要用例/fixture owner | `openubmc-dt-testing` |

## Resources

- `references/qemu-verification.md`：launcher/PID/serial/ports/image/smoke evidence checklist。
