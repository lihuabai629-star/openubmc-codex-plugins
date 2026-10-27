---
name: openubmc-qemu-testing
description: >-
  Launch, observe, stop, and smoke-test an openUBMC QEMU instance using the
  repository-selected launcher. Use for launcher discovery, PID/process identity,
  serial evidence, forwarded-port checks, image identity, guest readiness, x86
  development acceptance, and service smoke classification. Route platform-specific
  ARM/KVM setup, resource tree diagnosis, component fixes, and package delivery to
  their owners.
---

# OpenUBMC QEMU Testing

When the task enters another workflow stage, read [the phase handoff](<../openubmc-debug/references/skill-routing.md>)
and load its owner before acting; carry the existing Run and authorization.

## Role

本 Skill 是通用 QEMU verification owner。它拥有 launcher discovery、PID identity、serial evidence、port mapping、image identity、guest readiness、x86 development acceptance 和 smoke classification；不拥有平台环境搭建、镜像构建、资源树专项根因或组件代码修复。

## Accepted Input

Accept a direct request or concise handoff containing the QEMU intent, image or launcher hints,
requested scenario, smoke checks, and explicit process or network authorization. One authorization
does not imply another. For an x86 build-to-QEMU loop, also accept the Build result, repository launch
index, image identities, source revision, product version, and known package-binding gaps.

Derive routine local launch/control permission and the matching intent/authorization
fields from the user's QEMU request. Fill those internal fields yourself. Reuse
established network and transport decisions; ask only for an actual scope expansion.
Default to `verification.profile=targeted` for the requested checks. Select
`full-x86` only for a requested full acceptance; it is not a prerequisite for launch
or a focused debugging loop.

## Execution checks

1. **launcher 来自事实**：只使用 handoff、用户或仓库脚本/配置明确的 launcher；从其 help/源码确认参数，不发明启动命令。
2. **复用已授权的命令**：检查仓库 launcher 的参数和影响范围。常规任务可使用 `task_command`，由 Agent 在执行边界核对授权、argv、runtime 和进程身份，记录源码检查证据；不强制另造 wrapper 或为 launcher 缺少授权 API 停工。已有 repository launcher / reviewed wrapper 的执行边界仍可复用。
3. **先 image identity，后 launch**：解析 kernel/rootfs/dtb/flash 等实际输入，记录路径、size/mtime、checksum 或 manifest build identity。
4. **进程按身份拥有**：launch/stop 使用 task-scoped runtime directory；记录 PID、process start time、executable/argv 和 image identity。停止前全部复核，不按进程名批量终止。
5. **证据分层**：launcher exit、PID、serial、ports、guest readiness 和 service smoke 分别判断；某层失败不自动改写成组件失败。
6. **按任务选择验证**：复用已有 transport 决定。隔离测试已允许跳过证书/主机密钥验证时，自行填写 matching intent/authorization、范围、时限及恢复步骤，不再逐项确认；这些结果只证明连接与业务行为。不涉及 Web/Redfish 的 targeted 检查使用 `tls_mode=not_applicable`。
7. **端口范围明确**：默认 loopback。用户已经指定非 loopback bind 或 host exposure 时，自行填写 matching intent/authorization 并检查端口冲突；只有尚未授权的网络范围扩展才询问。
8. **新固件使用新 runtime**：持久化实例的 `restart` 不会自动写入新 HPM。验证新构建默认创建 fresh runtime；复用旧磁盘必须是明确的 stateful regression 目标。
9. **健康基线先于故障注入**：完整验收或 fault injection 先验证相应健康基线。普通 targeted 调试可用 `baseline.expected_state=not_requested`、`fault_injection=disabled`，不以全设备无告警为前提；不能靠停止 collector、放宽阈值或跳过请求的检查制造健康结果。
10. **结果契约可校验**：完整流程先验证 `openubmc-qemu-workflow-plan/v1`，结束后验证同一 digest 绑定的 `openubmc-qemu-workflow-result/v1`。Runtime 仅保存已验证结果，不代替 repository launcher 执行 QEMU。

日常开发复用已有缓存及任务拥有的持久实例；新 HPM 验收仍使用 fresh runtime。
大型 SDK、下载分块、临时归档和 raw 磁盘放仓库外，或用
`git check-ignore -v -- <精确生成目录>` 确认本地忽略，避免进入宿主 Git 快照。
在大规模构建/创建磁盘前，用 `du -sh` 与 `df -h` 记录实际占用及输出卷余量；
WSL 还记录承载 VHDX 的 Windows 卷余量（如 PowerShell `Get-Volume`）。
按本次预计需求处理低空间，不设置固定阻断阈值，不自动删除用户旧目录。

## Workflow

### 0. Classify the Request

读取 repositories、toolchain、artifact、requested scenario、requested verification、authorization、`qemu_testing_intent` 和用户改动。把请求分类为 discover、launch、observe、smoke、stop 或 diagnose-existing-instance。x86 开发闭环同时选择 `daily-development`、`model-simulation` 或 `alarm-testing`，并读取 [x86 QEMU development workflow](references/x86-development-workflow.md)。

完成条件：每个请求动作、QEMU root、runtime root 和不能触碰的外部状态均明确。

### 1. Discover Launcher and Inputs

- 从 handoff/user/repository 查找实际 launcher、config、machine/accelerator 选择和 image references。
- 读取 launcher help/源码，列出 inputs、PID/log handling、serial sink、network/port mapping 和 monitor/control channel。
- 从现有授权填写 normalized intent 和同名 authorization；记录 launcher/wrapper 或 Agent task command 的执行边界与源码检查证据。
- 解析 symlink/relative path，生成 image identity；输入不存在、身份冲突或来源不明时停止。
- 对构建交接同时核对 HPM、本仓 launcher 要求的完整 launch index、配套镜像/mock 输入、source revision、product version 和 package-binding gaps。Build 使用 bmcgo；显式 Bingo-only 产品保持 unsupported，不静默改写命令。
- 检查 task-scoped runtime directory、拟用 host ports 和现有 PID ownership。
- 新构建不得借用旧持久化磁盘证明生效；如果选择 existing runtime，记录其初始 artifact/disk identity 和 stateful 验证理由。
- 生成并验证 [QEMU plan](references/qemu-result-contract.md)，在任何 mutation 前固定 action、input、runtime、port、verification 和 authorization。

完成条件：final argv、image identity 和 port plan 可复核；`launcher.authorization_enforcement` 记录所用执行边界。只有必要输入缺失或实际越权时才标记 `read_only_blocked`。

### 2. Launch or Attach

- `launch=true` 还要求 `qemu_authorization.local_process_control=true`；非 loopback 方案另需 exposure intent 与 authorization。
- 启动前写 task-owned run manifest；启动后记录 PID/start time/executable/argv，而不是只相信旧 PID 文件。
- attach 到现有实例时只读收集身份；没有 ownership 时不得 stop/restart。
- 串口日志写入本次 run path，并保存 start offset，避免把旧 boot 日志当作新证据。
- 首启 timeout、host pressure、failed unit 或串口 fatal evidence 必须保留。仅在 task ownership 和 local process control authorization 均满足时做 bounded normal reboot recovery，并把失败 boot 与恢复 boot 分开记录。

完成条件：实例身份与本次 image/launcher 匹配，或结果明确为 blocked/attached-read-only。

### 3. Inspect and Smoke

按 `references/qemu-verification.md` 依次检查：

1. launcher/process identity；
2. serial boot progression 与 fatal signature；
3. host bind/forwarded port identity 和冲突；
4. guest readiness；
5. 用户要求的 SSH/Web/IPMI/MDB/service smoke；
6. 连续重启、coredump 或资源压力迹象。

x86 full acceptance 还核对 guest architecture/boot ID、product/model、persistent mounts、systemd、SELinux、真实 BMC 用户与 CLP、浏览器登录/刷新/退出、Redfish Basic/Session、IPMI RMCP+、bus permission、真实日志投递、resource-tree/alarm baseline，以及至少 120 秒 service/process identity stability。SNMP daemon stability 不等于 SNMP protocol 验证。

证书检查失败时保留该结果。有既定隔离测试授权时按对应 transport 继续业务检查，并标明未验证证书；否则仅跳过受影响的检查，继续其余项目。一次自然语言授权可同时填写相应 intent 和 authorization 字段。

完成条件：每个 smoke 项有时间、endpoint、verification mode 和结果；失败已落入一个 classification。

### 4. Stop and Clean Up

- `stop=true` 还要求 local process control authorization。
- 对比 PID、start time、executable/argv 和 run manifest 后，只停止当前 run 拥有的实例。
- 等待退出并验证端口释放；保留请求的 serial/run manifest，清理其余 task-owned runtime 文件。
- 身份不匹配时拒绝停止并报告 stale PID/ownership conflict。
- 默认保留 persistent disk、失败证据、plan/result 和 cache；只有明确授权删除实例数据时才清理完整 runtime。

完成条件：实例/端口/运行目录状态可证明，且没有影响其他 QEMU 进程。

### 5. Return Result

Return launcher, process identity, serial, port, image, readiness, smoke, stability, and cleanup results.
先用 `scripts/qemu_workflow_contract.py validate-result` 校验结果。`completed` requires fresh evidence for every requested intent and smoke item. 有 active Runtime Run 时，按 [证据交接](references/qemu-result-contract.md#runtime-evidence-handoff) 用 `prepare-evidence` 生成 bundle，并把输出提交给 `execute(kind=attach_qemu_evidence)`。此操作只附加证据，保留当前 Gate 和 Outcome。

## Smoke Classification and Routing

用户已要求验收后提交代码时，读取 `openubmc-code-submit`，交接已验证的 source
revision、镜像身份、QEMU 结果和未完成项。验收通过本身不授权推送或创建 MR/PR。

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
- `references/x86-development-workflow.md`：构建交接、fresh runtime、首次启动恢复、业务验收、健康基线和故障注入。
- `references/x86-repository-launcher.md`：仓库启动器命令、持久磁盘、验证器审查和 26.06 兼容问题。
- `references/qemu-result-contract.md`：可校验的 plan/result 字段和完成判据。
- `scripts/qemu_workflow_contract.py`：离线验证 plan digest、authorization gates、分层结果和 smoke coverage；不启动 QEMU。
