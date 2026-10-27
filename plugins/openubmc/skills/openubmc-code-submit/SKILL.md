---
name: openubmc-code-submit
description: "提交或推送 openUBMC 代码、准备或更新内部 GitLab MR 与社区 GitCode PR；核对个人 fork、目标分支、单一提交和验证证据。Conan 包上传由 openubmc-publish 负责。"
---

# openUBMC 代码提交

At a stage change, read [the phase handoff](../openubmc-debug/references/skill-routing.md)
and its owner; carry the Run and authorization.

## 选择目标平台

读取目标仓库的 AGENTS.md、当前授权和工作区状态。区分开发分支、上游基线、
合并目标以及个人推送分支；名称相同不证明角色相同。记录本次改动范围，保留其他改动。

用 `scripts/submission_route.py --repo <repo> --source-remote <个人remote>
--upstream-remote <上游remote>` 检查实际推送地址与上游读取地址。
脚本只读取本地 Git 配置；GitCode 按精确主机识别，内部 GitLab 需要从仓库约定或
已核实的平台身份传入 `--gitlab-host <host>`。未知主机、跨平台或多个推送地址
返回待核实状态，不能把任何非 GitCode 仓库都当成 GitLab。

| 目标 | 本阶段必读 |
| --- | --- |
| 公司内部 GitLab | [内部提交](references/internal-gitlab.md) |
| 社区 GitCode | [社区贡献](references/community-gitcode.md) |

用户已选定平台但 remote 不匹配时，先保留补丁并查明目标。不要更改 remote、
切换账号或把内部代码复制到公开仓库来消除不匹配。

## 继承范围与验证

- 仅修改、仅暂存、准备草稿、先别推送：完成指定的本地步骤。
- 提交并推送代码：验证后 commit/amend，推已确定的个人 fork，再核对远端 SHA。
  单独“提交代码”按已适用的仓库/平台约定执行。
- 创建或修改 MR/PR：准备代码、完整正文和目标，按所选平台的发布规则完成。
  推送代码本身不授权新建 MR/PR、合并、审批或联系他人。
- Conan 上传、manifest 更新、固件升级及 QEMU 操作分别继承其已获授权范围。

从 Developer 接收本次文件、源仓库和实际验证；从 Build 接收源 revision、包或 HPM
身份及构建结果；从 QEMU 接收对应镜像、实例身份和 smoke/恢复结果。提交树必须与
验证源码一致；rebase/amend 后核对树和产物绑定，变化部分重新验证，旧证据保持原 SHA。
缺失、失败或依赖阻塞如实写入提交交接，不把语法检查或 QEMU 端口可达写成完整验收。

源码提交通过 Git 和所选平台 API 执行。此 Skill 不新增 Runtime Gate 或执行器，
本地检查报告不是 Runtime Outcome；已有 Run 的状态继续由 Runtime 管理。

## 交付

报告实际平台、基线、提交 SHA、个人远端 SHA、已执行的验证及未完成项。
MR/PR 只在服务器读回核验后报告为已发布，返回真实链接并挂载到当前任务。
平台不支持挂载时保留链接，注明未挂载。草稿、预览和远端发布状态分别说明。
