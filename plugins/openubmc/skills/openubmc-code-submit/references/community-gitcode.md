# 社区 GitCode 贡献

## 准备代码与贡献内容

从当前仓库、GitCode 账号和 API 项目信息核对个人 fork、openUBMC 上游、目标分支
及 fork 关系。读取该仓库当前 CONTRIBUTING、PR/Issue 模板、CLA 和 CI 规则。
复用相关 Issue/PR，保持其真实 owner/repo/编号。内部项目策略、作者身份、分支
和版本不作为社区默认值。

fetch 上游及个人 remote，保留已有修改，按仓库规则审查 diff、运行验证、形成提交。
只有推送已获授权时推个人 fork，明确 `HEAD:refs/heads/<source>`；检查推送 URL
与平台，推送后读回 SHA。单一提交项目可用 `scripts/check_submission.py`；
允许多提交的项目传 `--expected-commits <实际约定数量>`。结果未知先读远端，
不盲目重推；force push 需要明确授权与绑定旧 SHA 的 lease。

有对应仓库模板时使用它；否则使用 [PR 描述](../templates/pr.md) 或
[Issue 内容](../templates/issue.md)。正文写具体问题、行为变化、相关实现和真实
验证结果。AI 声明按社区当前政策填写实际工具与工作量，缺少数据时明确缺口。
不伪造 CLA、人工验收、Issue 编号或审批。

## PR 与 API

读取 [GitCode API](gitcode-api.md)，使用本 Skill 自带的 `scripts/gitcode_cli.py`，
无需另装全局 `gitcode` Skill。先查询账号、目标和个人项目，分页查询 PR，按源项目、
源分支、目标项目、目标分支查重。当前 head 变化后重新检查受影响范围。

`create-pr` 使用目标 owner/repo；跨仓库源为 `--head <fork-owner>:<branch>`，
还必须提供 `--fork-path <fork-owner>/<fork-repo>`。Issue 参数来自真实关联，
`--issues '1;2'`；仅在仓库允许无关联时显式用 `--issues ''`。已有 PR 用
`update-pr` 修改标题/正文，避免重复创建。CLI 不自动选择评审人、审批、合并或删分支。

## 公开写入与结果

所有公开 Issue/PR、评论、Review、回复、resolve、审批或机器人命令，提交前必须
向用户展示**目标及完整内容**并获得明确确认。同一目标和未变正文已有确认时继续执行；
目标或内容变化后重新展示。先完成代码、验证、正文和预览，再进行最后这一步。
用户要求本地草稿时交付草稿，不进入发布步骤。

CLI 默认仅输出预览，不读取凭据、不发请求。确认后传同一预览的
`--confirmed <preview_sha256>`；摘要只绑定内容，不能代替用户真实确认。
写入超时或结果未知，先读服务器上的同一 PR/Issue，避免重复发布。

发布后读回 source/target、head SHA、标题和正文，按 [PR 状态](pr-state.md)
分别核对 CLA、CI、关联 Issue、未解决讨论和合并状态。CI 通过不证明评审已完成。
返回实际 URL 和阻塞；保留本地预览与已发布状态的区别。
