# PR 状态与贡献阻塞

先固定 PR head 与当前更新时间，分页读取标签、评论、CI 和未解决讨论。按时间和 head 识别最新状态，不把旧绿表替代当前失败标签。Issue 关联检查其真实 owner/repo 与当前关联状态，多个仓库的相同编号不是同一个 Issue。

分别核对 CLA 身份、贡献权限、needs-issue、unresolved-reviews、stat/needs-squash、CI、mergeable、review/approve。无推送权限、CLA 未接纳、CI 失败和讨论未解决是不同阻塞；CI 绿不证明设计一致或讨论已修复。

先准备完整可审的 Issue/PR 内容与本地补丁。已有对应 PR 时继续更新，不重复创建。分支、提交方式与仓库模板取当前 AGENTS 和平台规定；不从旧示例自动 amend/force-push。

机器人评论、审批、resolve、联系维护者和任何公开回复都先展示目标和全文并获得明确确认；不把查看或监控授权当作合并授权。提交后核对服务器返回状态、目标和实际 head，不能只看 HTTP 200。历史机器人命令以当前仓库支持为准。
