# 内部 GitLab 提交

## 基线与提交

内部“提交代码”沿用仓库约定：验证、形成一笔修复提交、推个人 fork。
“准备草稿”“仅 add”“不要提交/推送”等本次限制优先。MR 只在用户要求时创建或修改。

1. 核对当前仓库、remote、作者、开发分支、上游目标和个人分支。作者采用本仓
   Git 配置及当前用户约定；不修改全局身份，不从插件预设个人姓名、地址或项目 ID。
2. 备份本次补丁；fetch 对应上游与个人 remote。以最新目标基线迁移最小补丁，
   保留他人的基线历史。fetch 失败不能声称基线最新；可继续本地准备并报告缺口。
   若开发基线与合并目标确有不同，先解析现有仓库约定，缺少必要决定时才询问。
3. 检查完整 diff 与相关测试。版本和变更日志遵循该项目当前规则，一并进入同一提交。
   编译使用项目选择的 bmcgo 流程，实际包构建交给 `openubmc-build`。
4. 只暂存本次文件，单一修复相对目标为 `0 1`。后续修正 amend 这笔提交；
   已推送历史的改写仍需已有明确授权和精确 lease，不以 amend 约定推定授权。

只读检查（remote 名可覆盖默认值）：

```sh
python3 <skill-dir>/scripts/check_submission.py --repo <repo> \
  --upstream-remote <upstream> --source-remote <personal> \
  --target-branch <target> --source-branch <source> --phase pre-push --verify-remote
```

脚本验证干净工作区、历史范围和最新引用，不代替 diff 审查或编译。离线检查只证明
本地引用；`--verify-remote` 会读取上游 fetch URL 与个人 push URL，拒绝多个地址。

## 个人 fork 推送

普通推送明确来源和目标：`git push -u <personal> HEAD:refs/heads/<source>`。
先用当前账号和项目元数据证明该 remote 是个人 fork；remote 名不是权限证明。
不向上游直接推送。

改写已推送分支时，先保留旧提交、记录远端 SHA，确认改写已获授权，再使用
`--force-with-lease=refs/heads/<source>:<expected-old-sha>`。远端变化时保留现场，
不重取新 SHA 后盲目覆盖。完成后执行上述检查的 `--phase post-push --verify-remote`。

## 创建或修正 MR

用目标主机的 GitLab MCP、glab 或 API v4。先查询登录用户及 source/target 项目，
核对 fork 关系、源分支远端 SHA、目标分支。CLI 与 MCP 的账号可能不同；404 需要
区分账号权限与项目不存在，不能自动换账号。

仅在已要求 MR 时，分页查询同一 source project/branch、target project/branch
的 open MR，复用已有 MR。内部标题/描述采用已适用的简短格式：

```text
标题： 【修改人】<当前修改人> 【修改描述】<具体修改>
描述：
【修改人】<当前修改人>
【修改描述】<具体修改>
```

当前仓库模板或用户指定优先；详细日志不复制进描述。修改 MR 描述不改写 commit。
已授权的私有 MR 不因社区公开消息规则重复确认；仓库另有规则时按实际适用范围执行。

跨 fork 创建：`POST /api/v4/projects/<source-project-id>/merge_requests`，
结构化 body 包含 `source_branch`、`target_branch`、**`target_project_id`**、
`title`、`description`。如果 MCP schema 无目标项目字段，使用支持该字段的
原生 API 或 glab；不要先创建到错误项目。修正使用目标项目的 MR 更新接口。

复用该主机现有凭据提供者，凭据只留在内存/认证 header。多行正文使用结构化参数
或 UTF-8 `--body-file`，不拼接 shell 字符串。超时或结果未知，先查询同一四元组
确定是否已创建，再决定是否重试。

读回实际 MR 及全部提交：检查 source/target 项目和分支、SHA、唯一提交、标题与
正文一致。返回真实 web URL。合并、审批和向他人发送评论需要各自的明确授权。
GitCode 的 CLA、Issue 关联、社区机器人及 AI 声明按社区政策执行，不套到内部 MR。
