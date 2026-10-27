# GitCode API helper

所有命令使用同目录插件携带的 `scripts/gitcode_cli.py`，API 基址固定为
`https://api.gitcode.com/api/v5`。凭据优先取 `GITCODE_TOKEN`，否则读取私有
Git credentials；不输出 token、认证 URL、原始异常或凭据文件。
默认 Bearer header；仅当已验证的端点必须 query 认证时用 `GITCODE_AUTH_MODE=query`。

```sh
python3 <skill-dir>/scripts/gitcode_cli.py get-user
python3 <skill-dir>/scripts/gitcode_cli.py get-repo <owner> <repo>
python3 <skill-dir>/scripts/gitcode_cli.py get-branch <owner> <repo> <branch>
python3 <skill-dir>/scripts/gitcode_cli.py list-prs <owner> <repo> --state open
python3 <skill-dir>/scripts/gitcode_cli.py get-pr <owner> <repo> <number>
python3 <skill-dir>/scripts/gitcode_cli.py get-pr-commits <owner> <repo> <number>
python3 <skill-dir>/scripts/gitcode_cli.py get-pr-files <owner> <repo> <number>
python3 <skill-dir>/scripts/gitcode_cli.py create-pr <owner> <repo> \
  --head <fork-owner>:<branch> --fork-path <fork-owner>/<repo> --base <target> \
  --title '<title>' --body-file <utf8-file> --issues '<real-issue-numbers>'
python3 <skill-dir>/scripts/gitcode_cli.py update-pr <owner> <repo> <number> \
  --title '<title>' --body-file <utf8-file>
```

create/update/comment 默认只预览，按 [社区贡献](community-gitcode.md) 获得确认后
增加 `--confirmed <preview_sha256>`。完整标题、正文、源/目标和关联字段都绑定摘要。
`--draft` 是真实远端草稿 PR，仍需要公开写入确认。

列表自动分页，页失败或触达上限返回 incomplete；不将部分列表当全部。
429 有界退避，其他网络失败不自动重发写入。先固定 PR head，按该 SHA 读取完整
文件，结束前再次核对 head。`submit-review` 实际发表普通 PR 评论，不能称为
formal Review；Review ID、comment ID 和 discussion ID 分开使用。

创建 PR 契约核对自 GitCode 官方 API 文档（2026-10-23）：

- [创建 PR](https://docs.gitcode.com/docs/apis/post-api-v-5-repos-owner-repo-pulls)：
  `head=username:branch`、跨仓必填 `fork_path`、`inner_issue_nums`。
- [查询 PR 列表](https://docs.gitcode.com/docs/apis/get-api-v-5-repos-owner-repo-pulls)
- [更新 PR](https://docs.gitcode.com/docs/apis/patch-api-v-5-repos-owner-repo-pulls-number)

适配来源：`gitcode` API helper、`openubmc-community-contribution` 的贡献规则与
`gitlab-code-submit` 的只读提交检查。社区部分许可证见 [LICENSE](../LICENSE.marketplace)。
只使用包内路径；个人配置、历史会话、项目 ID 和凭据不随包分发。
