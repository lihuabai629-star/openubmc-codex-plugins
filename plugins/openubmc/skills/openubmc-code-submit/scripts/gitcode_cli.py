#!/usr/bin/env python3
"""GitCode API CLI tool for AI agents.

Usage:
  python gitcode_cli.py <command> [args...]

Commands:
  get-repo <owner> <repo>                   Get repository and fork identity
  get-branch <owner> <repo> <branch>        Get source or target branch identity
  list-prs <owner> <repo> [--state open]    List all matching PRs with pagination
  create-pr <owner> <repo> --help           Prepare/create a PR (preview by default)
  update-pr <owner> <repo> <number> --help  Prepare/update PR title and body
  get-user                                  Get current authenticated user
  get-pr <owner> <repo> <number>            Get PR metadata
  get-pr-files <owner> <repo> <number>      Get PR changed files
  get-pr-comments <owner> <repo> <number>   Get PR review comments
  get-pr-reviews <owner> <repo> <number>    Get PR reviews
  get-issue-comments <owner> <repo> <num>   Get PR issue comments
  check-reviewed <owner> <repo> <number>    Check if current user already reviewed
  get-design-topic <topic_id>               Fetch openUBMC design topic
  submit-review <owner> <repo> <number>     Submit review comment (use --body or --body-file)
  get-pr-commits <owner> <repo> <number>    Get PR commits
  post-issue-comment <owner> <repo> <num>   Post a comment on an Issue (use --body or --body-file)
  get-ai-review <owner> <repo> <number>     Get current AI user's review comments on a PR
  get-pr-linked-issues <owner> <repo> <number>  Get Issues linked to a PR (parses owner/repo from html_url)
"""

if __name__ == '__main__':
    import sys as _openubmc_sys
    _openubmc_sys.dont_write_bytecode = True
    import runpy as _openubmc_runpy
    from pathlib import Path as _openubmc_Path
    _openubmc_guard = _openubmc_Path(__file__).parent / '../../openubmc-debug/scripts/_plugin_entrypoint.py'
    _openubmc_cache = _openubmc_runpy.run_path(str(_openubmc_guard))['initialize'](__file__)


import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


API_BASE = "https://api.gitcode.com/api/v5"
TIMEOUT = 30
LINKED_ISSUE_URL_RE = re.compile(r"^https://gitcode\.com/([^/]+)/([^/]+)/issues/(\d+)(?:$|[/?#])")

class ApiError(RuntimeError):
    """Only secret-free diagnostics may cross the CLI boundary."""

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ApiError("redirect_refused")


def get_token():
    from pathlib import Path
    token = os.environ.get("GITCODE_TOKEN", "")
    if token:
        return token
    creds = Path.home() / ".git-credentials"
    if creds.is_file():
        for line in creds.read_text().splitlines():
            try:
                parsed = urllib.parse.urlsplit(line)
            except ValueError:
                continue
            if parsed.hostname == "gitcode.com":
                value = parsed.password or parsed.username
                if value:
                    return urllib.parse.unquote(value)
    raise ApiError("credentials_missing")


def validate_api_path(path):
    if (not path.startswith("/") or path.startswith("//") or "?" in path
            or "#" in path or "://" in path or any(ord(c) < 32 for c in path)
            or any(p in {".", ".."} for p in path.split("/"))):
        raise ApiError("invalid_api_path")


def api_request(path, params=None, body=None, method="GET"):
    import time
    validate_api_path(path)
    query = dict(params or {})
    if any(k.lower() in ("access_token", "token") for k in query):
        raise ApiError("credentials_must_use_private_source")
    token = get_token()
    headers = {"Accept": "application/json"}
    mode = os.environ.get("GITCODE_AUTH_MODE", "bearer")
    if mode == "query":
        query["access_token"] = token
    elif mode == "bearer":
        headers["Authorization"] = "Bearer " + token
    else:
        raise ApiError("invalid_auth_mode")
    suffix = "?" + urllib.parse.urlencode(query) if query else ""
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(API_BASE + path + suffix, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(req, timeout=TIMEOUT) as response:
                return {} if response.status == 204 else json.load(response)
        except urllib.error.HTTPError as err:
            if err.code == 429 and attempt < 2:
                try:
                    delay = min(30, max(1, int(err.headers.get("Retry-After", "2"))))
                except (ValueError, TypeError):
                    delay = 2 ** (attempt + 1)
                time.sleep(delay)
                continue
            raise ApiError(f"HTTP {err.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise ApiError("transport_or_response_failed") from None
    raise ApiError("retry_limit")


def api_get(path, params=None, raise_on_error=True):
    # Even optional data must not turn a failed request into an empty successful list.
    return api_request(path, params=params)


def api_get_all(path, params=None, per_page=100, max_pages=50, raise_on_error=True):
    if not 1 <= per_page <= 100 or max_pages < 1:
        raise ApiError("invalid_pagination")
    out = []
    params = dict(params or {})
    for page in range(1, max_pages + 1):
        batch = api_get(path, {**params, "page": page, "per_page": per_page})
        if not isinstance(batch, list):
            raise ApiError("incomplete: expected_list")
        out.extend(batch)
        if len(batch) < per_page:
            return out
    raise ApiError("incomplete: pagination_limit")


def write_preview(path, body, method):
    import hashlib
    validate_api_path(path)
    item = {"target": API_BASE + path, "method": method, "body": body}
    digest = hashlib.sha256(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**item, "status": "prepared", "preview_sha256": digest}


def api_post(path, body_dict=None, params=None, method="POST", raise_on_error=True):
    if params:
        raise ApiError("write_query_parameters_not_supported")
    preview = write_preview(path, body_dict or {}, method)
    confirmed = None
    if "--confirmed" in sys.argv:
        index = sys.argv.index("--confirmed")
        if index + 1 < len(sys.argv):
            confirmed = sys.argv[index + 1]
    if confirmed is None:
        print(json.dumps(preview, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    if confirmed != preview["preview_sha256"]:
        raise ApiError("confirmed_content_mismatch")
    return api_request(path, body=body_dict or {}, method=method)


def cmd_get_user():
    print(json.dumps(api_get("/user"), ensure_ascii=False, indent=2))


def cmd_get_pr(owner, repo, number):
    print(json.dumps(api_get(f"/repos/{owner}/{repo}/pulls/{number}"), ensure_ascii=False, indent=2))


def cmd_get_pr_files(owner, repo, number):
    # 变更文件 >100 时分页拉全,否则后续受检文件会被静默截断
    print(json.dumps(api_get_all(f"/repos/{owner}/{repo}/pulls/{number}/files"), ensure_ascii=False, indent=2))


def cmd_get_pr_comments(owner, repo, number):
    # 评论 >100 条时分页拉全(幂等检查依赖完整历史)
    print(json.dumps(api_get_all(f"/repos/{owner}/{repo}/pulls/{number}/comments"), ensure_ascii=False, indent=2))


def cmd_get_pr_reviews(owner, repo, number):
    # review 记录 >100 条时分页拉全
    print(json.dumps(api_get_all(f"/repos/{owner}/{repo}/pulls/{number}/reviews"), ensure_ascii=False, indent=2))


def cmd_get_issue_comments(owner, repo, number):
    # 评论 >100 条时分页拉全(幂等检查依赖完整历史)
    print(
        json.dumps(
            api_get_all(f"/repos/{owner}/{repo}/issues/{number}/comments"),
            ensure_ascii=False,
            indent=2,
        )
    )


def cmd_check_reviewed(owner, repo, number):
    review_keywords = ["review", "code review", "检视", "审查", "逐项", "发现的问题"]

    user_data = api_get("/user")
    username = user_data.get("login", "")

    source_paths = [
        f"/repos/{owner}/{repo}/pulls/{number}/comments",
        f"/repos/{owner}/{repo}/issues/{number}/comments",
        f"/repos/{owner}/{repo}/pulls/{number}/reviews",
    ]

    for path in source_paths:
        source = api_get_all(path, raise_on_error=False)
        if source is None or not isinstance(source, list):
            continue
        for item in source:
            item_user = ""
            if isinstance(item.get("user"), dict):
                item_user = item["user"].get("login", "")
            body = (item.get("body") or "").lower()
            if item_user == username:
                for kw in review_keywords:
                    if kw.lower() in body:
                        print(
                            json.dumps(
                                {
                                    "reviewed": True,
                            "blocks_review": False,
                                    "username": username,
                                    "matched_keyword": kw,
                                    "comment_id": item.get("id"),
                                },
                                ensure_ascii=False,
                            )
                        )
                        return

    print(json.dumps({"reviewed": False, "blocks_review": False, "username": username}, ensure_ascii=False))


def cmd_get_design_topic(topic_id):
    if not str(topic_id).isdigit() or int(topic_id) <= 0:
        print(json.dumps({"error": f"Invalid topic_id: {topic_id}"}))
        sys.exit(1)

    url = f"https://discuss.openubmc.cn/t/topic/{topic_id}.json"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            posts = data.get("post_stream", {}).get("posts", [])
            result = []
            for post in posts:
                result.append(
                    {
                        "username": post.get("username", ""),
                        "cooked": post.get("cooked", ""),
                        "created_at": post.get("created_at", ""),
                    }
                )
            print(
                json.dumps(
                    {
                        "title": data.get("title", ""),
                        "posts": result,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
    except urllib.error.HTTPError as e:
        print(json.dumps({"error": f"HTTP {e.code}", "detail": "Failed to fetch topic"}))
        sys.exit(1)
    except urllib.error.URLError as e:
        print(json.dumps({"error": "connection_failed", "detail": "connection_failed"}))
        sys.exit(1)


def cmd_submit_review(owner, repo, number):
    body = ""
    args = sys.argv[5:]
    i = 0
    while i < len(args):
        if args[i] == "--body" and i + 1 < len(args):
            body = args[i + 1]
            i += 2
        elif args[i] == "--body-file" and i + 1 < len(args):
            with open(args[i + 1], encoding="utf-8") as f:
                body = f.read()
            i += 2
        else:
            i += 1

    if not body:
        print(json.dumps({"error": "Review body is required (--body or --body-file)"}))
        sys.exit(1)

    result = api_post(
        f"/repos/{owner}/{repo}/pulls/{number}/comments",
        {
            "body": body,
        },
    )
    if result:
        print(json.dumps({"status": "success", "method": "pr_comment"}, ensure_ascii=False))


def cmd_get_pr_commits(owner, repo, number):
    # commit >100 个时分页拉全
    print(json.dumps(api_get_all(f"/repos/{owner}/{repo}/pulls/{number}/commits"), ensure_ascii=False, indent=2))


def cmd_post_issue_comment(owner, repo, number):
    body = ""
    args = sys.argv[5:]
    i = 0
    while i < len(args):
        if args[i] == "--body" and i + 1 < len(args):
            body = args[i + 1]
            i += 2
        elif args[i] == "--body-file" and i + 1 < len(args):
            with open(args[i + 1], encoding="utf-8") as f:
                body = f.read()
            i += 2
        else:
            i += 1

    if not body:
        print(json.dumps({"error": "Comment body is required (--body or --body-file)"}))
        sys.exit(1)

    # 注意：这是 Issue 评论端点 /issues/{n}/comments，与 submit-review 的 /pulls/{n}/comments 不同。
    # owner/repo/number 应取自关联 Issue 自身（可能位于与 PR 不同的仓库）。
    result = api_post(
        f"/repos/{owner}/{repo}/issues/{number}/comments",
        {
            "body": body,
        },
    )
    if result:
        print(json.dumps({"status": "success", "method": "issue_comment"}, ensure_ascii=False))


def cmd_get_ai_review(owner, repo, number):
    user_data = api_get("/user")
    username = user_data.get("login", "")

    # AI 检视评论只来自 /pulls/{n}/comments；禁止用 /issues/{n}/comments 或 /pulls/{n}/reviews（对 PR 号返回错误数据）。
    comments = api_get_all(
        f"/repos/{owner}/{repo}/pulls/{number}/comments",
        raise_on_error=False,
    )
    if comments is None or not isinstance(comments, list):
        print(json.dumps([], ensure_ascii=False))
        return

    ai_comments = []
    for item in comments:
        item_user = ""
        if isinstance(item.get("user"), dict):
            item_user = item["user"].get("login", "")
        if item_user == username:
            ai_comments.append(
                {
                    "id": item.get("id"),
                    "comment_type": item.get("comment_type"),
                    "body": item.get("body", ""),
                    "created_at": item.get("created_at", ""),
                    "user": item.get("user", {}),
                }
            )

    print(json.dumps(ai_comments, ensure_ascii=False, indent=2))


def cmd_get_pr_linked_issues(owner, repo, number):
    issues = api_get_all(
        f"/repos/{owner}/{repo}/pulls/{number}/issues",
        {"per_page": "100"},
        raise_on_error=False,
    )
    if issues is None or not isinstance(issues, list):
        print(json.dumps([], ensure_ascii=False))
        return

    result = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        # 关联 Issue 可能位于与 PR 不同的仓库；从 html_url 解析其自身的 owner/repo。
        issue_owner, issue_repo, issue_number = owner, repo, issue.get("number")
        match = LINKED_ISSUE_URL_RE.match(issue.get("html_url") or "")
        if match:
            issue_owner, issue_repo, parsed_number = match.groups()
            issue_number = int(parsed_number)
        enriched = dict(issue)
        enriched["owner"] = issue_owner
        enriched["repo"] = issue_repo
        enriched["issue_number"] = issue_number
        result.append(enriched)

    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_create_issue(owner, repo):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--body-file", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--labels", default="")
    parser.add_argument("--confirmed")
    args = parser.parse_args(sys.argv[4:])
    from pathlib import Path
    body = Path(args.body_file).read_text(encoding="utf-8")
    payload = {"title": args.title, "body": body}
    if args.labels:
        payload["labels"] = [x.strip() for x in args.labels.split(",") if x.strip()]
    result = api_post(f"/repos/{owner}/{repo}/issues", payload)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_get_repo(owner, repo):
    print(json.dumps(api_get(f"/repos/{owner}/{repo}"), ensure_ascii=False, indent=2))


def cmd_get_branch(owner, repo, branch):
    encoded = urllib.parse.quote(branch, safe="")
    print(json.dumps(api_get(f"/repos/{owner}/{repo}/branches/{encoded}"), ensure_ascii=False, indent=2))


def cmd_list_prs(owner, repo):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", choices=("open", "closed", "merged", "all"), default="open")
    args = parser.parse_args(sys.argv[4:])
    print(json.dumps(api_get_all(f"/repos/{owner}/{repo}/pulls", {"state": args.state}),
                     ensure_ascii=False, indent=2))


def valid_project_part(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value)) and value not in {".", ".."}


def read_body(path):
    from pathlib import Path
    body = Path(path).read_text(encoding="utf-8")
    if not body.strip():
        raise ApiError("body_required")
    return body


def cmd_create_pr(owner, repo):
    import argparse
    parser = argparse.ArgumentParser(description="Preview a PR; publish only after actual user confirmation.")
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--fork-path")
    parser.add_argument("--title", required=True)
    parser.add_argument("--body-file", required=True)
    parser.add_argument("--issues", required=True, help="Real Issue IDs separated by semicolons; explicitly empty if allowed")
    parser.add_argument("--draft", action="store_true")
    parser.add_argument("--confirmed")
    args = parser.parse_args(sys.argv[4:])
    if not args.title.strip() or not args.base.strip() or not args.head.strip():
        raise ApiError("title_and_branches_required")
    if args.issues and not re.fullmatch(r"[1-9][0-9]*(;[1-9][0-9]*)*", args.issues):
        raise ApiError("invalid_issue_numbers")
    if ":" in args.head:
        namespace, branch = args.head.split(":", 1)
        if not valid_project_part(namespace) or not branch or ":" in branch or not args.fork_path:
            raise ApiError("cross_fork_requires_owner_branch_and_fork_path")
    elif args.fork_path:
        raise ApiError("fork_path_requires_owner_in_head")
    if args.fork_path:
        parts = args.fork_path.split("/")
        if len(parts) != 2 or not all(valid_project_part(p) for p in parts) or parts[0] != namespace:
            raise ApiError("fork_path_does_not_match_head_owner")
    payload = {"title": args.title, "head": args.head, "base": args.base,
               "body": read_body(args.body_file), "inner_issue_nums": args.issues,
               "draft": args.draft, "prune_source_branch": False}
    if args.fork_path:
        payload["fork_path"] = args.fork_path
    print(json.dumps(api_post(f"/repos/{owner}/{repo}/pulls", payload), ensure_ascii=False, indent=2))


def cmd_update_pr(owner, repo, number):
    import argparse
    parser = argparse.ArgumentParser(description="Preview a PR title/body update.")
    parser.add_argument("--title", required=True)
    parser.add_argument("--body-file", required=True)
    parser.add_argument("--confirmed")
    args = parser.parse_args(sys.argv[5:])
    if not args.title.strip():
        raise ApiError("title_required")
    payload = {"title": args.title, "body": read_body(args.body_file)}
    print(json.dumps(api_post(f"/repos/{owner}/{repo}/pulls/{number}", payload, method="PATCH"),
                     ensure_ascii=False, indent=2))


COMMANDS = {
    "get-repo": (cmd_get_repo, 2),
    "get-branch": (cmd_get_branch, 3),
    "list-prs": (cmd_list_prs, 2),
    "create-pr": (cmd_create_pr, 2),
    "update-pr": (cmd_update_pr, 3),
    "create-issue": (cmd_create_issue, 2),
    "get-user": (cmd_get_user, 0),
    "get-pr": (cmd_get_pr, 3),
    "get-pr-files": (cmd_get_pr_files, 3),
    "get-pr-comments": (cmd_get_pr_comments, 3),
    "get-pr-reviews": (cmd_get_pr_reviews, 3),
    "get-issue-comments": (cmd_get_issue_comments, 3),
    "check-reviewed": (cmd_check_reviewed, 3),
    "get-design-topic": (cmd_get_design_topic, 1),
    "submit-review": (cmd_submit_review, 3),
    "get-pr-commits": (cmd_get_pr_commits, 3),
    "post-issue-comment": (cmd_post_issue_comment, 3),
    "get-ai-review": (cmd_get_ai_review, 3),
    "get-pr-linked-issues": (cmd_get_pr_linked_issues, 3),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)

    cmd_name = sys.argv[1]
    handler, expected_args = COMMANDS[cmd_name]

    if len(sys.argv) < 2 + expected_args:
        print(f"Error: {cmd_name} requires {expected_args} arguments")
        print(f"Usage: python gitcode_cli.py {cmd_name} {'<arg> ' * expected_args}".strip())
        sys.exit(1)

    arg_end = 2 + expected_args
    args = sys.argv[2:arg_end]
    if expected_args >= 2 and not all(valid_project_part(value) for value in args[:2]):
        raise ApiError("invalid_owner_or_repo")
    if expected_args == 3 and cmd_name != "get-branch" and not re.fullmatch(r"[1-9][0-9]*", args[2]):
        raise ApiError("invalid_number")
    handler(*args)


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        main()
    except ApiError as error:
        print(json.dumps({"status": "incomplete", "error": str(error)}), file=sys.stderr)
        sys.exit(2)
    except (OSError, UnicodeError, ValueError):
        print(json.dumps({"status": "incomplete", "error": "local_input_or_credentials_unavailable"}), file=sys.stderr)
        sys.exit(2)
