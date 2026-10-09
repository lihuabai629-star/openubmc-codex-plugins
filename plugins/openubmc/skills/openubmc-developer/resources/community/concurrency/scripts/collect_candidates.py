#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# openUBMC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#         http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""只读收集 C/C++ 与 Lua coredump 审查线索；输出不是缺陷判定。"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

GROUPS = {
    "containers": (
        r"\b(?:std::)?(?:unordered_(?:multi)?map|(?:multi)?map|"
        r"unordered_(?:multi)?set|(?:multi)?set|vector|deque|list)\s*<|"
        r"\b(?:mc::)?(?:dict|variants)\b|"
        r"\b(?:m_|s_|g_)\w+\s*(?:\.|->)\s*"
        r"(?:find|at|begin|end|size|empty|insert|emplace|try_emplace|"
        r"erase|clear|swap|push_back|pop_back|reserve|resize)\s*\(|"
        r"\b(?:m_|s_|g_)\w+\s*\["
    ),
    "shared_locks": (
        r"\b(?:std::shared_lock|SharedLock|ipc_shared_lock_guard|"
        r"shm_(?:global|object)_lock_shared_exec|lock_shared|"
        r"acquire_read_lock|pthread_rwlock_rdlock)\b"
    ),
    "state_and_context": (
        r"\b(?:static|thread_local|mutable)\b|"
        r"\b\w*(?:[Cc]ontext|[Cc]ache)\w*\b|"
        r"\b(?:set_req|get_instance|instance)\s*\("
    ),
    "callbacks_and_lifecycle": (
        r"\b(?:on_object_added|on_object_removed|property_changed|"
        r"shutdown|disconnect|connect|emit|register_object|unregister_object)\b|"
        r"\bstd::(?:thread|async)\b|\[\s*this\s*[,\]]|"
        r"\b(?:then|catch_error|post|dispatch|defer|single_shot|"
        r"wait_callbacks|active_callbacks|add_cleanup_callback|clear_connection_slots)\b"
    ),
    "exclusive_locks": (
        r"\b(?:std::(?:lock_guard|unique_lock|scoped_lock)|Lock|"
        r"ipc_lock_guard|shm_(?:global|object)_lock_exec|"
        r"acquire_write_lock|pthread_mutex_lock|pthread_rwlock_wrlock)\b"
    ),
    "ownership_and_retirement": (
        r"\b(?:shared_from_this|weak_from_this|shared_ptr|weak_ptr|"
        r"keep_alive|reset_for_test|clear_connection_slots|add_cleanup_callback|"
        r"is_service_registered|remove_match|begin_callback|end_callback|"
        r"wait_callbacks|active_callbacks|unregister_object|unregister_private_object|"
        r"get_raw|JsonValue)\b|~\w+\s*\("
    ),
    "borrowed_views": (
        r"\b(?:(?:std|mc)::)?(?:string_view|span)\b|"
        r"\b(?:call_info|active_call)\b|"
        r"(?:\.|->)\s*(?:c_str|data|as_string_view|get_raw)\s*\("
    ),
    "lua_numbers_and_gc": (
        r"\b(?:lua_(?:pushinteger|pushnumber|tointeger|tointegerx|tonumber|"
        r"tonumberx|gc|pcall|pcallk|settop|isinteger)|luaL_(?:checkinteger|"
        r"optinteger|checknumber|optnumber)|lua_Integer|lua_Number|"
        r"LUA_GC\w*|LUA_VERSION_NUM|LUA_MININTEGER|LUA_MAXINTEGER|"
        r"INT64_MIN|INT64_MAX|UINT64_MAX|k_max_safe_integer)\b|"
        r"\bcollectgarbage\s*\("
    ),
}
SOURCE_GLOBS = (
    "*.c",
    "*.cc",
    "*.cpp",
    "*.cxx",
    "*.c++",
    "*.h",
    "*.hh",
    "*.hpp",
    "*.hxx",
    "*.h++",
    "*.inc",
    "*.inl",
    "*.ipp",
    "*.tpp",
    "*.txx",
)
GROUP_SOURCE_GLOBS = {"lua_numbers_and_gc": SOURCE_GLOBS + ("*.lua",)}
EXCLUDED_GLOBS = (
    "!**/builddir/**",
    "!**/build/**",
    "!**/.git/**",
    "!**/third_party/**",
    "!**/third-party/**",
    "!**/vendor/**",
    "!**/node_modules/**",
)


def collect(root, scopes, limit):
    result = {}
    for name, pattern in GROUPS.items():
        command = ["rg", "--json", "--color", "never", "--sort", "path", "--no-messages"]
        # 用文件类型筛选后缀；正向 --glob 会覆盖仓库的 ignore 规则。
        for glob in GROUP_SOURCE_GLOBS.get(name, SOURCE_GLOBS):
            command.extend(["--type-add", "concurrencysource:" + glob])
        command.extend(["--type", "concurrencysource"])
        for glob in EXCLUDED_GLOBS:
            command.extend(["--glob", glob])
        command.extend(["-e", pattern, "--", *scopes])
        process = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if process.returncode not in (0, 1):
            raise RuntimeError(
                f"rg group {name} failed (exit {process.returncode}): "
                f"{process.stderr.strip() or '检查扫描路径及文件读取权限'}"
            )
        hits = []
        total = 0
        for raw in process.stdout.splitlines():
            record = json.loads(raw)
            if record["type"] != "match":
                continue
            total += 1
            if limit and len(hits) >= limit:
                continue
            data = record["data"]
            path_data = data["path"]
            line_data = data["lines"]
            # 非 UTF-8 路径/行仍保留 rg 的 base64 证据。
            hits.append(
                {
                    "path": path_data.get("text"),
                    "path_bytes": path_data.get("bytes"),
                    "line": data["line_number"],
                    "text": line_data.get("text", "").rstrip("\r\n"),
                    "text_bytes": line_data.get("bytes"),
                }
            )
        result[name] = {"total": total, "returned": len(hits), "omitted": total - len(hits), "candidates": hits}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="目标仓库根目录")
    parser.add_argument("--scope", action="append", help="根目录内的文件/目录，可重复")
    parser.add_argument("--limit", type=int, default=80, help="每组位置上限，0 为全部")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        parser.error("--root 必须为存在的目录")
    if args.limit < 0:
        parser.error("--limit 必须大于等于 0")
    if not shutil.which("rg"):
        parser.error("缺少 rg；请安装 ripgrep，或按 SKILL.md 手工搜索")
    scopes = args.scope or (["libraries"] if (root / "libraries").is_dir() else ["."])
    normalized = []
    for scope in scopes:
        target = (root / scope).resolve()
        try:
            relative = target.relative_to(root)
        except ValueError:
            parser.error(f"--scope 不能超出 --root: {scope}")
        if not target.exists():
            parser.error(f"--scope 不存在: {scope}")
        normalized.append(str(relative))
    try:
        groups = collect(root, normalized, args.limit)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"扫描失败: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "candidate_only",
                "root": str(root),
                "scopes": normalized,
                "limit_per_group": args.limit,
                "coverage": (
                    "rg ignore rules + C/C++ suffix allowlist " "(Lua for numeric/GC group) + excluded directories"
                ),
                "source_globs": SOURCE_GLOBS,
                "group_source_globs": GROUP_SOURCE_GLOBS,
                "excluded_globs": EXCLUDED_GLOBS,
                "groups": groups,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
