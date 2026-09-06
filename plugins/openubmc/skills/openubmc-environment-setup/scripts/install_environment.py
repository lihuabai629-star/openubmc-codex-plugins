#!/usr/bin/env python3
"""Install, inspect, repair, update, or remove the openUBMC agent workflow."""

from __future__ import annotations

import argparse
import ast
import base64
from contextlib import redirect_stdout
import getpass
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Literal, Mapping, NamedTuple, TypedDict
import urllib.error
import urllib.parse
import urllib.request


CLIENT_CONFIG_PATH = Path(__file__).resolve().with_name("client_config.py")
CLIENT_CONFIG_SPEC = importlib.util.spec_from_file_location(
    "openubmc_environment_client_config", CLIENT_CONFIG_PATH
)
if CLIENT_CONFIG_SPEC is None or CLIENT_CONFIG_SPEC.loader is None:
    raise RuntimeError(f"unable to load client configuration module: {CLIENT_CONFIG_PATH}")
client_config = importlib.util.module_from_spec(CLIENT_CONFIG_SPEC)
CLIENT_CONFIG_SPEC.loader.exec_module(client_config)


DEFAULT_REPO_URL = "https://github.com/lihuabai629-star/openubmc-agent-workflow.git"
DEFAULT_REF = "main"
FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
MUTABLE_REFS = frozenset({"head", "main", "master", "develop", "development", "trunk"})
LEGACY_STUDIO_HTTP_URL = "http://localhost:9876/mcp"
KNOWLEDGE_MCP_NAME = "openubmc-kb"
LEGACY_STUDIO_MCP_NAME = "openubmc-studio"
KNOWLEDGE_MCP_VERSION = "1.3.0"
KNOWLEDGE_MCP_INSTALL_SCHEMA = "openubmc-kb.install.v1"
_KNOWLEDGE_DIGEST_DOMAIN = b"openubmc-kb-content-v1\0"
TARGET_RUNTIME_API_VERSION = "openubmc.target-runtime.v1"
TARGET_RUNTIME_MCP_NAME = "openubmc-target-runtime"
TARGET_RUNTIME_INSTALL_SCHEMA = "openubmc-target-runtime.install.v1"
_RUNTIME_DIGEST_DOMAIN = b"openubmc-target-runtime-content-v1\0"
STATE_VERSION = 1
COMMANDS = (
    "install",
    "check",
    "repair",
    "update",
    "rollback",
    "refresh",
    "credentials",
    "uninstall",
)
SkillBundle = tuple[tuple[str, str], ...]


class SkillProfilePolicy(NamedTuple):
    bundle: SkillBundle
    manages_knowledge_mcp: bool


class ResolvedSkillProfile(NamedTuple):
    name: str
    bundle: SkillBundle
    manages_knowledge_mcp: bool


class CheckReadiness(NamedTuple):
    installation_ok: bool
    operational_ready: bool
    release_identity_verified: bool
    evaluation_ready: bool

    def top_level_fields(self) -> dict[str, bool]:
        return {
            "ok": self.installation_ok,
            "operational_ready": self.operational_ready,
            "release_identity_verified": self.release_identity_verified,
            "evaluation_ready": self.evaluation_ready,
        }

    def readiness_fields(self) -> dict[str, bool]:
        return {
            "release_identity": self.release_identity_verified,
            "evaluation": self.evaluation_ready,
        }


class RecordedInstall(NamedTuple):
    source_root: Path
    source_mode: str
    source_commit: str
    resolved_commit: str
    rollback_commit: str
    repo_url: str
    ref: str
    requested_ref: str
    ref_kind: str
    clients: tuple[str, ...]
    profile: ResolvedSkillProfile
    knowledge_url: str
    target: str
    tool_dirs: tuple[str, ...]
    mcp: dict[str, Any]
    runtime_mcp: dict[str, Any]
    links: dict[str, str]
    preserved_skills: tuple[str, ...]
    profiles: tuple[str, ...]
    runtime: dict[str, Any]
    release: dict[str, Any]


class HttpMcpEntry(TypedDict):
    type: Literal["http"]
    url: str


class StdioMcpEntry(TypedDict):
    type: Literal["stdio"]
    command: str
    args: list[str]

# canonical Skill name -> repository-relative directory
SKILL_BUNDLE: SkillBundle = (
    ("openubmc-environment-setup", "openubmc-environment-setup"),
    ("openubmc-debug", "openubmc-debug"),
    ("openubmc-log-analyzer", "openubmc-log-analyzer"),
    ("openubmc-developer", "openubmc-developer"),
    ("openubmc-build", "openubmc-build"),
    ("openubmc-upgrade", "openubmc-upgrade"),
    ("openubmc-live-patch", "openubmc-live-patch"),
    ("openubmc-dt-testing", "testing"),
    ("openubmc-publish", "openubmc-publish"),
    ("openubmc-lua-component", "lua-component"),
    ("openubmc-qemu-testing", "qemu-testing"),
)
DEFAULT_SKILL_PROFILE = "full"
TARGET_RUNTIME_SKILL_PROFILE = "target-runtime"
TARGET_RUNTIME_SKILL_NAMES = frozenset(
    {
        "openubmc-environment-setup",
        "openubmc-debug",
        "openubmc-log-analyzer",
        "openubmc-developer",
        "openubmc-build",
        "openubmc-upgrade",
        "openubmc-live-patch",
    }
)
TARGET_RUNTIME_SKILL_BUNDLE: SkillBundle = tuple(
    item for item in SKILL_BUNDLE if item[0] in TARGET_RUNTIME_SKILL_NAMES
)
SKILL_PROFILES: dict[str, SkillProfilePolicy] = {
    DEFAULT_SKILL_PROFILE: SkillProfilePolicy(
        bundle=SKILL_BUNDLE,
        manages_knowledge_mcp=True,
    ),
    TARGET_RUNTIME_SKILL_PROFILE: SkillProfilePolicy(
        bundle=TARGET_RUNTIME_SKILL_BUNDLE,
        manages_knowledge_mcp=False,
    ),
}

# Compatibility wrappers remain in the repository for explicit path-based use,
# but must not be present in the normal discovery catalog.
RETIRED_SKILL_LINKS: tuple[tuple[str, str], ...] = (
    ("lua-component", "lua-component"),
    ("openubmc-mdb-interface-dev", "mdb-interface-dev"),
    ("mdb-interface-dev", "mdb-interface-dev"),
    ("openubmc-interface-mapping", "interface-mapping"),
    ("interface-mapping", "interface-mapping"),
    ("openubmc-debugging", "openubmc-debugging"),
)

CLIENTS = ("codex",)
LEGACY_CLIENTS = ("claude", "openclaw")
KNOWN_CLIENTS = (*CLIENTS, *LEGACY_CLIENTS)
SUPPORTED_MCP_CLIENTS = ("codex",)
MCP_OWNERSHIP_CLIENTS = ("codex", "claude")
REQUIRED_TOOLS = ("bmcgo", "conan", "git", "python3", "ssh")
CONDITIONAL_TOOLS = {
    "sshpass": (
        "password-based SSH, remote log pulling, and Live Patch require sshpass; "
        "key-based SSH remains available"
    ),
}
RECOMMENDED_TOOLS = {
    "rg": "source evidence search uses a slower fallback when ripgrep is unavailable",
}
CLIENT_EXECUTABLES = {
    "codex": "codex",
}
APT_TOOL_PACKAGES = {
    "git": "git",
    "ssh": "openssh-client",
    "sshpass": "sshpass",
    "rg": "ripgrep",
}
CODEX_NPM_PACKAGE = "@openai/codex"
BMCGO_WHEEL_NAME = "hw_ibmc_bmcgo-0.7.51-py3-none-any.whl"
BMCGO_WHEEL_SHA256 = "d8424a2e8a4549ffd5d574288ed7d9016b91b2ae0d5c2463387102250795ae1e"
CREDENTIAL_KEY_ORDER = (
    "OPENUBMC_SSH_USER",
    "OPENUBMC_SSH_PASSWORD",
    "OPENUBMC_TELNET_USER",
    "OPENUBMC_TELNET_PASSWORD",
    "REDFISH_USERNAME",
    "REDFISH_PASSWORD",
    "OPENUBMC_OS_SSH_USER",
    "OPENUBMC_OS_SSH_PASSWORD",
    "OPENUBMC_OS_SSH_PORT",
)
ALLOWED_CREDENTIAL_KEYS = frozenset(CREDENTIAL_KEY_ORDER)
REQUIRED_CREDENTIAL_KEYS = (
    "OPENUBMC_SSH_USER",
    "OPENUBMC_SSH_PASSWORD",
    "REDFISH_USERNAME",
    "REDFISH_PASSWORD",
    "OPENUBMC_OS_SSH_USER",
    "OPENUBMC_OS_SSH_PASSWORD",
)

MARKER_START = "# >>> openUBMC environment setup >>>"
MARKER_END = "# <<< openUBMC environment setup <<<"
OLD_MARKER_START = "# >>> openUBMC environment >>>"
OLD_MARKER_END = "# <<< openUBMC environment <<<"
LEGACY_CREDENTIALS_START = "# >>> openUBMC debug credentials >>>"
LEGACY_CREDENTIALS_END = "# <<< openUBMC debug credentials <<<"

PROFILE_BLOCK = f'''{MARKER_START}
if [ -r "${{XDG_CONFIG_HOME:-$HOME/.config}}/openubmc/env.sh" ]; then
    . "${{XDG_CONFIG_HOME:-$HOME/.config}}/openubmc/env.sh"
fi
{MARKER_END}
'''


class SetupError(RuntimeError):
    """A configuration error safe to show to the user."""


def http_mcp_entry(url: str) -> HttpMcpEntry:
    return {"type": "http", "url": url}


def stdio_mcp_entry(command: str | Path) -> StdioMcpEntry:
    return {"type": "stdio", "command": str(command), "args": []}


def record_created_entry(record: Mapping[str, object] | None) -> bool:
    return record is not None and record.get("created_entry") is True


def record_created_file(record: Mapping[str, object] | None) -> bool:
    return record is not None and record.get("created_file") is True


def valid_client_ownership_record(record: object) -> bool:
    return (
        isinstance(record, Mapping)
        and isinstance(record.get("created_entry"), bool)
        and isinstance(record.get("created_file"), bool)
    )


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument(
        "--skip-tool-install",
        action="store_true",
        help="do not automatically install missing workflow tools",
    )


def add_source_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", type=Path, help="existing skills repository checkout")
    parser.add_argument("--repo-url", default=DEFAULT_REPO_URL, help="skills Git repository")
    parser.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help="release tag or full commit for a managed checkout",
    )
    parser.add_argument(
        "--source-mode",
        choices=("auto", "linked", "managed"),
        default="auto",
        help="link a local checkout or use an installer-managed clone",
    )


def add_install_options(parser: argparse.ArgumentParser) -> None:
    add_common_options(parser)
    add_source_options(parser)
    parser.add_argument(
        "--clients",
        default="auto",
        help="Codex client selection: auto, codex, or all",
    )
    parser.add_argument("--target", choices=("current", "docker"), default="current")
    parser.add_argument(
        "--skill-profile",
        choices=tuple(SKILL_PROFILES),
        default=None,
        help="Skill link set to manage; existing installs keep their recorded profile",
    )
    parser.add_argument(
        "--preserve-skills",
        default=None,
        help=(
            "comma-separated canonical Skill names whose existing links must be "
            "retained across a source switch; use none to clear the recorded list"
        ),
    )
    parser.add_argument(
        "--kb-url",
        "--studio-url",
        dest="knowledge_url",
        default=None,
        help="knowledge MCP URL; --studio-url remains a compatibility alias",
    )
    parser.add_argument(
        "--kb-config",
        type=Path,
        help="import a private openUBMC KB JSON configuration",
    )
    parser.add_argument("--configure-credentials", action="store_true")
    parser.add_argument("--import-credentials", type=Path)
    parser.add_argument("--skip-credentials", action="store_true")


def new_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_install_options(subparsers.add_parser("install", help="install or refresh configuration"))
    check = subparsers.add_parser("check", help="inspect the installed workflow")
    add_common_options(check)
    check.add_argument("--deep", action="store_true", help="include a full-worktree dirty check")
    for command, help_text in (
        ("repair", "repair configuration without pulling source"),
        ("update", "revalidate an installer-managed immutable release"),
        ("rollback", "restore the previous known-good managed revision"),
        ("refresh", "record and repair a linked source checkout"),
    ):
        child = subparsers.add_parser(command, help=help_text)
        add_common_options(child)
    credentials = subparsers.add_parser("credentials", help="configure private BMC and OS credentials")
    add_common_options(credentials)
    credentials.add_argument("--import-credentials", type=Path)
    credentials.add_argument("--kb", action="store_true", help="configure openUBMC KB OneID credentials")
    credentials.add_argument("--kb-config", type=Path, help="import a private openUBMC KB JSON configuration")
    uninstall = subparsers.add_parser("uninstall", help="remove installer-managed configuration")
    add_common_options(uninstall)
    uninstall.add_argument("--purge-credentials", action="store_true")
    return parser


def legacy_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    for command in ("install", "check", "repair", "update", "rollback", "refresh", "uninstall"):
        actions.add_argument(f"--{command}", action="store_true")
    add_install_options(parser)
    parser.add_argument("--purge-credentials", action="store_true")
    parser.add_argument("--deep", action="store_true")
    return parser


def apply_argument_defaults(args: argparse.Namespace) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "source": None,
        "repo_url": DEFAULT_REPO_URL,
        "ref": DEFAULT_REF,
        "source_mode": "auto",
        "clients": "auto",
        "target": "current",
        "skill_profile": None,
        "preserve_skills": None,
        "knowledge_url": None,
        "kb_config": None,
        "kb": False,
        "configure_credentials": False,
        "import_credentials": None,
        "skip_credentials": False,
        "purge_credentials": False,
        "non_interactive": False,
        "skip_tool_install": False,
        "dry_run": False,
        "json": False,
        "deep": False,
    }
    for name, value in defaults.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    if args.command == "credentials":
        args.configure_credentials = True
    return args


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in COMMANDS:
        parser = new_cli_parser()
        args = parser.parse_args(raw)
        args.legacy_cli = False
    else:
        parser = legacy_cli_parser()
        args = parser.parse_args(raw)
        args.command = next(
            (command for command in COMMANDS if getattr(args, command, False)),
            "install",
        )
        args.legacy_cli = True
    args = apply_argument_defaults(args)
    args.ref_explicit = any(
        argument == "--ref" or argument.startswith("--ref=") for argument in raw
    )
    args.repo_url_explicit = any(
        argument == "--repo-url" or argument.startswith("--repo-url=")
        for argument in raw
    )
    if args.import_credentials and args.skip_credentials:
        parser.error("--import-credentials and --skip-credentials are mutually exclusive")
    return args


def config_root(home: Path) -> Path:
    override = os.environ.get("XDG_CONFIG_HOME", "")
    if override:
        path = Path(override).expanduser()
        return path if path.is_absolute() else path.absolute()
    return home / ".config"


def openubmc_config_dir(home: Path) -> Path:
    return config_root(home) / "openubmc"


def state_path(home: Path) -> Path:
    return openubmc_config_dir(home) / "environment-state.json"


def credentials_path(home: Path) -> Path:
    return openubmc_config_dir(home) / "credentials.env"


def managed_source_dir(home: Path) -> Path:
    return home / ".local" / "share" / "openubmc" / "skills"


def runtime_install_root(home: Path) -> Path:
    return home / ".local" / "share" / "openubmc" / "target-runtime"


def runtime_package_path(home: Path) -> Path:
    return runtime_install_root(home) / "openubmc_target_runtime"


def runtime_launcher_path(home: Path) -> Path:
    return runtime_install_root(home) / "openubmc-target-runtime-mcp"


def runtime_manifest_path(home: Path) -> Path:
    return runtime_install_root(home) / "manifest.json"


def knowledge_install_root(home: Path) -> Path:
    return home / ".local" / "share" / "openubmc" / "kb-mcp"


def knowledge_launcher_path(home: Path) -> Path:
    return knowledge_install_root(home) / "openubmc-kb-mcp"


def knowledge_manifest_path(home: Path) -> Path:
    return knowledge_install_root(home) / "manifest.json"


def knowledge_config_path(home: Path) -> Path:
    return openubmc_config_dir(home) / "kb-mcp.json"


def client_skills_dir(home: Path, client: str) -> Path:
    if client == "codex":
        return home / ".agents" / "skills"
    if client == "claude":
        return home / ".claude" / "skills"
    if client == "openclaw":
        return home / ".openclaw" / "skills"
    raise SetupError(f"unsupported client: {client}")


def detected_clients(home: Path) -> list[str]:
    del home
    return ["codex"]


def parse_clients(value: str, home: Path) -> list[str]:
    if value == "auto":
        return detected_clients(home)
    if value == "all":
        return list(CLIENTS)
    clients = []
    for item in value.split(","):
        client = item.strip().lower()
        if not client:
            continue
        if client in LEGACY_CLIENTS:
            raise SetupError(
                f"only Codex is supported; replace --clients {value} with "
                "--clients codex"
            )
        if client not in CLIENTS:
            raise SetupError(f"unsupported client: {client}")
        if client not in clients:
            clients.append(client)
    if "codex" not in clients:
        clients.insert(0, "codex")
    return clients


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as error:
        raise SetupError(f"required command is unavailable: {command[0]}") from error


def git_output(root: Path, *arguments: str) -> str:
    result = run_command(["git", "-C", str(root), *arguments])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise SetupError(detail)
    return result.stdout.strip()


def git_commit(root: Path) -> str:
    try:
        return git_output(root, "rev-parse", "HEAD")
    except SetupError:
        return "unversioned"


def resolve_skill_profile(profile: str) -> ResolvedSkillProfile:
    try:
        policy = SKILL_PROFILES[profile]
    except KeyError as error:
        raise SetupError(f"unsupported Skill profile: {profile}") from error
    return ResolvedSkillProfile(
        name=profile,
        bundle=policy.bundle,
        manages_knowledge_mcp=policy.manages_knowledge_mcp,
    )


def parse_preserved_skills(
    value: object,
    bundle: Iterable[tuple[str, str]],
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, str):
        raise SetupError("preserve_skills must be a comma-separated string")
    names = tuple(
        dict.fromkeys(
            item.strip()
            for item in value.split(",")
            if item.strip()
        )
    )
    if not names or names == ("none",):
        return ()
    if "none" in names:
        raise SetupError("preserve_skills cannot mix none with Skill names")
    available = {canonical for canonical, _relative in bundle}
    unknown = sorted(set(names) - available)
    if unknown:
        raise SetupError(
            "unknown preserved Skill name(s): " + ", ".join(unknown)
        )
    return names


def skill_profile_from_state(state: Mapping[str, object]) -> ResolvedSkillProfile:
    value = state.get("skill_profile", DEFAULT_SKILL_PROFILE)
    if not isinstance(value, str) or value not in SKILL_PROFILES:
        raise SetupError(f"unsupported Skill profile in installer state: {value!r}")
    return resolve_skill_profile(value)


def materialize_skill_bundle(
    bundle: Iterable[tuple[str, str]],
) -> SkillBundle:
    resolved = tuple(bundle)
    if not resolved:
        raise SetupError("Skill bundle must not be empty")
    return resolved


def bundle_git_paths(
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
) -> tuple[str, ...]:
    resolved = materialize_skill_bundle(bundle)
    paths = [relative for _, relative in resolved]
    paths.append("openubmc-target-runtime")
    if resolved == SKILL_BUNDLE:
        paths.append("openubmc-kb-mcp")
    return tuple(dict.fromkeys(paths))


def git_dirty(root: Path, *, paths: Iterable[str] | None = None) -> bool:
    scoped_paths = tuple(paths or ())
    if not scoped_paths:
        try:
            return bool(git_output(root, "status", "--porcelain"))
        except SetupError:
            return False
    tracked = run_command(
        ["git", "-C", str(root), "diff-index", "--quiet", "HEAD", "--", *scoped_paths]
    )
    if tracked.returncode == 1:
        return True
    if tracked.returncode != 0:
        return False
    untracked = run_command(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            *scoped_paths,
        ]
    )
    return untracked.returncode == 0 and bool(untracked.stdout.strip())


def normalized_repo_url(value: str) -> str:
    return value.rstrip("/").removesuffix(".git")


def github_repo_slug(repo_url: str) -> str | None:
    normalized = normalized_repo_url(repo_url.strip())
    if normalized.startswith("git@github.com:"):
        candidate = normalized.removeprefix("git@github.com:")
    else:
        parsed = urllib.parse.urlsplit(normalized)
        if parsed.hostname != "github.com":
            return None
        candidate = parsed.path.lstrip("/")
    parts = candidate.split("/")
    if len(parts) != 2 or not all(parts):
        return None
    return "/".join(parts)


def immutable_release_remediation_command(
    *,
    repo_url: str,
    source_mode: str,
    requested_ref: str,
    ref_kind: str,
) -> str:
    immutable_ref = (
        requested_ref
        if source_mode == "managed" and ref_kind in {"tag", "commit"}
        else ""
    )
    repo_slug = github_repo_slug(repo_url)
    if immutable_ref:
        ref_assignment = f"WORKFLOW_REF={shlex.quote(immutable_ref)}"
    elif repo_slug is not None:
        discovery = (
            "import json,os,urllib.request;"
            "base=os.environ.get('GITHUB_API_URL','https://api.github.com').rstrip('/');"
            f"url=base+'/repos/{repo_slug}/releases/latest';"
            "token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN');"
            "headers={'Accept':'application/vnd.github+json',"
            "'User-Agent':'openubmc-agent-workflow-installer',"
            "'X-GitHub-Api-Version':'2022-11-28'};"
            "headers.update({'Authorization':'Bearer '+token} if token else {});"
            "request=urllib.request.Request(url,headers=headers);"
            "print(json.load(urllib.request.urlopen(request,timeout=30))['tag_name'])"
        )
        ref_assignment = (
            f'WORKFLOW_REF="$(python3 -c {shlex.quote(discovery)})"'
        )
    else:
        quoted_repo_url = shlex.quote(repo_url)
        ref_assignment = (
            'WORKFLOW_REF="$(git ls-remote --tags --refs '
            f"{quoted_repo_url} "
            "| awk '$2 ~ /^refs\\/tags\\/v?[0-9]+\\.[0-9]+\\.[0-9]+$/ "
            "{sub(\"refs/tags/\",\"\",$2); print $2}' "
            '| sort -V | tail -n 1)"'
        )
    quoted_repo_url = shlex.quote(repo_url)
    return (
        f"(set -e; {ref_assignment}; "
        'test -n "$WORKFLOW_REF"; WORKFLOW_TMP="$(mktemp -d)"; '
        'trap \'rm -rf -- "$WORKFLOW_TMP"\' EXIT; '
        f"git clone --quiet --filter=blob:none --no-checkout {quoted_repo_url} "
        '"$WORKFLOW_TMP"; '
        'git -C "$WORKFLOW_TMP" fetch --quiet --depth=1 origin "$WORKFLOW_REF"; '
        'git -C "$WORKFLOW_TMP" checkout --quiet --detach FETCH_HEAD; '
        'python3 "$WORKFLOW_TMP/openubmc-target-runtime/openubmc_target_runtime/'
        'release.py" verify --root "$WORKFLOW_TMP" >/dev/null; '
        'python3 "$WORKFLOW_TMP/openubmc-environment-setup/scripts/'
        'install_environment.py" install --source-mode managed '
        f'--repo-url {quoted_repo_url} --ref "$WORKFLOW_REF" --non-interactive)'
    )


def github_token() -> str | None:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            return token
    return None


def git_auth_environment(repo_url: str) -> dict[str, str] | None:
    token = github_token()
    if token is None or normalized_repo_url(repo_url) != normalized_repo_url(DEFAULT_REPO_URL):
        return None
    environment = dict(os.environ)
    count_text = environment.get("GIT_CONFIG_COUNT", "0")
    if not count_text.isdecimal():
        raise SetupError("GIT_CONFIG_COUNT must be a non-negative integer")
    count = int(count_text)
    basic_token = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    environment["GIT_CONFIG_COUNT"] = str(count + 1)
    environment[f"GIT_CONFIG_KEY_{count}"] = "http.https://github.com/.extraheader"
    environment[f"GIT_CONFIG_VALUE_{count}"] = f"Authorization: Basic {basic_token}"
    return environment


def read_skill_name(skill_file: Path) -> str:
    text = skill_file.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise SetupError(f"missing YAML frontmatter: {skill_file}")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise SetupError(f"unterminated YAML frontmatter: {skill_file}")
    for line in text[4:end].splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "name":
            return value.strip().strip("\"'")
    raise SetupError(f"missing Skill name: {skill_file}")


def validate_source(
    root: Path,
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
) -> Path:
    resolved_bundle = materialize_skill_bundle(bundle)
    root = root.expanduser().absolute()
    if not root.is_dir():
        raise SetupError(f"skills source does not exist: {root}")
    errors = []
    for canonical, relative in resolved_bundle:
        skill_file = root / relative / "SKILL.md"
        if not skill_file.is_file():
            errors.append(f"missing {relative}/SKILL.md")
            continue
        actual = read_skill_name(skill_file)
        if actual != canonical:
            errors.append(f"{relative}/SKILL.md declares {actual!r}, expected {canonical!r}")
    if errors:
        raise SetupError("invalid skills source: " + "; ".join(errors))
    return root


def validate_release_source(root: Path, dry_run: bool) -> dict[str, object]:
    validator = root / "scripts" / "validate_workflow.py"
    if not validator.is_file():
        raise SetupError(f"release validator is missing: {validator}")
    if dry_run:
        print(f"would validate release contract in {root}")
        return release_identity(root, source_mode="managed", dry_run=True)
    result = run_command(
        [sys.executable, str(validator), "--release-contract-only"],
        cwd=root,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SetupError(detail or "release contract validation failed")
    return release_identity(root, source_mode="managed", dry_run=False)


def _release_version(value: object) -> tuple[int, int, int]:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", str(value).strip())
    if match is None:
        raise SetupError(f"workflow release version is invalid: {value!r}")
    return tuple(int(part) for part in match.groups())


def workflow_release_metadata(
    root: Path,
    *,
    required: bool,
) -> dict[str, object] | None:
    workflow = root / "workflow.json"
    try:
        document = json.loads(workflow.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if not required:
            return None
        raise SetupError(f"workflow release metadata is unavailable: {workflow}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError(f"workflow release metadata is unavailable: {workflow}") from exc
    if not isinstance(document, Mapping):
        raise SetupError("workflow release metadata must be an object")
    _release_version(document.get("version", ""))
    return dict(document)


def release_identity(
    root: Path,
    *,
    source_mode: Literal["managed", "linked"],
    dry_run: bool,
) -> dict[str, object]:
    if source_mode not in {"managed", "linked"}:
        raise SetupError(f"unsupported source mode for release identity: {source_mode}")
    managed = source_mode == "managed"
    try:
        workflow = workflow_release_metadata(root, required=managed)
    except SetupError as error:
        if managed:
            raise
        return {
            "schema": "linked-development-source",
            "immutable": False,
            "validation_error": str(error),
        }
    if workflow is None:
        return {
            "schema": "linked-development-source",
            "immutable": False,
        }

    release_version = str(workflow.get("version", ""))
    lock_path = root / "release-lock.json"
    if not lock_path.is_file():
        if managed and _release_version(release_version) >= (1, 2, 0):
            raise SetupError(f"immutable release lock is missing: {lock_path}")
        return {
            "schema": (
                "legacy-release-without-lock"
                if managed
                else "linked-development-source"
            ),
            "release_version": release_version,
            "immutable": False,
        }
    verifier = (
        root
        / "openubmc-target-runtime"
        / "openubmc_target_runtime"
        / "release.py"
    )
    if not verifier.is_file():
        raise SetupError(f"release lock verifier is missing: {verifier}")
    if dry_run:
        print(f"would verify immutable release lock in {root}")
        return {
            "schema": "planned-release-lock",
            "release_version": release_version,
            "immutable": managed,
        }
    result = run_command(
        [sys.executable, str(verifier), "verify", "--root", str(root)],
        cwd=root,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        error = SetupError(detail or "immutable release lock validation failed")
        if managed:
            raise error
        return {
            "schema": "linked-development-source",
            "release_version": release_version,
            "immutable": False,
            "validation_error": str(error),
        }
    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SetupError("release lock verifier returned invalid JSON") from exc
    if not isinstance(identity, dict):
        raise SetupError("release lock verifier returned an invalid identity")
    if managed:
        identity["immutable"] = True
        return identity
    return {
        "schema": "linked-development-source",
        "release_version": release_version,
        "immutable": False,
        "verified_release_lock": identity,
    }


def release_ref_kind(value: object) -> Literal["tag", "commit"]:
    candidate = str(value).strip() if value is not None else ""
    lowered = candidate.lower()
    if FULL_COMMIT.fullmatch(candidate):
        return "commit"
    if (
        not candidate
        or lowered in MUTABLE_REFS
        or lowered.startswith("refs/heads/")
        or candidate.startswith("-")
        or candidate.endswith(("/", ".", ".lock"))
        or ".." in candidate
        or "@{" in candidate
        or any(character.isspace() or character in "~^:?*[\\" for character in candidate)
    ):
        raise SetupError("--ref must name an explicit release tag or full commit")
    return "tag"


def iter_runtime_source_files(package_root: Path):
    root = package_root.resolve()
    if not root.is_dir() or not (root / "__init__.py").is_file():
        raise SetupError(f"canonical Target Runtime is unavailable: {root}")
    found = False
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise SetupError(
                f"Target Runtime source must not contain symbolic links: {relative}"
            )
        if path.is_file() and path.suffix in {".pyc", ".pyo", ".so", ".pyd", ".dll"}:
            raise SetupError(f"Target Runtime contains an unbound executable: {relative}")
        if path.suffix != ".py":
            continue
        if path.is_file():
            found = True
            yield path, relative
    if not found:
        raise SetupError(f"Target Runtime package contains no Python sources: {root}")


def runtime_content_digest(package_root: Path) -> str:
    digest = hashlib.sha256(_RUNTIME_DIGEST_DOMAIN)
    for path, relative in iter_runtime_source_files(package_root):
        content = path.read_bytes()
        encoded_path = relative.as_posix().encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def file_content_digest(path: Path, *, domain: bytes = _RUNTIME_DIGEST_DOMAIN) -> str:
    """Return a stable digest for one release-owned source file."""
    if path.is_symlink() or not path.is_file():
        raise SetupError(f"release source file is unavailable: {path}")
    digest = hashlib.sha256(domain)
    relative = path.name.encode("utf-8")
    content = path.read_bytes()
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
    return f"sha256:{digest.hexdigest()}"


_COMPOSITION_ROOTS = (
    "openubmc-target-runtime", *(path for _name, path in SKILL_BUNDLE),
)
_COMPOSITION_IGNORED = frozenset({"__pycache__", "tests", "node_modules", ".git"})


def runtime_composition_files(source: Path) -> dict[str, str]:
    """Bind the Python loaders, domain implementations and Skill instructions."""
    files: dict[str, str] = {}
    for name in _COMPOSITION_ROOTS:
        root = source / name
        if root.is_symlink():
            raise SetupError(f"Runtime composition contains a symlink: {name}")
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(source)
            if _COMPOSITION_IGNORED.intersection(relative.parts):
                continue
            if path.is_symlink():
                raise SetupError(f"Runtime composition contains a symlink: {relative}")
            # Bind every release-owned file. Python may load sourceless bytecode
            # or an ABI extension before a same-named source module.
            if path.is_file():
                files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def read_runtime_api_version(package_root: Path) -> str:
    contracts = package_root.resolve() / "contracts.py"
    try:
        tree = ast.parse(contracts.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError) as error:
        raise SetupError(f"Target Runtime API metadata is unavailable: {contracts}") from error
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(
            isinstance(target, ast.Name) and target.id == "RUNTIME_API_VERSION"
            for target in targets
        ):
            return value.value
    raise SetupError(f"Target Runtime API constant is missing: {contracts}")


def build_runtime_plan(
    home: Path,
    source: Path,
    *,
    source_commit: str = "unknown-source-commit",
    allow_missing_source: bool = False,
) -> dict[str, str]:
    source_package = source / "openubmc-target-runtime" / "openubmc_target_runtime"
    mcp_entrypoint = source / "openubmc-debug" / "scripts" / "target_runtime_mcp.py"
    if allow_missing_source and not source.exists():
        api_version = TARGET_RUNTIME_API_VERSION
        content_digest = "planned"
    else:
        api_version = read_runtime_api_version(source_package)
        if api_version != TARGET_RUNTIME_API_VERSION:
            raise SetupError(
                "canonical Target Runtime API mismatch: "
                f"expected {TARGET_RUNTIME_API_VERSION}, found {api_version}"
            )
        content_digest = runtime_content_digest(source_package)
        if not mcp_entrypoint.is_file():
            raise SetupError(f"Target Runtime MCP entrypoint is missing: {mcp_entrypoint}")
    return {
        "schema_version": TARGET_RUNTIME_INSTALL_SCHEMA,
        "api_version": api_version,
        "content_digest": content_digest,
        "source_commit": str(source_commit).strip() or "unknown-source-commit",
        "source_package_path": str(source_package),
        "package_path": str(runtime_package_path(home)),
        "launcher_path": str(runtime_launcher_path(home)),
        "manifest_path": str(runtime_manifest_path(home)),
        "mcp_entrypoint": str(mcp_entrypoint),
        "mcp_entrypoint_digest": (
            "planned"
            if allow_missing_source and not source.exists()
            else file_content_digest(mcp_entrypoint, domain=b"openubmc-mcp-entrypoint-v1" + bytes([0]))
        ),
        "composition_source": str(source),
        "composition_files": runtime_composition_files(source),
    }


def render_runtime_launcher(plan: dict[str, str]) -> str:
    package = json.dumps(plan["package_path"])
    entrypoint = json.dumps(plan["mcp_entrypoint"])
    expected_api = json.dumps(plan["api_version"])
    expected_digest = json.dumps(plan["content_digest"])
    source_commit = json.dumps(plan.get("source_commit", "unknown-source-commit"))
    return f'''#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import runpy
import sys
import tempfile

PACKAGE_ROOT = Path({package})
MCP_ENTRYPOINT = Path({entrypoint})
EXPECTED_API = {expected_api}
EXPECTED_DIGEST = {expected_digest}
EXPECTED_ENTRYPOINT_DIGEST = {json.dumps(plan.get("mcp_entrypoint_digest", "planned"))}
COMPOSITION_SOURCE = Path({json.dumps(plan.get("composition_source", ""))})
COMPOSITION_FILES = {repr(dict(sorted(plan.get("composition_files", {}).items())))}
COMPOSITION_ROOTS = {repr(_COMPOSITION_ROOTS)}
SOURCE_COMMIT = {source_commit}
DIGEST_DOMAIN = b"openubmc-target-runtime-content-v1\\0"
RUNTIME_CONTENT = {{}}
ENTRYPOINT_CONTENT = b""


def fail(reason: str) -> None:
    raise SystemExit(
        "Target Runtime installation validation failed before remote execution: "
        + reason
        + "; run openubmc-environment-setup repair"
    )


def runtime_api() -> str:
    contracts = PACKAGE_ROOT / "contracts.py"
    try:
        tree = ast.parse(contracts.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        fail("Runtime API metadata is missing or invalid")
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == "RUNTIME_API_VERSION" for target in targets):
            return value.value
    fail("Runtime API constant is missing")


def runtime_digest() -> str:
    if not PACKAGE_ROOT.is_dir() or not (PACKAGE_ROOT / "__init__.py").is_file():
        fail("Runtime package is missing")
    digest = hashlib.sha256(DIGEST_DOMAIN)
    for path in PACKAGE_ROOT.rglob("*"):
        relative = path.relative_to(PACKAGE_ROOT)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            fail("Runtime package contains a symbolic link")
        if path.is_file() and path.suffix in {{".pyc", ".pyo", ".so", ".pyd", ".dll"}}:
            fail("Runtime package contains an unbound executable: " + str(relative))
    files = [
        path for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if "__pycache__" not in path.relative_to(PACKAGE_ROOT).parts
    ]
    if not files:
        fail("Runtime package contains no Python sources")
    for path in files:
        if path.is_symlink() or not path.is_file():
            fail("Runtime package contains an invalid source path")
        relative = path.relative_to(PACKAGE_ROOT).as_posix().encode("utf-8")
        content = path.read_bytes()
        RUNTIME_CONTENT[path.relative_to(PACKAGE_ROOT).as_posix()] = content
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def entrypoint_digest() -> str:
    global ENTRYPOINT_CONTENT
    if MCP_ENTRYPOINT.is_symlink() or not MCP_ENTRYPOINT.is_file():
        fail("MCP entrypoint is missing")
    digest = hashlib.sha256(b"openubmc-mcp-entrypoint-v1\\0")
    relative = MCP_ENTRYPOINT.name.encode("utf-8")
    content = MCP_ENTRYPOINT.read_bytes()
    ENTRYPOINT_CONTENT = content
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
    return "sha256:" + digest.hexdigest()


if runtime_api() != EXPECTED_API:
    fail("Runtime API mismatch")
if runtime_digest() != EXPECTED_DIGEST:
    fail("Runtime content digest mismatch")
actual_entrypoint_digest = entrypoint_digest()
if EXPECTED_ENTRYPOINT_DIGEST != "planned" and actual_entrypoint_digest != EXPECTED_ENTRYPOINT_DIGEST:
    fail("MCP entrypoint content digest mismatch")
actual_composition = {{}}
composition_content = {{}}
for name in COMPOSITION_ROOTS:
    root = COMPOSITION_SOURCE / name
    if root.is_symlink():
        fail("Runtime composition contains a symlink: " + name)
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(COMPOSITION_SOURCE)
        if {{"__pycache__", "tests", "node_modules", ".git"}}.intersection(relative.parts):
            continue
        if path.is_symlink():
            fail("Runtime composition contains a symlink: " + str(relative))
        if path.is_file():
            content = path.read_bytes()
            composition_content[relative.as_posix()] = content
            actual_composition[relative.as_posix()] = hashlib.sha256(content).hexdigest()
if actual_composition != COMPOSITION_FILES:
    changed = sorted(key for key in set(actual_composition) | set(COMPOSITION_FILES)
                     if actual_composition.get(key) != COMPOSITION_FILES.get(key))
    fail("Runtime composition mismatch: " + ", ".join(changed[:8]))

# Execute only the exact bytes that passed the checks above. Helpers loaded
# later by path or subprocess must use the same snapshot as the MCP entrypoint.
# Re-reading the original paths after validation would reopen a drift window.
_composition_snapshot = tempfile.TemporaryDirectory(prefix="openubmc-runtime-composition-")
snapshot_root = Path(_composition_snapshot.name)
for relative, content in composition_content.items():
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o500)
snapshot_package = snapshot_root / "installed-runtime" / "openubmc_target_runtime"
for relative, content in RUNTIME_CONTENT.items():
    destination = snapshot_package / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o400)
try:
    entrypoint_relative = MCP_ENTRYPOINT.relative_to(COMPOSITION_SOURCE)
except ValueError:
    entrypoint_relative = Path("entrypoint") / MCP_ENTRYPOINT.name
snapshot_entrypoint = snapshot_root / entrypoint_relative
snapshot_entrypoint.parent.mkdir(parents=True, exist_ok=True)
if snapshot_entrypoint.exists():
    if snapshot_entrypoint.read_bytes() != ENTRYPOINT_CONTENT:
        fail("MCP entrypoint changed during composition validation")
else:
    snapshot_entrypoint.write_bytes(ENTRYPOINT_CONTENT)
snapshot_entrypoint.chmod(0o400)
PACKAGE_ROOT = snapshot_package
MCP_ENTRYPOINT = snapshot_entrypoint

# Never import stale sourceless bytecode from a release source tree.
sys.dont_write_bytecode = True
_fresh_pycache_root = tempfile.TemporaryDirectory(prefix="openubmc-runtime-pycache-")
sys.pycache_prefix = _fresh_pycache_root.name

os.environ["OPENUBMC_MCP_SOURCE_COMMIT"] = SOURCE_COMMIT

config_root = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
credentials = config_root / "openubmc" / "credentials.env"
if credentials.is_file():
    os.environ.setdefault("OPENUBMC_CREDENTIALS_FILE", str(credentials))
sys.path.insert(0, str(PACKAGE_ROOT.parent))
sys.path.insert(0, str(MCP_ENTRYPOINT.parent))
runpy.run_path(str(MCP_ENTRYPOINT), run_name="__main__")
'''


def deploy_runtime(plan: dict[str, str], dry_run: bool) -> dict[str, str]:
    source_package = Path(plan["source_package_path"])
    package = Path(plan["package_path"])
    launcher = Path(plan["launcher_path"])
    manifest = Path(plan["manifest_path"])
    if dry_run:
        print(f"would deploy Target Runtime to {package}")
        print(f"would write Target Runtime MCP launcher {launcher}")
        return dict(plan)

    root = package.parent
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise SetupError(f"Target Runtime install root must be a real directory: {root}")
    if package.is_symlink() or (package.exists() and not package.is_dir()):
        raise SetupError(f"Target Runtime package path must be a real directory: {package}")
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    staged_root = Path(tempfile.mkdtemp(prefix=".runtime-", dir=root))
    staged_package = staged_root / package.name
    try:
        for source_file, relative in iter_runtime_source_files(source_package):
            destination = staged_package / relative
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)
        staged_digest = runtime_content_digest(staged_package)
        if staged_digest != plan["content_digest"]:
            raise SetupError("copied Target Runtime content digest changed during install")
        if package.exists():
            shutil.rmtree(package)
        os.replace(staged_package, package)
    finally:
        shutil.rmtree(staged_root, ignore_errors=True)

    atomic_write(
        manifest,
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    atomic_write(launcher, render_runtime_launcher(plan), 0o755)
    return dict(plan)


def iter_knowledge_source_files(root: Path):
    package_root = root.resolve()
    required = (package_root / "package.json", package_root / "package-lock.json")
    if not all(path.is_file() for path in required) or not (package_root / "src/server.js").is_file():
        raise SetupError(f"canonical openUBMC KB MCP is unavailable: {package_root}")
    paths = [*required, *sorted((package_root / "src").rglob("*.js"))]
    for path in paths:
        relative = path.relative_to(package_root)
        if path.is_symlink() or not path.is_file():
            raise SetupError(f"openUBMC KB MCP contains an invalid source path: {relative}")
        yield path, relative


def knowledge_content_digest(root: Path) -> str:
    digest = hashlib.sha256(_KNOWLEDGE_DIGEST_DOMAIN)
    for path, relative in iter_knowledge_source_files(root):
        content = path.read_bytes()
        encoded_path = relative.as_posix().encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def node_major(node: Path | str) -> int:
    result = run_command([str(node), "--version"])
    if result.returncode != 0:
        return 0
    match = re.fullmatch(r"v?(\d+)(?:\.\d+){1,2}", result.stdout.strip())
    return int(match.group(1)) if match else 0


def resolve_node(home: Path, tool_dirs: Iterable[str]) -> Path | None:
    candidates = [home / ".local" / "bin" / "node"]
    discovered = shutil.which("node", path=tool_search_path(tool_dirs))
    if discovered:
        candidates.append(Path(discovered))
    return next((path for path in candidates if path.is_file() and os.access(path, os.X_OK)), None)


def install_knowledge_dependencies(
    home: Path,
    source: Path,
    tool_dirs: Iterable[str],
    *,
    dry_run: bool,
) -> Path:
    package_root = source / "openubmc-kb-mcp"
    if dry_run and not source.exists():
        print("would install openUBMC KB MCP Node.js dependencies")
        return home / ".local" / "bin" / "node"
    tuple(iter_knowledge_source_files(package_root))
    node = resolve_node(home, tool_dirs)
    if node is None:
        raise SetupError("Node.js is unavailable after dependency installation")
    if node_major(node) < 20:
        npm = shutil.which("npm", path=tool_search_path(tool_dirs))
        if not npm:
            raise SetupError("Node.js 20 or newer is required and npm is unavailable")
        if dry_run:
            print(f"would install Node.js 20 under {home / '.local'}")
            return home / ".local" / "bin" / "node"
        command = [
            npm,
            "install",
            "--global",
            "--prefix",
            str(home / ".local"),
            "node@20",
        ]
        result = run_command(command, env={**os.environ, "HOME": str(home)})
        if result.returncode != 0:
            raise command_error(command, result)
        node = resolve_node(home, tool_dirs)
        if node is None or node_major(node) < 20:
            raise SetupError("automatic Node.js 20 installation did not produce a usable runtime")
        print(f"installed Node.js 20 under {home / '.local'}")
    dependency = package_root / "node_modules" / "@modelcontextprotocol" / "sdk" / "package.json"
    if dependency.is_file():
        return node
    if dry_run:
        print(f"would install openUBMC KB MCP dependencies in {package_root}")
        return node
    npm = shutil.which("npm", path=tool_search_path(tool_dirs))
    if not npm:
        raise SetupError("npm is unavailable after dependency installation")
    command = [npm, "ci", "--omit=dev", "--no-audit", "--no-fund"]
    result = run_command(command, cwd=package_root, env={**os.environ, "HOME": str(home)})
    if result.returncode != 0:
        raise command_error(command, result)
    if not dependency.is_file():
        raise SetupError("openUBMC KB MCP dependency installation is incomplete")
    print("installed openUBMC KB MCP dependencies")
    return node


def build_knowledge_plan(
    home: Path,
    source: Path,
    node: Path,
    *,
    source_commit: str = "unknown-source-commit",
    allow_missing_source: bool = False,
) -> dict[str, str]:
    package_root = source / "openubmc-kb-mcp"
    digest = "planned" if allow_missing_source and not source.exists() else knowledge_content_digest(package_root)
    return {
        "schema_version": KNOWLEDGE_MCP_INSTALL_SCHEMA,
        "version": KNOWLEDGE_MCP_VERSION,
        "content_digest": digest,
        "source_commit": str(source_commit).strip() or "unknown-source-commit",
        "source_path": str(package_root),
        "server_path": str(package_root / "src" / "server.js"),
        "node_path": str(node),
        "config_path": str(knowledge_config_path(home)),
        "launcher_path": str(knowledge_launcher_path(home)),
        "manifest_path": str(knowledge_manifest_path(home)),
    }


def render_knowledge_launcher(plan: Mapping[str, str]) -> str:
    source = json.dumps(plan["source_path"])
    server = json.dumps(plan["server_path"])
    node = json.dumps(plan["node_path"])
    config = json.dumps(plan["config_path"])
    expected_digest = json.dumps(plan["content_digest"])
    source_commit = json.dumps(plan.get("source_commit", "unknown-source-commit"))
    return f'''#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
from pathlib import Path

SOURCE_ROOT = Path({source})
SERVER = Path({server})
NODE = Path({node})
CONFIG = Path({config})
EXPECTED_DIGEST = {expected_digest}
SOURCE_COMMIT = {source_commit}
DIGEST_DOMAIN = b"openubmc-kb-content-v1\\0"


def fail(reason: str) -> None:
    raise SystemExit(
        "openUBMC KB MCP installation validation failed: "
        + reason
        + "; run openubmc-environment-setup repair"
    )


files = [SOURCE_ROOT / "package.json", SOURCE_ROOT / "package-lock.json", *sorted((SOURCE_ROOT / "src").rglob("*.js"))]
if not files or any(path.is_symlink() or not path.is_file() for path in files):
    fail("source files are missing or invalid")
digest = hashlib.sha256(DIGEST_DOMAIN)
for path in files:
    relative = path.relative_to(SOURCE_ROOT).as_posix().encode("utf-8")
    content = path.read_bytes()
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
if "sha256:" + digest.hexdigest() != EXPECTED_DIGEST:
    fail("content digest mismatch")
if not NODE.is_file() or not os.access(NODE, os.X_OK):
    fail("Node.js runtime is missing")
os.environ["OPENUBMC_MCP_SOURCE_COMMIT"] = SOURCE_COMMIT
os.environ.setdefault("OPENUBMC_KB_CONFIG", str(CONFIG))
os.execv(str(NODE), [str(NODE), str(SERVER), "--config", str(CONFIG)])
'''


def deploy_knowledge_mcp(plan: dict[str, str], dry_run: bool) -> dict[str, str]:
    launcher = Path(plan["launcher_path"])
    manifest = Path(plan["manifest_path"])
    if dry_run:
        print(f"would write openUBMC KB MCP launcher {launcher}")
        return dict(plan)
    launcher.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(
        manifest,
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    atomic_write(launcher, render_knowledge_launcher(plan), 0o755)
    return dict(plan)


def default_knowledge_config() -> dict[str, object]:
    return {"username": "", "password": ""}


def ensure_knowledge_config(home: Path, source: Path | None, dry_run: bool) -> str:
    destination = knowledge_config_path(home)
    configured_source = source
    if configured_source is None:
        environment_path = os.environ.get("OPENUBMC_KB_CONFIG", "").strip()
        configured_source = Path(environment_path).expanduser() if environment_path else None
    if configured_source is not None:
        configured_source = configured_source.expanduser().absolute()
        if configured_source.is_symlink() or not configured_source.is_file():
            raise SetupError(f"openUBMC KB configuration must be a regular file: {configured_source}")
        try:
            document = json.loads(configured_source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SetupError("openUBMC KB configuration must contain valid JSON") from error
        if not isinstance(document, dict):
            raise SetupError("openUBMC KB configuration must be a JSON object")
        if dry_run:
            print(f"would import openUBMC KB configuration to {destination}")
        else:
            atomic_write(
                destination,
                json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                0o600,
            )
        return "imported"
    if destination.is_file() and not destination.is_symlink():
        if not dry_run and stat.S_IMODE(destination.stat().st_mode) != 0o600:
            os.chmod(destination, 0o600)
        return "preserved"
    if destination.exists():
        raise SetupError(f"openUBMC KB configuration path is not a regular file: {destination}")
    if dry_run:
        print(f"would create openUBMC KB configuration {destination}")
    else:
        atomic_write(
            destination,
            json.dumps(default_knowledge_config(), ensure_ascii=False, indent=2) + "\n",
            0o600,
        )
    return "created"


def local_repository_from_script(
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
) -> Path | None:
    candidate = Path(__file__).resolve().parents[2]
    try:
        return validate_source(candidate, bundle)
    except SetupError:
        return None


def fetch_immutable_release(root: Path, ref: str) -> tuple[Literal["tag", "commit"], str]:
    ref_kind = release_ref_kind(ref)
    fetch_ref = ref if ref_kind == "commit" else f"refs/tags/{ref}"
    remote = git_output(root, "remote", "get-url", "origin")
    fetch_args = [
        "git",
        "-C",
        str(root),
        "fetch",
        "--no-tags",
    ]
    if (root / ".git" / "shallow").is_file():
        fetch_args.append("--unshallow")
    fetch_args.extend(("origin", fetch_ref))
    fetched = run_command(
        fetch_args,
        env=git_auth_environment(remote),
    )
    if fetched.returncode != 0:
        label = "full commit" if ref_kind == "commit" else "release tag"
        detail = fetched.stderr.strip() or fetched.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise SetupError(f"unable to fetch {label} {ref}{suffix}")
    resolved = git_output(root, "rev-parse", "FETCH_HEAD^{commit}")
    validation_history = run_command(
        [
            "git",
            "-C",
            str(root),
            "fetch",
            "--no-tags",
            "origin",
            "+refs/heads/*:refs/remotes/origin/*",
            "+refs/tags/*:refs/tags/*",
        ],
        env=git_auth_environment(remote),
    )
    if validation_history.returncode != 0:
        detail = validation_history.stderr.strip() or validation_history.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise SetupError(f"unable to fetch release validation history{suffix}")
    return ref_kind, resolved


def checkout_detached_release(root: Path, commit: str) -> None:
    checkout = run_command(["git", "-C", str(root), "checkout", "--detach", commit])
    if checkout.returncode != 0:
        raise SetupError(
            checkout.stderr.strip() or f"unable to checkout release revision {commit}"
        )


def clone_source(
    destination: Path,
    repo_url: str,
    ref: str,
    dry_run: bool,
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
) -> Path:
    release_ref_kind(ref)
    if dry_run:
        print(f"would clone {repo_url}@{ref} to {destination}")
        return destination
    if destination.exists():
        raise SetupError(f"managed source destination already exists: {destination}")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    initialized = run_command(["git", "init", "--quiet", str(destination)])
    if initialized.returncode != 0:
        raise SetupError(initialized.stderr.strip() or "unable to initialize skills repository")
    try:
        remote = run_command(
            ["git", "-C", str(destination), "remote", "add", "origin", repo_url]
        )
        if remote.returncode != 0:
            raise SetupError(remote.stderr.strip() or "unable to configure skills repository")
        _ref_kind, resolved = fetch_immutable_release(destination, ref)
        checkout_detached_release(destination, resolved)
        return validate_source(destination, bundle)
    except (OSError, SetupError):
        shutil.rmtree(destination, ignore_errors=True)
        raise


def checkout_managed_release(
    root: Path,
    repo_url: str,
    ref: str,
    dry_run: bool,
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
    *,
    expected_commit: str | None = None,
) -> str:
    release_ref_kind(ref)
    remote = git_output(root, "remote", "get-url", "origin")
    if normalized_repo_url(remote) != normalized_repo_url(repo_url):
        raise SetupError(f"managed source origin differs from configured repository: {remote}")
    if git_dirty(root, paths=bundle_git_paths(bundle)):
        raise SetupError(f"refusing to update dirty skills checkout: {root}")
    if dry_run:
        print(f"would checkout immutable release {repo_url}@{ref} in {root}")
        return "planned"
    ref_kind, resolved = fetch_immutable_release(root, ref)
    if expected_commit and resolved.lower() != expected_commit.lower():
        label = "release tag moved" if ref_kind == "tag" else "release commit changed"
        raise SetupError(
            f"{label}: requested={ref}, recorded={expected_commit}, remote={resolved}"
        )
    checkout_detached_release(root, resolved)
    return resolved


def checkout_managed_revision(
    root: Path,
    commit: str,
    dry_run: bool,
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        raise SetupError("recorded rollback revision is invalid")
    if git_dirty(root, paths=bundle_git_paths(bundle)):
        raise SetupError(f"refusing to roll back dirty skills checkout: {root}")
    verify = run_command(["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"])
    if verify.returncode != 0:
        raise SetupError(f"recorded rollback revision is unavailable: {commit}")
    if dry_run:
        print(f"would restore managed source {root} to {commit}")
        return
    checkout = run_command(["git", "-C", str(root), "checkout", "--detach", commit])
    if checkout.returncode != 0:
        raise SetupError(checkout.stderr.strip() or f"unable to restore revision {commit}")


def source_mode_from_state(state: Mapping[str, object]) -> str:
    mode = state.get("source_mode")
    if isinstance(mode, str) and mode in {"linked", "managed"}:
        return mode
    if mode is not None:
        raise SetupError(f"unsupported source mode in installer state: {mode!r}")
    return "managed" if state.get("managed_checkout") is True else "linked"


def ref_kind_from_state(state: Mapping[str, object], source_mode: str) -> str:
    value = state.get("ref_kind")
    if value is None:
        return "legacy-branch" if source_mode == "managed" else "linked"
    if isinstance(value, str) and value in {"tag", "commit", "legacy-branch", "linked"}:
        return value
    raise SetupError(f"unsupported ref kind in installer state: {value!r}")


def resolve_source(
    args: argparse.Namespace,
    *,
    bundle: Iterable[tuple[str, str]] = SKILL_BUNDLE,
    expected_commit: str | None = None,
) -> tuple[Path, str]:
    resolved_bundle = materialize_skill_bundle(bundle)
    requested_mode = args.source_mode
    if requested_mode == "managed" and args.source:
        raise SetupError("--source cannot be combined with --source-mode managed")
    if args.source:
        root = validate_source(args.source, resolved_bundle)
        return root, "linked"
    if requested_mode != "managed":
        local = local_repository_from_script(resolved_bundle)
        if local is not None:
            return local, "linked"
        if requested_mode == "linked":
            raise SetupError("linked source mode requires --source or a valid local repository")
    if not args.ref_explicit:
        raise SetupError("managed installation requires --ref with a release tag or full commit")
    release_ref_kind(args.ref)
    destination = managed_source_dir(args.home)
    if destination.exists():
        root = validate_source(destination, resolved_bundle)
        checkout_managed_release(
            root,
            args.repo_url,
            args.ref,
            args.dry_run,
            bundle=resolved_bundle,
            expected_commit=expected_commit,
        )
        return root, "managed"
    return (
        clone_source(
            destination,
            args.repo_url,
            args.ref,
            args.dry_run,
            resolved_bundle,
        ),
        "managed",
    )


def atomic_write(path: Path, content: str, mode: int | None = None) -> None:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    target_mode = existing_mode if mode is None else mode
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.chmod(temporary, target_mode)
        os.replace(temporary, path)
        os.chmod(path, target_mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def backup_path(home: Path) -> Path:
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    return openubmc_config_dir(home) / "backups" / timestamp


def backup_file(path: Path, root: Path, dry_run: bool) -> None:
    if not path.exists() or path.is_symlink():
        return
    relative = Path(str(path).lstrip(os.sep).replace(":", "_"))
    destination = root / relative
    if dry_run:
        print(f"would back up {path} to {destination}")
        return
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_dir():
        shutil.copytree(path, destination, dirs_exist_ok=True)
    else:
        shutil.copy2(path, destination)


def same_target(link: Path, target: Path) -> bool:
    if not link.is_symlink():
        return False
    return Path(os.path.realpath(link)) == Path(os.path.realpath(target))


def remaining_links_into_source(
    home: Path,
    clients: Iterable[str],
    source: Path,
    managed_links: Iterable[str],
) -> list[Path]:
    source_root = Path(os.path.realpath(source))
    planned_removals = {Path(path) for path in managed_links}
    consumers: list[Path] = []
    for client in clients:
        if client not in KNOWN_CLIENTS:
            continue
        skills_root = client_skills_dir(home, client)
        if not skills_root.is_dir() or skills_root.is_symlink():
            continue
        for link in skills_root.iterdir():
            if link in planned_removals or not link.is_symlink():
                continue
            target = Path(os.path.realpath(link))
            try:
                target.relative_to(source_root)
            except ValueError:
                continue
            consumers.append(link)
    return sorted(consumers)


def ensure_link(link: Path, target: Path, backups: Path, dry_run: bool) -> None:
    if same_target(link, target):
        return
    if link.exists() or link.is_symlink():
        if link.is_symlink():
            if dry_run:
                print(f"would replace stale link {link}")
            else:
                link.unlink()
        else:
            backup_file(link, backups, dry_run)
            if dry_run:
                print(f"would replace conflicting path {link} after backup")
            else:
                if link.is_dir():
                    shutil.rmtree(link)
                else:
                    link.unlink()
    if dry_run:
        print(f"would link {link} -> {target}")
        return
    link.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    link.symlink_to(target, target_is_directory=True)


def valid_preserved_skill_target(target: Path) -> bool:
    return target.is_dir() and (target / "SKILL.md").is_file()


def current_skill_link_target(link: Path) -> Path | None:
    if not link.is_symlink():
        return None
    target = Path(os.path.realpath(link))
    return target if valid_preserved_skill_target(target) else None


def resolve_preserved_link_targets(
    home: Path,
    clients: Iterable[str],
    preserved_skills: Iterable[str],
    recorded_links: Mapping[str, str] | None = None,
    *,
    prefer_recorded: bool = False,
) -> dict[str, Path]:
    preserved = set(preserved_skills)
    if not preserved:
        return {}
    recorded_links = recorded_links or {}
    targets: dict[str, Path] = {}
    for client in clients:
        destination_root = client_skills_dir(home, client)
        for canonical in sorted(preserved):
            link = destination_root / canonical
            current = current_skill_link_target(link)
            recorded_value = recorded_links.get(str(link), "")
            recorded_candidate = Path(recorded_value) if recorded_value else None
            recorded = (
                recorded_candidate
                if recorded_candidate is not None
                and valid_preserved_skill_target(recorded_candidate)
                else None
            )
            target = recorded if prefer_recorded else (current or recorded)
            if target is None:
                raise SetupError(
                    f"preserved Skill target is unavailable for {canonical}: {link}"
                )
            targets[str(link)] = target
    return targets


def install_links(
    home: Path,
    source: Path,
    clients: Iterable[str],
    backups: Path,
    dry_run: bool,
    bundle: tuple[tuple[str, str], ...] = SKILL_BUNDLE,
    preserved_targets: Mapping[str, Path] | None = None,
) -> dict[str, str]:
    managed: dict[str, str] = {}
    preserved_targets = preserved_targets or {}
    for client in clients:
        destination_root = client_skills_dir(home, client)
        for retired_name, relative in RETIRED_SKILL_LINKS:
            retired_link = destination_root / retired_name
            retired_target = source / relative
            if same_target(retired_link, retired_target):
                if dry_run:
                    print(f"would remove retired Skill link {retired_link}")
                else:
                    retired_link.unlink()
        for canonical, relative in bundle:
            link = destination_root / canonical
            target = preserved_targets.get(str(link), source / relative)
            ensure_link(link, target, backups, dry_run)
            managed[str(link)] = str(target)
        legacy = destination_root / "openubmc-environment"
        if legacy.is_symlink():
            if dry_run:
                print(f"would remove legacy Skill link {legacy}")
            else:
                legacy.unlink()
    return managed


def _remove_marked_block(text: str, start: str, end: str) -> str:
    pattern = re.compile(
        rf"(?:^|\n){re.escape(start)}\n.*?{re.escape(end)}\n?", re.DOTALL
    )
    return pattern.sub("\n", text)


def replace_profile_hook(text: str) -> str:
    cleaned = text
    for start, end in (
        (MARKER_START, MARKER_END),
        (OLD_MARKER_START, OLD_MARKER_END),
        (LEGACY_CREDENTIALS_START, LEGACY_CREDENTIALS_END),
    ):
        cleaned = _remove_marked_block(cleaned, start, end)
    cleaned = cleaned.strip()
    return f"{cleaned}\n\n{PROFILE_BLOCK}" if cleaned else PROFILE_BLOCK


def remove_profile_hook(text: str) -> str:
    cleaned = text
    for start, end in (
        (MARKER_START, MARKER_END),
        (OLD_MARKER_START, OLD_MARKER_END),
        (LEGACY_CREDENTIALS_START, LEGACY_CREDENTIALS_END),
    ):
        cleaned = _remove_marked_block(cleaned, start, end)
    return cleaned.strip() + ("\n" if cleaned.strip() else "")


def profile_paths(home: Path) -> list[Path]:
    paths = [home / ".bashrc", home / ".profile"]
    for bash_login in (home / ".bash_profile", home / ".bash_login"):
        if bash_login.exists():
            paths.append(bash_login)
    shell = os.environ.get("SHELL", "")
    if shell.endswith("zsh") or (home / ".zshrc").exists() or (home / ".zprofile").exists():
        paths.extend((home / ".zshrc", home / ".zprofile"))
    return paths


def private_file_shell_function() -> str:
    return r'''_openubmc_private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || return 1
    _openubmc_meta="$(stat -c '%u %a' "$1" 2>/dev/null || stat -f '%u %Lp' "$1" 2>/dev/null || true)"
    _openubmc_uid="${_openubmc_meta%% *}"
    _openubmc_mode="${_openubmc_meta#* }"
    [ "${_openubmc_uid}" = "$(id -u)" ] || return 1
    case "${_openubmc_mode}" in
        600) return 0 ;;
    esac
    return 1
}
'''


def render_env(tool_dirs: Iterable[str]) -> str:
    directories = [item for item in tool_dirs if item]
    lines = [
        "# Managed by openubmc-environment-setup. Safe to source repeatedly.",
        "",
        "# Removed compatibility variables must not leak from an older login shell.",
        "unset OPENUBMC_BUILD_SKILL_ROOT OPENUBMC_DEBUG_SKILL_ROOT OPENUBMC_UPGRADE_SKILL_ROOT",
        "",
    ]
    if directories:
        joined = ":".join(shlex.quote(item) for item in directories)
        lines.extend((f"export PATH={joined}:\"$PATH\"", ""))
    lines.append(private_file_shell_function().rstrip())
    lines.extend(
        (
            "",
            '_openubmc_credentials="${XDG_CONFIG_HOME:-$HOME/.config}/openubmc/credentials.env"',
            'if _openubmc_private_file "${_openubmc_credentials}"; then',
            '    export OPENUBMC_CREDENTIALS_FILE="${_openubmc_credentials}"',
            'elif [ "${OPENUBMC_CREDENTIALS_FILE:-}" = "${_openubmc_credentials}" ]; then',
            "    unset OPENUBMC_CREDENTIALS_FILE",
            "fi",
            '_openubmc_kb_config="${XDG_CONFIG_HOME:-$HOME/.config}/openubmc/kb-mcp.json"',
            'if _openubmc_private_file "${_openubmc_kb_config}"; then',
            '    export OPENUBMC_KB_CONFIG="${_openubmc_kb_config}"',
            'elif [ "${OPENUBMC_KB_CONFIG:-}" = "${_openubmc_kb_config}" ]; then',
            "    unset OPENUBMC_KB_CONFIG",
            "fi",
            "unset _openubmc_credentials _openubmc_kb_config _openubmc_meta _openubmc_uid _openubmc_mode",
            "unset -f _openubmc_private_file 2>/dev/null || true",
            "",
        )
    )
    return "\n".join(lines)


def tool_search_path(tool_dirs: Iterable[str]) -> str:
    entries = [item for item in tool_dirs if item]
    current = os.environ.get("PATH", "")
    if current:
        entries.append(current)
    return os.pathsep.join(entries)


def user_tool_bin(home: Path) -> Path:
    return home / ".local" / "bin"


def command_error(command: list[str], result: subprocess.CompletedProcess[str]) -> SetupError:
    detail = result.stderr.strip() or result.stdout.strip() or "command failed"
    return SetupError(f"{' '.join(command)} failed: {detail}")


def privileged_command(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    sudo = shutil.which("sudo")
    if not sudo:
        raise SetupError("automatic system package installation requires root or sudo")
    return [sudo, "-n", *command]


def install_apt_packages(packages: Iterable[str], *, dry_run: bool) -> None:
    selected = sorted(set(packages))
    if not selected:
        return
    if not shutil.which("apt-get"):
        raise SetupError(
            "automatic dependency installation currently requires apt-get"
        )
    if dry_run:
        print("would install system packages: " + ", ".join(selected))
        return
    environment = dict(os.environ)
    environment["DEBIAN_FRONTEND"] = "noninteractive"
    update = privileged_command(["apt-get", "update"])
    result = run_command(update, env=environment)
    if result.returncode != 0:
        raise command_error(update, result)
    install = privileged_command(
        ["apt-get", "install", "-y", "--no-install-recommends", *selected]
    )
    result = run_command(install, env=environment)
    if result.returncode != 0:
        raise command_error(install, result)
    print("installed system packages: " + ", ".join(selected))


def python_pip_available() -> bool:
    result = run_command([sys.executable, "-m", "pip", "--version"])
    return result.returncode == 0


def discover_bmcgo_wheel(source: Path) -> Path:
    configured = os.environ.get("OPENUBMC_BMCGO_PACKAGE", "").strip()
    candidates = [
        Path(configured).expanduser() if configured else None,
        source / "openubmc-environment-setup" / "assets" / BMCGO_WHEEL_NAME,
        Path(__file__).resolve().parents[1] / "assets" / BMCGO_WHEEL_NAME,
        Path("/home/workspace/tool") / BMCGO_WHEEL_NAME,
    ]
    for candidate in candidates:
        if candidate is None or not candidate.is_file():
            continue
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if digest != BMCGO_WHEEL_SHA256:
            raise SetupError(f"bmcgo package digest mismatch: {candidate}")
        return candidate
    raise SetupError("bundled bmcgo package is unavailable")


def install_python_workflow_tools(
    home: Path,
    source: Path,
    tool_dirs: Iterable[str],
    *,
    dry_run: bool,
) -> None:
    search_path = tool_search_path(tool_dirs)
    missing_bmcgo = shutil.which("bmcgo", path=search_path) is None
    missing_conan = shutil.which("conan", path=search_path) is None
    if not missing_bmcgo and not missing_conan:
        return
    packages: list[str] = []
    if missing_bmcgo:
        packages.append(
            BMCGO_WHEEL_NAME
            if dry_run and not source.exists()
            else str(discover_bmcgo_wheel(source))
        )
    if missing_conan:
        packages.append("conan")
    if dry_run:
        names = [Path(item).name if item.endswith(".whl") else item for item in packages]
        print("would install Python workflow packages: " + ", ".join(names))
        return
    environment = dict(os.environ)
    environment["HOME"] = str(home)
    environment["PYTHONUSERBASE"] = str(home / ".local")
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--user",
        "--upgrade",
        "--disable-pip-version-check",
        "--break-system-packages",
        *packages,
    ]
    result = run_command(command, env=environment)
    if (
        result.returncode != 0
        and "no such option: --break-system-packages"
        in (result.stderr + result.stdout).lower()
    ):
        command = [item for item in command if item != "--break-system-packages"]
        result = run_command(command, env=environment)
    if result.returncode != 0:
        raise command_error(command, result)
    print("installed Python workflow packages")


def install_codex_client(
    home: Path,
    tool_dirs: Iterable[str],
    *,
    dry_run: bool,
) -> None:
    if shutil.which("codex", path=tool_search_path(tool_dirs)):
        return
    prefix = home / ".local"
    if dry_run:
        print(f"would install Codex under {prefix}")
        return
    npm = shutil.which("npm")
    if not npm:
        raise SetupError("npm is unavailable after system dependency installation")
    environment = dict(os.environ)
    environment["HOME"] = str(home)
    command = [
        npm,
        "install",
        "--global",
        "--prefix",
        str(prefix),
        CODEX_NPM_PACKAGE,
    ]
    result = run_command(command, env=environment)
    if result.returncode != 0:
        raise command_error(command, result)
    print(f"installed Codex under {prefix}")


def install_bootstrap_tools(
    home: Path,
    clients: Iterable[str],
    tool_dirs: Iterable[str],
    *,
    dry_run: bool,
    knowledge_mcp: bool = False,
) -> None:
    search_path = tool_search_path(tool_dirs)
    apt_packages = [
        package
        for tool, package in APT_TOOL_PACKAGES.items()
        if shutil.which(tool, path=search_path) is None
    ]
    if (
        shutil.which("bmcgo", path=search_path) is None
        or shutil.which("conan", path=search_path) is None
    ) and not python_pip_available():
        apt_packages.append("python3-pip")
    if "codex" in set(clients) and shutil.which("codex", path=search_path) is None:
        if shutil.which("npm", path=search_path) is None:
            apt_packages.extend(("nodejs", "npm"))
    if knowledge_mcp:
        if shutil.which("node", path=search_path) is None:
            apt_packages.append("nodejs")
        if shutil.which("npm", path=search_path) is None:
            apt_packages.append("npm")
    install_apt_packages(apt_packages, dry_run=dry_run)
    if "codex" in set(clients):
        install_codex_client(home, tool_dirs, dry_run=dry_run)


def inspect_tooling(
    tool_dirs: Iterable[str], clients: Iterable[str]
) -> dict[str, Any]:
    search_path = tool_search_path(tool_dirs)
    selected_clients = set(clients)

    def availability(tools: Iterable[str]) -> dict[str, bool]:
        return {
            tool: shutil.which(tool, path=search_path) is not None
            for tool in tools
        }

    required = availability(REQUIRED_TOOLS)
    conditional = availability(CONDITIONAL_TOOLS)
    recommended = availability(RECOMMENDED_TOOLS)
    client_tools = {
        client: shutil.which(executable, path=search_path) is not None
        for client, executable in CLIENT_EXECUTABLES.items()
        if client in selected_clients
    }
    return {
        "ready": all(required.values()),
        "client_ready": all(client_tools.values()),
        "required": required,
        "conditional": conditional,
        "recommended": recommended,
        "clients": client_tools,
    }


def tooling_next_actions(
    tooling: Mapping[str, object], *, credentials_ok: bool
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    repairable: list[str] = []
    if not credentials_ok:
        actions.append(
            {
                "code": "configure_credentials",
                "detail": (
                    "run python3 \"$HOME/.agents/skills/"
                    "openubmc-environment-setup/scripts/install_environment.py\" "
                    "credentials"
                ),
            }
        )
    for tool, available in dict(tooling.get("required", {})).items():
        if available is not True:
            repairable.append(str(tool))
    for tool, available in dict(tooling.get("conditional", {})).items():
        if available is not True:
            repairable.append(str(tool))
    for tool, available in dict(tooling.get("recommended", {})).items():
        if available is not True:
            repairable.append(str(tool))
    for client, available in dict(tooling.get("clients", {})).items():
        if available is not True and client == "codex":
            repairable.append("codex")
        elif available is not True:
            executable = CLIENT_EXECUTABLES.get(str(client), str(client))
            actions.append(
                {
                    "code": "install_external_client",
                    "client": str(client),
                    "detail": (
                        f"install {executable} to launch {client} directly in this "
                        "environment; Skill and MCP configuration is already staged"
                    ),
                }
            )
    if repairable:
        actions.append(
            {
                "code": "repair_tooling",
                "tools": ",".join(sorted(set(repairable))),
                "detail": (
                    "run python3 \"$HOME/.agents/skills/"
                    "openubmc-environment-setup/scripts/install_environment.py\" "
                    "repair --non-interactive; the installer will add the tools "
                    "automatically"
                ),
            }
        )
    return actions


def knowledge_next_actions(
    report: Mapping[str, object]
) -> list[dict[str, str]]:
    if report.get("managed") is not True or report.get("healthy") is True:
        return []
    return [
        {
            "code": "configure_openubmc_kb",
            "detail": (
                "configure a standalone openubmc-kb stdio MCP entry or make the "
                "recorded HTTP endpoint available"
            ),
        }
    ]


def resolve_tool_dirs(
    non_interactive: bool, existing_dirs: Iterable[str] = ()
) -> tuple[list[str], list[str]]:
    del non_interactive
    tool_dirs = [
        item for item in dict.fromkeys(existing_dirs) if item and Path(item).is_dir()
    ]
    missing: list[str] = []
    for tool in REQUIRED_TOOLS:
        found = shutil.which(tool, path=tool_search_path(tool_dirs))
        if found:
            continue
        missing.append(tool)
    return tool_dirs, missing


def install_environment_files(
    home: Path, tool_dirs: Iterable[str], backups: Path, dry_run: bool
) -> list[str]:
    config_dir = openubmc_config_dir(home)
    env_file = config_dir / "env.sh"
    profiles = profile_paths(home)
    for path in (env_file, *profiles):
        if path.is_symlink():
            raise SetupError(f"refusing to replace symbolic link: {path}")
    if dry_run:
        print(f"would write {env_file}")
    else:
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(config_dir, 0o700)
        atomic_write(env_file, render_env(tool_dirs), 0o600)
    for profile in profiles:
        original = profile.read_text(encoding="utf-8", errors="ignore") if profile.exists() else ""
        updated = replace_profile_hook(original)
        if updated == original:
            continue
        backup_file(profile, backups, dry_run)
        if dry_run:
            print(f"would update {profile}")
        else:
            atomic_write(profile, updated, None if profile.exists() else 0o644)
    return [str(path) for path in profiles]


def validate_openubmc_config_dir(home: Path) -> None:
    config_dir = openubmc_config_dir(home)
    if config_dir.is_symlink() or (config_dir.exists() and not config_dir.is_dir()):
        raise SetupError(f"configuration directory must be a real directory: {config_dir}")
    if config_dir.exists():
        metadata = config_dir.stat()
        if metadata.st_uid != os.getuid():
            raise SetupError(f"configuration directory has the wrong owner: {config_dir}")


def validate_environment_paths(home: Path) -> None:
    validate_openubmc_config_dir(home)
    env_file = openubmc_config_dir(home) / "env.sh"
    for path in (state_path(home), env_file, *profile_paths(home)):
        if path.is_symlink():
            raise SetupError(f"refusing to replace symbolic link: {path}")
        if path.exists() and not path.is_file():
            raise SetupError(f"managed file path is not a regular file: {path}")


def parse_credentials_value(value: str, *, line_number: int) -> str:
    cooked = value.strip()
    if "\0" in cooked:
        raise SetupError(f"invalid credential value on line {line_number}")
    if not cooked:
        return ""
    if cooked[0] in {"'", '"'}:
        if len(cooked) < 2 or cooked[-1] != cooked[0]:
            raise SetupError(f"malformed quoted credential on line {line_number}")
        return cooked[1:-1]
    if cooked[-1] in {"'", '"'}:
        raise SetupError(f"malformed quoted credential on line {line_number}")
    return cooked


def normalize_credentials(
    values: dict[str, str], *, require_complete: bool = False
) -> dict[str, str]:
    normalized = dict(values)
    bmc_user = normalized.get("OPENUBMC_SSH_USER", "")
    redfish_user = normalized.get("REDFISH_USERNAME", "")
    if bmc_user and redfish_user and bmc_user != redfish_user:
        raise SetupError("BMC SSH and Redfish usernames must match")
    shared_user = bmc_user or redfish_user
    if shared_user:
        normalized["OPENUBMC_SSH_USER"] = shared_user
        normalized["REDFISH_USERNAME"] = shared_user

    bmc_password = normalized.get("OPENUBMC_SSH_PASSWORD", "")
    redfish_password = normalized.get("REDFISH_PASSWORD", "")
    if bmc_password and redfish_password and bmc_password != redfish_password:
        raise SetupError("BMC SSH and Redfish passwords must match")
    shared_password = bmc_password or redfish_password
    if shared_password:
        normalized["OPENUBMC_SSH_PASSWORD"] = shared_password
        normalized["REDFISH_PASSWORD"] = shared_password

    if require_complete:
        missing = [key for key in REQUIRED_CREDENTIAL_KEYS if not normalized.get(key)]
        if missing:
            raise SetupError("credentials are missing: " + ", ".join(missing))
    return normalized


def parse_credentials(
    content: str, *, require_complete: bool = False
) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = raw.partition("=")
        key = key.strip()
        if not separator or key not in ALLOWED_CREDENTIAL_KEYS:
            raise SetupError(f"unsupported credential key on line {number}")
        value = parse_credentials_value(raw_value, line_number=number)
        if key in values and values[key] != value:
            raise SetupError(f"conflicting credential key: {key}")
        values[key] = value
    return normalize_credentials(values, require_complete=require_complete)


def read_credentials_file(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise SetupError(f"credentials must be a regular non-symlink file: {path}")
    metadata = path.stat()
    if metadata.st_uid != os.getuid():
        raise SetupError(f"credentials file has the wrong owner: {path}")
    try:
        return parse_credentials(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise SetupError(f"unable to read credentials: {path}") from error


def credentials_status(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return False, "missing"
    try:
        values = read_credentials_file(path)
    except SetupError as error:
        return False, str(error)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        return False, f"permissions are {mode:04o}, expected 0600"
    missing = [key for key in REQUIRED_CREDENTIAL_KEYS if not values.get(key)]
    if missing:
        return False, "missing keys: " + ", ".join(missing)
    return True, "configured"


def render_credentials(values: dict[str, str]) -> str:
    normalized = normalize_credentials(values)
    return "".join(
        f"{key}={normalized[key]}\n"
        for key in CREDENTIAL_KEY_ORDER
        if key in normalized
    )


def write_credentials_file(path: Path, values: dict[str, str], dry_run: bool) -> None:
    normalized = normalize_credentials(values, require_complete=True)
    content = render_credentials(normalized)
    parse_credentials(content, require_complete=True)
    if dry_run:
        print(f"would write private credentials to {path}")
        return
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    atomic_write(path, content, 0o600)


def prompt_missing_credentials(existing: dict[str, str]) -> dict[str, str]:
    values = normalize_credentials(existing)
    if not values.get("OPENUBMC_SSH_USER") or not values.get("OPENUBMC_SSH_PASSWORD"):
        bmc_user = input("BMC SSH/Redfish username: ").strip()
        bmc_password = getpass.getpass("BMC SSH/Redfish password: ")
        values["OPENUBMC_SSH_USER"] = bmc_user
        values["OPENUBMC_SSH_PASSWORD"] = bmc_password
        values["REDFISH_USERNAME"] = bmc_user
        values["REDFISH_PASSWORD"] = bmc_password
    if not values.get("OPENUBMC_OS_SSH_USER") or not values.get("OPENUBMC_OS_SSH_PASSWORD"):
        values["OPENUBMC_OS_SSH_USER"] = input("OS SSH username: ").strip()
        values["OPENUBMC_OS_SSH_PASSWORD"] = getpass.getpass("OS SSH password: ")
    return normalize_credentials(values, require_complete=True)


def prepare_credentials(
    args: argparse.Namespace, *, repair_only: bool = False
) -> dict[str, Any]:
    destination = credentials_path(args.home)
    if args.skip_credentials:
        if repair_only:
            if not destination.exists():
                return {"destination": destination, "result": "missing"}
            values = read_credentials_file(destination)
            missing = [key for key in REQUIRED_CREDENTIAL_KEYS if not values.get(key)]
            return {
                "destination": destination,
                "result": "missing" if missing else "repaired",
                "chmod": stat.S_IMODE(destination.stat().st_mode) != 0o600,
            }
        return {"destination": destination, "result": "skipped"}
    existing: dict[str, str] = {}
    chmod_needed = False
    if destination.exists():
        existing = read_credentials_file(destination)
        chmod_needed = stat.S_IMODE(destination.stat().st_mode) != 0o600
    if args.import_credentials:
        source = args.import_credentials.expanduser().absolute()
        if source.is_symlink() or not source.is_file():
            raise SetupError(f"credential import must be a regular non-symlink file: {source}")
        metadata = source.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SetupError("credential import must be owned by the current user with mode 0600")
        values = dict(existing)
        values.update(parse_credentials(source.read_text(encoding="utf-8")))
        values = normalize_credentials(values, require_complete=True)
        return {
            "destination": destination,
            "result": "imported",
            "values": values,
        }
    missing = [key for key in REQUIRED_CREDENTIAL_KEYS if not existing.get(key)]
    if not missing:
        return {
            "destination": destination,
            "result": "preserved",
            "chmod": chmod_needed,
        }
    if repair_only:
        return {
            "destination": destination,
            "result": "missing",
            "chmod": chmod_needed,
        }
    if args.non_interactive or not sys.stdin.isatty():
        if args.configure_credentials:
            raise SetupError("credential configuration requires a TTY or --import-credentials")
        return {
            "destination": destination,
            "result": "missing",
            "chmod": chmod_needed,
        }
    if args.dry_run:
        return {
            "destination": destination,
            "result": "planned",
            "missing_count": len(missing),
            "chmod": chmod_needed,
        }
    values = prompt_missing_credentials(existing)
    return {
        "destination": destination,
        "result": "configured",
        "values": values,
    }


def apply_credentials_plan(plan: dict[str, Any], dry_run: bool) -> str:
    destination = Path(plan["destination"])
    values = plan.get("values")
    if isinstance(values, dict):
        write_credentials_file(destination, values, dry_run)
    elif plan.get("chmod"):
        if dry_run:
            print(f"would set mode 0600 on {destination}")
        else:
            os.chmod(destination, 0o600)
    if plan.get("result") == "planned":
        print(
            f"would request {plan.get('missing_count', 0)} missing credential fields "
            "through hidden TTY input"
        )
    return str(plan["result"])


def configure_credentials(args: argparse.Namespace, *, repair_only: bool = False) -> str:
    return apply_credentials_plan(
        prepare_credentials(args, repair_only=repair_only), args.dry_run
    )


def backup_config_file(path: Path, backups: Path, dry_run: bool) -> None:
    backup_file(path, backups, dry_run)


def migrate_legacy_toml_mcp_name(
    path: Path,
    backups: Path,
    dry_run: bool,
    *,
    current_managed: bool = False,
) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    original = path.read_text(encoding="utf-8", errors="strict")
    try:
        migration = client_config.migrate_toml_alias(
            original,
            legacy_name=LEGACY_STUDIO_MCP_NAME,
            current_name=KNOWLEDGE_MCP_NAME,
            default_url=LEGACY_STUDIO_HTTP_URL,
            current_managed=current_managed,
        )
    except client_config.ClientConfigError as error:
        raise SetupError(f"{error} in {path}") from error
    if migration.action == "unchanged":
        return False
    backup_config_file(path, backups, dry_run)
    if dry_run:
        if migration.action == "removed":
            print(f"would remove default {LEGACY_STUDIO_MCP_NAME} alias from {path}")
        else:
            print(
                f"would rename {LEGACY_STUDIO_MCP_NAME} to "
                f"{KNOWLEDGE_MCP_NAME} in {path}"
            )
    else:
        atomic_write(path, migration.text, None)
    return True


def migrate_legacy_json_mcp_name(
    path: Path,
    backups: Path,
    dry_run: bool,
    *,
    current_managed: bool = False,
) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        migration = client_config.migrate_json_alias(
            path.read_text(encoding="utf-8"),
            legacy_name=LEGACY_STUDIO_MCP_NAME,
            current_name=KNOWLEDGE_MCP_NAME,
            default_url=LEGACY_STUDIO_HTTP_URL,
            current_managed=current_managed,
        )
    except (OSError, client_config.ClientConfigError) as error:
        raise SetupError(f"invalid JSON client configuration: {path}: {error}") from error
    if migration.action == "unchanged":
        return False
    backup_config_file(path, backups, dry_run)
    if dry_run:
        if migration.action == "removed":
            print(f"would remove default {LEGACY_STUDIO_MCP_NAME} alias from {path}")
        else:
            print(
                f"would rename {LEGACY_STUDIO_MCP_NAME} to "
                f"{KNOWLEDGE_MCP_NAME} in {path}"
            )
    else:
        atomic_write(path, migration.text, None)
    return True


def migrate_legacy_mcp_names(
    home: Path,
    clients: Iterable[str],
    backups: Path,
    dry_run: bool,
    prior: Mapping[str, object] | None = None,
) -> None:
    prior = prior or {}
    for client in clients:
        previous = prior.get(client)
        current_managed = (
            record_created_entry(previous)
            if isinstance(previous, Mapping)
            else False
        )
        if client == "codex":
            migrate_legacy_toml_mcp_name(
                home / ".codex" / "config.toml",
                backups,
                dry_run,
                current_managed=current_managed,
            )
        elif client == "claude":
            migrate_legacy_json_mcp_name(
                home / ".claude.json",
                backups,
                dry_run,
                current_managed=current_managed,
            )


def toml_section_bounds(lines: list[str], header: str) -> tuple[int, int] | None:
    prefix = "[mcp_servers."
    if not header.startswith(prefix) or not header.endswith("]"):
        raise SetupError(f"invalid TOML section header: {header}")
    path = ("mcp_servers", header[len(prefix) : -1])
    try:
        return client_config.toml_section_bounds(lines, path)
    except client_config.ClientConfigError as error:
        raise SetupError(str(error)) from error


def toml_named_mcp_entry(path: Path, name: str) -> dict[str, object] | None:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        return client_config.parse_toml_mcp_entry(
            path.read_text(encoding="utf-8", errors="strict"),
            name,
            allow_missing_args=True,
        )
    except client_config.ClientConfigError as error:
        raise SetupError(f"invalid TOML client configuration: {path}: {error}") from error


def toml_knowledge_mcp_entry(path: Path) -> dict[str, str] | None:
    entry = toml_named_mcp_entry(path, KNOWLEDGE_MCP_NAME)
    if entry is None:
        return None
    if entry["type"] == "http":
        return {"transport": "http", "url": str(entry["url"])}
    return {"transport": "stdio", "command": str(entry["command"])}


def is_known_legacy_knowledge_stdio(
    command: object,
    args: object,
) -> bool:
    command_name = Path(str(command)).name.casefold()
    if command_name not in {"node", "node.exe"}:
        return False
    if not isinstance(args, list) or not all(
        isinstance(item, str) for item in args
    ):
        return False
    return any(
        item.replace("\\", "/").casefold().endswith(
            "/openubmc-standalone-mcp/src/server.js"
        )
        for item in args
    )


def toml_has_known_legacy_knowledge_stdio(path: Path) -> bool:
    entry = toml_named_mcp_entry(path, KNOWLEDGE_MCP_NAME)
    if entry is None or entry.get("type") != "stdio":
        return False
    return is_known_legacy_knowledge_stdio(entry.get("command"), entry.get("args"))


def toml_mcp_url(path: Path) -> str | None:
    entry = toml_knowledge_mcp_entry(path)
    if entry is None or entry.get("transport") != "http":
        return None
    return entry["url"]


def upsert_toml_mcp(
    path: Path,
    url: str,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    file_existed = path.exists()
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = original.splitlines()
    header = f"[mcp_servers.{KNOWLEDGE_MCP_NAME}]"
    bounds = toml_section_bounds(lines, header)
    created_entry = record_created_entry(prior)
    if bounds is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend((header, f"url = {json.dumps(url)}"))
        created_entry = True
    else:
        start, end = bounds
        existing = toml_knowledge_mcp_entry(path)
        if existing is not None and existing.get("transport") == "stdio":
            if not created_entry:
                return {
                    "path": str(path),
                    "ownership": "external",
                    "transport": "stdio",
                    "created_entry": False,
                    "created_file": False,
                }
        current = existing.get("url") if existing is not None else None
        if existing is None or existing.get("transport") != "http" or current != url:
            if not created_entry:
                raise SetupError(
                    f"existing {KNOWLEDGE_MCP_NAME} MCP URL differs in {path}: {current!r}"
                )
            lines[start:end] = (header, f"url = {json.dumps(url)}")
    updated = "\n".join(lines).rstrip() + "\n"
    if updated != original:
        backup_config_file(path, backups, dry_run)
        if dry_run:
            print(f"would register {KNOWLEDGE_MCP_NAME} in {path}")
        else:
            atomic_write(path, updated, None)
    return {
        "path": str(path),
        "url": url,
        "created_entry": created_entry,
        "created_file": record_created_file(prior) or not file_existed,
    }


def remove_toml_mcp(
    path: Path, record: dict[str, Any], backups: Path, dry_run: bool
) -> None:
    if not record_created_entry(record) or not path.exists() or path.is_symlink():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    header = f"[mcp_servers.{KNOWLEDGE_MCP_NAME}]"
    bounds = toml_section_bounds(lines, header)
    if bounds is None:
        return
    if toml_mcp_url(path) != record.get("url"):
        print(f"warning: preserving changed {KNOWLEDGE_MCP_NAME} MCP entry in {path}")
        return
    start, end = bounds
    updated_lines = lines[:start] + lines[end:]
    updated = "\n".join(updated_lines).strip()
    updated = updated + "\n" if updated else ""
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would remove {KNOWLEDGE_MCP_NAME} from {path}")
    elif not updated and record_created_file(record):
        path.unlink()
    else:
        atomic_write(path, updated, None)


def json_mcp_entry(path: Path) -> dict[str, Any] | None:
    return json_named_mcp_entry(path, KNOWLEDGE_MCP_NAME)


def upsert_json_mcp(
    path: Path,
    url: str,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    file_existed = path.exists()
    if path.exists():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SetupError(f"invalid JSON client configuration: {path}") from error
    else:
        document = {}
    servers = document.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise SetupError(f"mcpServers must be an object: {path}")
    existing = servers.get(KNOWLEDGE_MCP_NAME)
    created_entry = record_created_entry(prior)
    if existing is None:
        servers[KNOWLEDGE_MCP_NAME] = http_mcp_entry(url)
        created_entry = True
    elif isinstance(existing, dict) and existing.get("url") == url:
        return {
            "path": str(path),
            "url": url,
            "created_entry": created_entry,
            "created_file": record_created_file(prior),
        }
    elif created_entry:
        servers[KNOWLEDGE_MCP_NAME] = http_mcp_entry(url)
    elif not isinstance(existing, dict):
        raise SetupError(f"{KNOWLEDGE_MCP_NAME} MCP entry must be an object: {path}")
    else:
        raise SetupError(
            f"existing {KNOWLEDGE_MCP_NAME} MCP URL differs in {path}: {existing.get('url')!r}"
        )
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would register {KNOWLEDGE_MCP_NAME} in {path}")
    else:
        atomic_write(path, updated, None)
    return {
        "path": str(path),
        "url": url,
        "created_entry": created_entry,
        "created_file": record_created_file(prior) or not file_existed,
    }


def remove_json_mcp(
    path: Path, record: dict[str, Any], backups: Path, dry_run: bool
) -> None:
    if not record_created_entry(record) or not path.exists() or path.is_symlink():
        return
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    servers = document.get("mcpServers")
    if not isinstance(servers, dict) or KNOWLEDGE_MCP_NAME not in servers:
        return
    entry = servers.get(KNOWLEDGE_MCP_NAME)
    if not isinstance(entry, dict) or entry.get("url") != record.get("url"):
        print(f"warning: preserving changed {KNOWLEDGE_MCP_NAME} MCP entry in {path}")
        return
    servers.pop(KNOWLEDGE_MCP_NAME, None)
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would remove {KNOWLEDGE_MCP_NAME} from {path}")
    elif record_created_file(record) and document == {"mcpServers": {}}:
        path.unlink()
    else:
        atomic_write(path, updated, None)


def remove_toml_knowledge_mcp(
    path: Path, record: dict[str, Any], backups: Path, dry_run: bool
) -> None:
    if not record_created_entry(record) or not path.exists() or path.is_symlink():
        return
    try:
        current = toml_knowledge_mcp_entry(path)
    except SetupError:
        current = None
    expected = (
        {"transport": "stdio", "command": record.get("command")}
        if record.get("command")
        else {"transport": "http", "url": record.get("url")}
    )
    if current != expected:
        print(f"warning: preserving changed {KNOWLEDGE_MCP_NAME} MCP entry in {path}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    bounds = toml_section_bounds(lines, f"[mcp_servers.{KNOWLEDGE_MCP_NAME}]")
    if bounds is None:
        return
    start, end = bounds
    updated = "\n".join(lines[:start] + lines[end:]).strip()
    updated = updated + "\n" if updated else ""
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would remove {KNOWLEDGE_MCP_NAME} from {path}")
    elif not updated and record_created_file(record):
        path.unlink()
    else:
        atomic_write(path, updated, None)


def remove_json_knowledge_mcp(
    path: Path, record: dict[str, Any], backups: Path, dry_run: bool
) -> None:
    if not record_created_entry(record) or not path.exists() or path.is_symlink():
        return
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        return
    expected = (
        stdio_mcp_entry(str(record.get("command")))
        if record.get("command")
        else http_mcp_entry(str(record.get("url")))
    )
    if servers.get(KNOWLEDGE_MCP_NAME) != expected:
        print(f"warning: preserving changed {KNOWLEDGE_MCP_NAME} MCP entry in {path}")
        return
    servers.pop(KNOWLEDGE_MCP_NAME, None)
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would remove {KNOWLEDGE_MCP_NAME} from {path}")
    elif record_created_file(record) and document == {"mcpServers": {}}:
        path.unlink()
    else:
        atomic_write(path, updated, None)


def is_explicit_empty_toml_args(line: str) -> bool:
    return re.fullmatch(r"\s*args\s*=\s*\[\s*]\s*", line) is not None


def toml_stdio_mcp_entry(path: Path) -> dict[str, object] | None:
    entry = toml_named_mcp_entry(path, TARGET_RUNTIME_MCP_NAME)
    if entry is None:
        return None
    if entry["type"] != "stdio" or entry.get("args") != []:
        raise SetupError(
            f"{TARGET_RUNTIME_MCP_NAME} TOML section must contain one command "
            "and no args or args = []"
        )
    return entry


def upsert_toml_stdio_mcp(
    path: Path,
    launcher: Path,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    file_existed = path.exists()
    original = path.read_text(encoding="utf-8") if file_existed else ""
    lines = original.splitlines()
    header = f"[mcp_servers.{TARGET_RUNTIME_MCP_NAME}]"
    bounds = toml_section_bounds(lines, header)
    expected = stdio_mcp_entry(launcher)
    created_entry = record_created_entry(prior)
    if bounds is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend((header, f"command = {json.dumps(str(launcher))}", "args = []"))
        created_entry = True
    else:
        start, end = bounds
        current = toml_stdio_mcp_entry(path)
        has_explicit_empty_args = any(
            is_explicit_empty_toml_args(line)
            for line in lines[start + 1 : end]
        )
        if current == expected and has_explicit_empty_args:
            return {
                "path": str(path),
                "command": str(launcher),
                "args": [],
                "created_entry": created_entry,
                "created_file": record_created_file(prior),
            }
        if not created_entry:
            raise SetupError(
                f"existing {TARGET_RUNTIME_MCP_NAME} MCP command differs in {path}"
            )
        lines[start:end] = (
            header,
            f"command = {json.dumps(str(launcher))}",
            "args = []",
        )
    updated = "\n".join(lines).rstrip() + "\n"
    if updated != original:
        backup_config_file(path, backups, dry_run)
        if dry_run:
            print(f"would register {TARGET_RUNTIME_MCP_NAME} in {path}")
        else:
            atomic_write(path, updated, None)
    return {
        "path": str(path),
        "command": str(launcher),
        "args": [],
        "created_entry": created_entry,
        "created_file": record_created_file(prior) or not file_existed,
    }


def remove_toml_stdio_mcp(
    path: Path, record: dict[str, Any], backups: Path, dry_run: bool
) -> None:
    if not record_created_entry(record) or not path.exists() or path.is_symlink():
        return
    try:
        current = toml_stdio_mcp_entry(path)
    except SetupError:
        current = None
    expected = {
        "type": "stdio",
        "command": record.get("command"),
        "args": record.get("args", []),
    }
    if current != expected:
        print(f"warning: preserving changed {TARGET_RUNTIME_MCP_NAME} MCP entry in {path}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    header = f"[mcp_servers.{TARGET_RUNTIME_MCP_NAME}]"
    bounds = toml_section_bounds(lines, header)
    if bounds is None:
        return
    start, end = bounds
    updated_lines = lines[:start] + lines[end:]
    updated = "\n".join(updated_lines).strip()
    updated = updated + "\n" if updated else ""
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would remove {TARGET_RUNTIME_MCP_NAME} from {path}")
    elif not updated and record_created_file(record):
        path.unlink()
    else:
        atomic_write(path, updated, None)


def json_named_mcp_entry(path: Path, name: str) -> dict[str, Any] | None:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        return client_config.parse_json_mcp_entry(
            path.read_text(encoding="utf-8"),
            name,
        )
    except (OSError, client_config.ClientConfigError) as error:
        raise SetupError(f"invalid JSON client configuration: {path}: {error}") from error


def upsert_json_stdio_mcp(
    path: Path,
    launcher: Path,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    file_existed = path.exists()
    if file_existed:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SetupError(f"invalid JSON client configuration: {path}") from error
    else:
        document = {}
    servers = document.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise SetupError(f"mcpServers must be an object: {path}")
    expected = stdio_mcp_entry(launcher)
    existing = servers.get(TARGET_RUNTIME_MCP_NAME)
    created_entry = record_created_entry(prior)
    if existing is None:
        servers[TARGET_RUNTIME_MCP_NAME] = expected
        created_entry = True
    elif existing == expected:
        return {
            "path": str(path),
            "command": str(launcher),
            "args": [],
            "created_entry": created_entry,
            "created_file": record_created_file(prior),
        }
    elif created_entry:
        servers[TARGET_RUNTIME_MCP_NAME] = expected
    else:
        raise SetupError(
            f"existing {TARGET_RUNTIME_MCP_NAME} MCP command differs in {path}"
        )
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would register {TARGET_RUNTIME_MCP_NAME} in {path}")
    else:
        atomic_write(path, updated, None)
    return {
        "path": str(path),
        "command": str(launcher),
        "args": [],
        "created_entry": created_entry,
        "created_file": record_created_file(prior) or not file_existed,
    }


def remove_json_stdio_mcp(
    path: Path, record: dict[str, Any], backups: Path, dry_run: bool
) -> None:
    if not record_created_entry(record) or not path.exists() or path.is_symlink():
        return
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        return
    expected = {
        "type": "stdio",
        "command": record.get("command"),
        "args": record.get("args", []),
    }
    if servers.get(TARGET_RUNTIME_MCP_NAME) != expected:
        print(f"warning: preserving changed {TARGET_RUNTIME_MCP_NAME} MCP entry in {path}")
        return
    servers.pop(TARGET_RUNTIME_MCP_NAME, None)
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would remove {TARGET_RUNTIME_MCP_NAME} from {path}")
    elif record_created_file(record) and document == {"mcpServers": {}}:
        path.unlink()
    else:
        atomic_write(path, updated, None)


def remove_retired_claude_mcp(
    path: Path,
    knowledge_record: Mapping[str, object] | None,
    runtime_record: Mapping[str, object] | None,
    backups: Path,
    dry_run: bool,
) -> None:
    """Remove both workflow-owned Claude entries with one reversible backup."""
    records = tuple(
        record
        for record in (knowledge_record, runtime_record)
        if isinstance(record, Mapping) and record_created_entry(record)
    )
    if not records or not path.exists() or path.is_symlink():
        return
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        return

    changed = False
    if isinstance(knowledge_record, Mapping) and record_created_entry(
        knowledge_record
    ):
        expected_knowledge = (
            stdio_mcp_entry(str(knowledge_record.get("command")))
            if knowledge_record.get("command")
            else http_mcp_entry(str(knowledge_record.get("url")))
        )
        if servers.get(KNOWLEDGE_MCP_NAME) == expected_knowledge:
            servers.pop(KNOWLEDGE_MCP_NAME, None)
            changed = True
        else:
            print(
                f"warning: preserving changed {KNOWLEDGE_MCP_NAME} MCP entry in {path}"
            )
    if isinstance(runtime_record, Mapping) and record_created_entry(runtime_record):
        expected_runtime = {
            "type": "stdio",
            "command": runtime_record.get("command"),
            "args": runtime_record.get("args", []),
        }
        if servers.get(TARGET_RUNTIME_MCP_NAME) == expected_runtime:
            servers.pop(TARGET_RUNTIME_MCP_NAME, None)
            changed = True
        else:
            print(
                f"warning: preserving changed {TARGET_RUNTIME_MCP_NAME} MCP entry in {path}"
            )
    if not changed:
        return

    backup_config_file(path, backups, dry_run)
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if dry_run:
        print(f"would remove retired workflow MCP entries from {path}")
    elif any(record_created_file(record) for record in records) and document == {
        "mcpServers": {}
    }:
        path.unlink()
    else:
        atomic_write(path, updated, None)


def configure_runtime_mcp(
    home: Path,
    clients: Iterable[str],
    launcher: Path,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    managed: dict[str, dict[str, Any]] = {}
    prior = prior or {}
    for client in clients:
        previous = prior.get(client)
        if not isinstance(previous, dict):
            previous = None
        if client == "codex":
            managed[client] = upsert_toml_stdio_mcp(
                home / ".codex" / "config.toml",
                launcher,
                backups,
                dry_run,
                previous,
            )
        elif client == "claude":
            managed[client] = upsert_json_stdio_mcp(
                home / ".claude.json", launcher, backups, dry_run, previous
            )
        elif client == "openclaw":
            managed[client] = {"adapter_available": False, "command": str(launcher)}
    return managed


def configure_mcp(
    home: Path,
    clients: Iterable[str],
    url: str,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    managed: dict[str, dict[str, Any]] = {}
    prior = prior or {}
    for client in clients:
        previous = prior.get(client)
        if not isinstance(previous, dict):
            previous = None
        if client == "codex":
            managed[client] = upsert_toml_mcp(
                home / ".codex" / "config.toml", url, backups, dry_run, previous
            )
        elif client == "claude":
            managed[client] = upsert_json_mcp(
                home / ".claude.json", url, backups, dry_run, previous
            )
        elif client == "openclaw":
            print("warning: OpenClaw Skill links installed; MCP registration requires a supported OpenClaw config adapter")
            managed[client] = {"adapter_available": False, "url": url}
    return managed


def upsert_toml_knowledge_stdio_mcp(
    path: Path,
    launcher: Path,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    file_existed = path.exists()
    original = path.read_text(encoding="utf-8") if file_existed else ""
    lines = original.splitlines()
    header = f"[mcp_servers.{KNOWLEDGE_MCP_NAME}]"
    bounds = toml_section_bounds(lines, header)
    created_entry = record_created_entry(prior)
    expected_command = str(launcher)
    if bounds is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend((header, f"command = {json.dumps(expected_command)}", "args = []"))
        created_entry = True
    else:
        existing = toml_knowledge_mcp_entry(path)
        if existing == {"transport": "stdio", "command": expected_command}:
            return {
                "path": str(path),
                "transport": "stdio",
                "command": expected_command,
                "args": [],
                "created_entry": created_entry,
                "created_file": record_created_file(prior),
            }
        if (
            not created_entry
            and existing is not None
            and existing.get("transport") == "http"
            and existing.get("url") == LEGACY_STUDIO_HTTP_URL
        ):
            created_entry = True
        elif not created_entry and toml_has_known_legacy_knowledge_stdio(path):
            created_entry = True
        elif not created_entry:
            return {
                "path": str(path),
                "ownership": "external",
                "transport": str(existing.get("transport", "unknown")) if existing else "unknown",
                "created_entry": False,
                "created_file": False,
            }
        start, end = bounds
        lines[start:end] = (
            header,
            f"command = {json.dumps(expected_command)}",
            "args = []",
        )
    updated = "\n".join(lines).rstrip() + "\n"
    if updated != original:
        backup_config_file(path, backups, dry_run)
        if dry_run:
            print(f"would register {KNOWLEDGE_MCP_NAME} in {path}")
        else:
            atomic_write(path, updated, None)
    return {
        "path": str(path),
        "transport": "stdio",
        "command": expected_command,
        "args": [],
        "created_entry": created_entry,
        "created_file": record_created_file(prior) or not file_existed,
    }


def upsert_json_knowledge_stdio_mcp(
    path: Path,
    launcher: Path,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SetupError(f"refusing to replace symbolic link: {path}")
    file_existed = path.exists()
    if file_existed:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SetupError(f"invalid JSON client configuration: {path}") from error
    else:
        document = {}
    servers = document.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise SetupError(f"mcpServers must be an object: {path}")
    expected = stdio_mcp_entry(launcher)
    existing = servers.get(KNOWLEDGE_MCP_NAME)
    created_entry = record_created_entry(prior)
    if existing is None:
        servers[KNOWLEDGE_MCP_NAME] = expected
        created_entry = True
    elif existing == expected:
        return {
            "path": str(path),
            "transport": "stdio",
            "command": str(launcher),
            "args": [],
            "created_entry": created_entry,
            "created_file": record_created_file(prior),
        }
    elif (
        not created_entry
        and isinstance(existing, dict)
        and existing.get("url") == LEGACY_STUDIO_HTTP_URL
    ):
        created_entry = True
        servers[KNOWLEDGE_MCP_NAME] = expected
    elif (
        not created_entry
        and isinstance(existing, dict)
        and is_known_legacy_knowledge_stdio(
            existing.get("command"),
            existing.get("args"),
        )
    ):
        created_entry = True
        servers[KNOWLEDGE_MCP_NAME] = expected
    elif not created_entry:
        return {
            "path": str(path),
            "ownership": "external",
            "transport": "stdio" if isinstance(existing, dict) and "command" in existing else "http",
            "created_entry": False,
            "created_file": False,
        }
    else:
        servers[KNOWLEDGE_MCP_NAME] = expected
    updated = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    backup_config_file(path, backups, dry_run)
    if dry_run:
        print(f"would register {KNOWLEDGE_MCP_NAME} in {path}")
    else:
        atomic_write(path, updated, None)
    return {
        "path": str(path),
        "transport": "stdio",
        "command": str(launcher),
        "args": [],
        "created_entry": created_entry,
        "created_file": record_created_file(prior) or not file_existed,
    }


def configure_knowledge_mcp(
    home: Path,
    clients: Iterable[str],
    launcher: Path,
    backups: Path,
    dry_run: bool,
    prior: dict[str, Any] | None = None,
    *,
    url: str | None = None,
) -> dict[str, dict[str, Any]]:
    if url:
        return configure_mcp(home, clients, url, backups, dry_run, prior)
    managed: dict[str, dict[str, Any]] = {}
    prior = prior or {}
    for client in clients:
        previous = prior.get(client)
        if not isinstance(previous, dict):
            previous = None
        if client == "codex":
            managed[client] = upsert_toml_knowledge_stdio_mcp(
                home / ".codex" / "config.toml",
                launcher,
                backups,
                dry_run,
                previous,
            )
        elif client == "claude":
            managed[client] = upsert_json_knowledge_stdio_mcp(
                home / ".claude.json",
                launcher,
                backups,
                dry_run,
                previous,
            )
        elif client == "openclaw":
            managed[client] = {"adapter_available": False, "command": str(launcher)}
    return managed


def knowledge_mcp_transport_summary(
    clients: Iterable[str], records: Mapping[str, object]
) -> tuple[list[str], list[str], list[str]]:
    external: list[str] = []
    managed_stdio: list[str] = []
    managed_http: list[str] = []
    for client in clients:
        if client not in SUPPORTED_MCP_CLIENTS:
            continue
        record = records.get(client)
        if isinstance(record, Mapping) and record.get("ownership") == "external":
            external.append(client)
        elif isinstance(record, Mapping) and record.get("command"):
            managed_stdio.append(client)
        else:
            managed_http.append(client)
    return external, managed_stdio, managed_http


def inherit_created_file_ownership(
    records: dict[str, dict[str, Any]],
    owners: Mapping[str, object],
) -> dict[str, dict[str, Any]]:
    for client, record in records.items():
        owner = owners.get(client)
        if isinstance(owner, Mapping) and record_created_file(owner):
            record["created_file"] = True
    return records


def recover_runtime_mcp_ownership(
    home: Path,
    clients: Iterable[str],
    prior: Mapping[str, object],
) -> dict[str, dict[str, Any]]:
    """Recover ownership omitted by state written before runtime_mcp existed."""
    recovered = {
        client: dict(record)
        for client, record in prior.items()
        if isinstance(client, str) and isinstance(record, dict)
    }
    launcher = runtime_launcher_path(home)
    expected = stdio_mcp_entry(launcher)
    for client in clients:
        if client not in MCP_OWNERSHIP_CLIENTS:
            continue
        if valid_client_ownership_record(recovered.get(client)):
            continue
        if client == "codex":
            path = home / ".codex" / "config.toml"
            try:
                current = toml_stdio_mcp_entry(path)
            except (OSError, UnicodeError, SetupError):
                current = None
        else:
            path = home / ".claude.json"
            try:
                current = json_named_mcp_entry(path, TARGET_RUNTIME_MCP_NAME)
            except SetupError:
                current = None
        if current == expected:
            recovered[client] = {
                "path": str(path),
                "command": str(launcher),
                "args": [],
                "created_entry": True,
                # The entry can be recovered exactly from its installer-owned
                # launcher path. File ownership cannot, so preserve the file.
                "created_file": False,
            }
    return recovered


def validate_mcp_configuration(
    home: Path,
    clients: Iterable[str],
    url: str,
    prior: Mapping[str, object] | None = None,
) -> None:
    prior = prior or {}
    for client in clients:
        previous = prior.get(client)
        managed_entry = (
            record_created_entry(previous)
            if isinstance(previous, Mapping)
            else False
        )
        if client == "codex":
            path = home / ".codex" / "config.toml"
            if path.is_symlink():
                raise SetupError(f"refusing to replace symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise SetupError(f"client configuration is not a regular file: {path}")
            entry = toml_knowledge_mcp_entry(path)
            current = entry.get("url") if entry is not None else None
            if (
                entry is not None
                and entry.get("transport") == "http"
                and current != url
                and not managed_entry
            ):
                raise SetupError(
                    f"existing {KNOWLEDGE_MCP_NAME} MCP URL differs in {path}: {current!r}"
                )
        elif client == "claude":
            path = home / ".claude.json"
            if path.is_symlink():
                raise SetupError(f"refusing to replace symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise SetupError(f"client configuration is not a regular file: {path}")
            current = json_mcp_entry(path)
            if current is not None and current.get("url") != url and not managed_entry:
                raise SetupError(
                    f"existing {KNOWLEDGE_MCP_NAME} MCP URL differs in {path}: "
                    f"{current.get('url')!r}"
                )


def validate_knowledge_mcp_configuration(
    home: Path,
    clients: Iterable[str],
    launcher: Path,
    prior: Mapping[str, object] | None = None,
    *,
    url: str | None = None,
) -> None:
    if url:
        validate_mcp_configuration(home, clients, url, prior)
        return
    del launcher
    prior = prior or {}
    for client in clients:
        previous = prior.get(client)
        managed_entry = record_created_entry(previous) if isinstance(previous, Mapping) else False
        if client == "codex":
            path = home / ".codex" / "config.toml"
            if path.is_symlink():
                raise SetupError(f"refusing to replace symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise SetupError(f"client configuration is not a regular file: {path}")
            entry = toml_knowledge_mcp_entry(path)
            if (
                entry is not None
                and entry.get("transport") == "http"
                and entry.get("url") != LEGACY_STUDIO_HTTP_URL
                and not managed_entry
            ):
                raise SetupError(
                    f"existing {KNOWLEDGE_MCP_NAME} MCP URL differs in {path}: {entry.get('url')!r}"
                )
        elif client == "claude":
            path = home / ".claude.json"
            if path.is_symlink():
                raise SetupError(f"refusing to replace symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise SetupError(f"client configuration is not a regular file: {path}")
            entry = json_mcp_entry(path)
            if (
                isinstance(entry, Mapping)
                and "url" in entry
                and entry.get("url") != LEGACY_STUDIO_HTTP_URL
                and not managed_entry
            ):
                raise SetupError(
                    f"existing {KNOWLEDGE_MCP_NAME} MCP URL differs in {path}: {entry.get('url')!r}"
                )


def validate_runtime_mcp_configuration(
    home: Path,
    clients: Iterable[str],
    launcher: Path,
    prior: dict[str, Any] | None = None,
) -> None:
    prior = prior or {}
    expected = stdio_mcp_entry(launcher)
    for client in clients:
        previous = prior.get(client)
        managed_entry = (
            record_created_entry(previous)
            if isinstance(previous, Mapping)
            else False
        )
        if client == "codex":
            path = home / ".codex" / "config.toml"
            if path.is_symlink():
                raise SetupError(f"refusing to replace symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise SetupError(f"client configuration is not a regular file: {path}")
            current = toml_stdio_mcp_entry(path)
        elif client == "claude":
            path = home / ".claude.json"
            if path.is_symlink():
                raise SetupError(f"refusing to replace symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise SetupError(f"client configuration is not a regular file: {path}")
            current = json_named_mcp_entry(path, TARGET_RUNTIME_MCP_NAME)
        else:
            continue
        if current is not None and current != expected and not managed_entry:
            raise SetupError(
                f"existing {TARGET_RUNTIME_MCP_NAME} MCP command differs in {path}"
            )


def validate_link_plan(
    home: Path,
    source: Path,
    clients: Iterable[str],
    *,
    allow_missing_targets: bool = False,
    bundle: tuple[tuple[str, str], ...] = SKILL_BUNDLE,
) -> None:
    for client in clients:
        for canonical, relative in bundle:
            target = source / relative
            if not allow_missing_targets and not target.is_dir():
                raise SetupError(f"Skill target is missing: {target}")
            link = client_skills_dir(home, client) / canonical
            if link.exists() and not link.is_symlink():
                if not link.is_file() and not link.is_dir():
                    raise SetupError(f"conflicting Skill path cannot be backed up: {link}")
                if not os.access(link, os.R_OK):
                    raise SetupError(f"conflicting Skill path cannot be backed up: {link}")


def knowledge_http_health(url: str, timeout: float = 2.0) -> tuple[bool, str]:
    health_url = url[:-4] + "/health" if url.endswith("/mcp") else url.rstrip("/") + "/health"
    request = urllib.request.Request(health_url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(4096).decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError) as error:
        return False, str(error)
    try:
        document = json.loads(payload)
    except json.JSONDecodeError:
        return False, "health endpoint did not return JSON"
    if document.get("status") != "ok":
        return False, "health endpoint did not report status=ok"
    tools = document.get("tools", "unknown")
    return True, f"ok ({tools} tools)"


def save_state(home: Path, state: dict[str, object], dry_run: bool) -> None:
    path = state_path(home)
    content = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if dry_run:
        print(f"would write installer state to {path}")
        return
    atomic_write(path, content, 0o600)


def load_state(home: Path) -> dict[str, object]:
    path = state_path(home)
    if path.is_symlink() or not path.is_file():
        raise SetupError(f"installer state is missing: {path}")
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SetupError(f"installer state must be owned by the current user with mode 0600: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SetupError(f"invalid installer state: {path}") from error
    if not isinstance(document, dict):
        raise SetupError(f"installer state must be an object: {path}")
    if document.get("version") != STATE_VERSION:
        raise SetupError(f"unsupported installer state version: {document.get('version')}")
    return document


def try_load_state(home: Path) -> dict[str, object] | None:
    try:
        return load_state(home)
    except SetupError:
        return None


def recorded_string_list(
    state: Mapping[str, object], key: str
) -> tuple[str, ...]:
    value = state.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SetupError(f"{key} in installer state must be a list of strings")
    return tuple(value)


def recorded_string_mapping(
    state: Mapping[str, object], key: str
) -> dict[str, str]:
    value = state.get(key, {})
    if not isinstance(value, dict) or any(
        not isinstance(item_key, str) or not isinstance(item_value, str)
        for item_key, item_value in value.items()
    ):
        raise SetupError(f"{key} in installer state must map strings to strings")
    return dict(value)


def recorded_object(state: Mapping[str, object], key: str) -> dict[str, Any]:
    value = state.get(key, {})
    if not isinstance(value, dict):
        raise SetupError(f"{key} in installer state must be an object")
    return dict(value)


def recorded_client_records(
    state: Mapping[str, object], key: str
) -> dict[str, dict[str, Any]]:
    records = recorded_object(state, key)
    invalid = [
        repr(name)
        for name, value in records.items()
        if not isinstance(name, str) or not isinstance(value, dict)
    ]
    if invalid:
        raise SetupError(
            f"{key} in installer state has invalid client records: "
            + ", ".join(sorted(invalid))
        )
    return {name: dict(value) for name, value in records.items()}


def source_root_from_state(state: Mapping[str, object]) -> Path:
    value = state.get("source_root")
    if not isinstance(value, str) or not value.strip():
        raise SetupError("source_root in installer state must be a non-empty string")
    return Path(value)


def decode_recorded_install(state: Mapping[str, object]) -> RecordedInstall:
    profile = skill_profile_from_state(state)
    source_mode = source_mode_from_state(state)
    source_commit = str(state.get("source_commit", ""))
    requested_ref = str(state.get("requested_ref", state.get("ref", "")))
    preserved_skills = parse_preserved_skills(
        ",".join(recorded_string_list(state, "preserved_skills")),
        profile.bundle,
    )
    return RecordedInstall(
        source_root=source_root_from_state(state),
        source_mode=source_mode,
        source_commit=source_commit,
        resolved_commit=str(state.get("resolved_commit", source_commit)),
        rollback_commit=str(state.get("rollback_commit", "")),
        repo_url=str(state.get("repo_url", DEFAULT_REPO_URL)),
        ref=str(state.get("ref", requested_ref or DEFAULT_REF)),
        requested_ref=requested_ref,
        ref_kind=ref_kind_from_state(state, source_mode),
        clients=recorded_string_list(state, "clients"),
        profile=profile,
        knowledge_url=str(
            state.get("knowledge_url", state.get("studio_url", ""))
        ),
        target=str(state.get("target", "current")),
        tool_dirs=recorded_string_list(state, "tool_dirs"),
        mcp=recorded_client_records(state, "mcp"),
        runtime_mcp=recorded_client_records(state, "runtime_mcp"),
        links=recorded_string_mapping(state, "links"),
        preserved_skills=preserved_skills,
        profiles=recorded_string_list(state, "profiles"),
        runtime=recorded_object(state, "runtime"),
        release=recorded_object(state, "release"),
    )


def missing_client_ownership_records(
    recorded: RecordedInstall,
) -> tuple[str, ...]:
    missing: list[str] = []
    for client in dict.fromkeys(recorded.clients):
        if client not in MCP_OWNERSHIP_CLIENTS:
            continue
        if (
            recorded.profile.manages_knowledge_mcp
            and not valid_client_ownership_record(recorded.mcp.get(client))
        ):
            missing.append(f"mcp.{client}")
        if not valid_client_ownership_record(recorded.runtime_mcp.get(client)):
            missing.append(f"runtime_mcp.{client}")
    return tuple(missing)


def retire_legacy_client_state(
    home: Path,
    recorded: RecordedInstall,
    retired_clients: Iterable[str],
    prior_mcp: Mapping[str, object],
    prior_runtime_mcp: Mapping[str, object],
    backups: Path,
    dry_run: bool,
) -> None:
    """Remove only installer-owned state for clients retired from the product."""
    retired = tuple(dict.fromkeys(retired_clients))
    preserved_link_paths = {
        str(client_skills_dir(home, client) / canonical)
        for client in retired
        for canonical in recorded.preserved_skills
    }
    retired_roots = tuple(client_skills_dir(home, client) for client in retired)
    for link_text, target_text in sorted(recorded.links.items()):
        link = Path(link_text)
        if not any(link == root or root in link.parents for root in retired_roots):
            continue
        if link_text in preserved_link_paths:
            if same_target(link, Path(target_text)):
                print(f"preserving external Skill link {link}")
            continue
        if not same_target(link, Path(target_text)):
            continue
        if dry_run:
            print(f"would remove retired client Skill link {link}")
        else:
            link.unlink()

    if "claude" not in retired:
        return
    knowledge_record = (
        prior_mcp.get("claude") if recorded.profile.manages_knowledge_mcp else None
    )
    remove_retired_claude_mcp(
        home / ".claude.json",
        knowledge_record if isinstance(knowledge_record, Mapping) else None,
        prior_runtime_mcp.get("claude")
        if isinstance(prior_runtime_mcp.get("claude"), Mapping)
        else None,
        backups,
        dry_run,
    )


def perform_install(
    args: argparse.Namespace,
    *,
    update: bool = False,
    recorded_state: RecordedInstall | None = None,
    repair_only: bool = False,
) -> int:
    home = args.home.expanduser().absolute()
    args.home = home
    if recorded_state is not None:
        prior_install = recorded_state
    else:
        prior_document = try_load_state(home)
        prior_install = (
            decode_recorded_install(prior_document)
            if prior_document is not None
            else None
        )
    if (
        args.command == "install"
        and prior_install is not None
        and prior_install.source_mode == "managed"
        and prior_install.ref_kind == "legacy-branch"
        and args.source is None
        and args.source_mode == "auto"
        and not args.ref_explicit
    ):
        raise SetupError(
            "managed source uses a mutable legacy branch; "
            "rerun bootstrap with an immutable --ref"
        )
    if args.knowledge_url is None:
        prior_url = prior_install.knowledge_url if prior_install is not None else ""
        args.knowledge_url = prior_url if prior_url and prior_url != LEGACY_STUDIO_HTTP_URL else None
    if args.skill_profile is not None:
        selected_policy = resolve_skill_profile(str(args.skill_profile))
    elif prior_install is not None:
        selected_policy = prior_install.profile
    else:
        selected_policy = resolve_skill_profile(DEFAULT_SKILL_PROFILE)
    selected_profile = selected_policy.name
    selected_bundle = selected_policy.bundle
    if args.preserve_skills is not None:
        preserved_skills = parse_preserved_skills(
            args.preserve_skills,
            selected_bundle,
        )
    elif prior_install is not None:
        preserved_skills = parse_preserved_skills(
            ",".join(prior_install.preserved_skills),
            selected_bundle,
        )
    else:
        preserved_skills = ()
    args.skill_profile = selected_profile
    manage_knowledge_mcp = selected_policy.manages_knowledge_mcp
    prior_source: Path | None = None
    prior_source_mode: str | None = None
    if (
        args.source is None
        and prior_install is not None
        and prior_install.source_mode == "managed"
        and args.source_mode == "auto"
        and args.ref_explicit
    ):
        args.source_mode = "managed"
        if not args.repo_url_explicit:
            args.repo_url = prior_install.repo_url
    if args.source is None and prior_install and args.source_mode == "auto":
        prior_source = prior_install.source_root
        prior_source_mode = prior_install.source_mode
        args.repo_url = prior_install.repo_url
        args.ref = prior_install.ref
        args.target = prior_install.target
    clients = parse_clients(args.clients, home)
    retired_clients = (
        tuple(
            client
            for client in dict.fromkeys(prior_install.clients)
            if client in LEGACY_CLIENTS
        )
        if prior_install
        else ()
    )
    prior_mcp = dict(prior_install.mcp) if prior_install else {}
    prior_runtime_mcp = (
        recover_runtime_mcp_ownership(
            home,
            prior_install.clients,
            prior_install.runtime_mcp,
        )
        if prior_install
        else {}
    )
    validate_environment_paths(home)
    if manage_knowledge_mcp:
        validate_knowledge_mcp_configuration(
            home,
            clients,
            knowledge_launcher_path(home),
            prior_mcp,
            url=args.knowledge_url,
        )
        if retired_clients:
            validate_knowledge_mcp_configuration(
                home,
                retired_clients,
                knowledge_launcher_path(home),
                prior_mcp,
                url=args.knowledge_url,
            )
    validate_runtime_mcp_configuration(
        home,
        clients,
        runtime_launcher_path(home),
        prior_runtime_mcp,
    )
    if retired_clients:
        validate_runtime_mcp_configuration(
            home,
            retired_clients,
            runtime_launcher_path(home),
            prior_runtime_mcp,
        )
    credential_plan = prepare_credentials(args, repair_only=repair_only)
    recorded_tool_dirs: Iterable[str] = (
        prior_install.tool_dirs if prior_install else ()
    )
    tool_dirs = list(dict.fromkeys([*recorded_tool_dirs, str(user_tool_bin(home))]))
    if not args.skip_tool_install:
        install_bootstrap_tools(
            home,
            clients,
            tool_dirs,
            dry_run=args.dry_run,
            knowledge_mcp=manage_knowledge_mcp,
        )

    if prior_source is not None and prior_source_mode is not None:
        source = validate_source(prior_source, selected_bundle)
        source_mode = prior_source_mode
        if update and source_mode == "managed":
            if prior_install is not None and prior_install.ref_kind in {"tag", "commit"}:
                checkout_managed_release(
                    source,
                    args.repo_url,
                    args.ref,
                    args.dry_run,
                    bundle=selected_bundle,
                    expected_commit=prior_install.resolved_commit,
                )
            else:
                raise SetupError(
                    "managed source is not pinned to an immutable release; "
                    "rerun bootstrap with an immutable --ref"
                )
    else:
        expected_release_commit = (
            prior_install.resolved_commit
            if (
                prior_install is not None
                and prior_install.source_mode == "managed"
                and prior_install.ref_kind in {"tag", "commit"}
                and args.ref_explicit
                and str(args.ref) == prior_install.requested_ref
            )
            else None
        )
        source, source_mode = resolve_source(
            args,
            bundle=selected_bundle,
            expected_commit=expected_release_commit,
        )
    if update and source_mode == "managed" and source.exists() and not args.dry_run:
        source = validate_source(source, selected_bundle)
    if source_mode == "managed" and source.exists():
        release_state = validate_release_source(source, args.dry_run)
    elif source.exists():
        release_state = release_identity(
            source,
            source_mode="linked",
            dry_run=args.dry_run,
        )
    else:
        release_state = {
            "schema": "planned-release-lock",
            "immutable": source_mode == "managed",
        }
    planned_missing_source = (
        args.dry_run and source_mode == "managed" and not source.exists()
    )
    if not args.skip_tool_install:
        install_python_workflow_tools(
            home,
            source,
            tool_dirs,
            dry_run=args.dry_run,
        )
    knowledge_node: Path | None = None
    if manage_knowledge_mcp:
        if args.skip_tool_install:
            knowledge_node = resolve_node(home, tool_dirs) or (home / ".local" / "bin" / "node")
        else:
            knowledge_node = install_knowledge_dependencies(
                home,
                source,
                tool_dirs,
                dry_run=args.dry_run,
            )
    tool_dirs, missing_tools = resolve_tool_dirs(
        args.non_interactive,
        tool_dirs,
    )
    tooling = inspect_tooling(tool_dirs, clients)
    if not args.dry_run and not args.skip_tool_install:
        unresolved = list(missing_tools)
        unresolved.extend(
            tool
            for tool, available in tooling["conditional"].items()
            if not available
        )
        unresolved.extend(
            tool
            for tool, available in tooling["recommended"].items()
            if not available
        )
        if "codex" in clients and not tooling["clients"].get("codex", False):
            unresolved.append("codex")
        if unresolved:
            raise SetupError(
                "automatic workflow tool installation did not complete: "
                + ", ".join(sorted(set(unresolved)))
            )
    planned_source_commit = str(
        release_state.get("source_commit", "")
    ).strip() or (
        git_commit(source) if source.exists() else "planned"
    )
    runtime_plan = build_runtime_plan(
        home,
        source,
        source_commit=planned_source_commit,
        allow_missing_source=planned_missing_source,
    )
    knowledge_plan = (
        build_knowledge_plan(
            home,
            source,
            knowledge_node or (home / ".local" / "bin" / "node"),
            source_commit=planned_source_commit,
            allow_missing_source=planned_missing_source,
        )
        if manage_knowledge_mcp
        else {}
    )
    validate_link_plan(
        home,
        source,
        clients,
        allow_missing_targets=planned_missing_source,
        bundle=selected_bundle,
    )
    preserved_targets = resolve_preserved_link_targets(
        home,
        clients,
        preserved_skills,
        prior_install.links if prior_install is not None else None,
        prefer_recorded=(
            args.preserve_skills is None and prior_install is not None
        ),
    )
    backups = backup_path(home)
    if prior_install is not None and retired_clients:
        retire_legacy_client_state(
            home,
            prior_install,
            retired_clients,
            prior_mcp,
            prior_runtime_mcp,
            backups,
            args.dry_run,
        )
    active_prior_mcp = {
        client: record for client, record in prior_mcp.items() if client in clients
    }
    active_prior_runtime_mcp = {
        client: record
        for client, record in prior_runtime_mcp.items()
        if client in clients
    }
    migrate_legacy_mcp_names(
        home,
        clients,
        backups,
        args.dry_run,
        active_prior_mcp,
    )
    managed_links = install_links(
        home,
        source,
        clients,
        backups,
        args.dry_run,
        selected_bundle,
        preserved_targets,
    )
    profiles = install_environment_files(home, tool_dirs, backups, args.dry_run)
    credential_result = apply_credentials_plan(credential_plan, args.dry_run)
    runtime_state = deploy_runtime(runtime_plan, args.dry_run)
    if manage_knowledge_mcp:
        ensure_knowledge_config(home, args.kb_config, args.dry_run)
        knowledge_state = deploy_knowledge_mcp(knowledge_plan, args.dry_run)
    else:
        knowledge_state = {}
    mcp_state = (
        configure_knowledge_mcp(
            home,
            clients,
            Path(knowledge_state["launcher_path"]),
            backups,
            args.dry_run,
            active_prior_mcp,
            url=args.knowledge_url,
        )
        if manage_knowledge_mcp
        else dict(active_prior_mcp)
    )
    runtime_mcp_state = inherit_created_file_ownership(
        configure_runtime_mcp(
            home,
            clients,
            Path(runtime_state["launcher_path"]),
            backups,
            args.dry_run,
            active_prior_runtime_mcp,
        ),
        mcp_state,
    )
    current_source_commit = git_commit(source) if source.exists() else "planned"
    source_commit = (
        prior_install.source_commit
        if (
            args.command == "repair"
            and prior_install is not None
            and prior_install.source_commit
        )
        else current_source_commit
    )
    rollback_commit = (
        prior_install.source_commit
        if (
            prior_install is not None
            and source_commit != prior_install.source_commit
            and source_mode == "managed"
            and args.command in {"install", "update", "rollback"}
        )
        else (prior_install.rollback_commit if prior_install is not None else "")
    )
    if source_mode == "managed" and args.command == "rollback":
        ref_kind = "commit"
        requested_ref = source_commit
    else:
        ref_kind = (
            release_ref_kind(args.ref)
            if source_mode == "managed" and (args.ref_explicit or prior_install is None)
            else (
                prior_install.ref_kind
                if source_mode == "managed" and prior_install is not None
                else "linked"
            )
        )
        requested_ref = str(args.ref) if source_mode == "managed" else ""
    state_ref = requested_ref if source_mode == "managed" else args.ref
    state = {
        "version": STATE_VERSION,
        "repo_url": args.repo_url,
        "ref": state_ref,
        "requested_ref": requested_ref,
        "ref_kind": ref_kind,
        "source_root": str(source),
        "source_commit": source_commit,
        "resolved_commit": source_commit,
        "rollback_commit": rollback_commit,
        "source_dirty": (
            git_dirty(source, paths=bundle_git_paths(selected_bundle))
            if source.exists()
            else False
        ),
        "source_mode": source_mode,
        "managed_checkout": source_mode == "managed",
        "skill_profile": selected_profile,
        "clients": clients,
        "links": managed_links,
        "preserved_skills": list(preserved_skills),
        "profiles": profiles,
        "tool_dirs": tool_dirs,
        "mcp": mcp_state,
        "knowledge_mcp": knowledge_state,
        "runtime": runtime_state,
        "release": release_state,
        "runtime_mcp": runtime_mcp_state,
        "knowledge_url": args.knowledge_url or "",
        "target": args.target,
    }
    setattr(args, "_planned_workflow_state", state)
    setattr(args, "_tooling_report", tooling)
    setattr(args, "_credential_result", credential_result)
    save_state(home, state, args.dry_run)
    if args.skip_tool_install:
        if missing_tools:
            print(
                "warning: required workflow tools are missing from PATH: "
                + ", ".join(missing_tools)
            )
        if not tooling["conditional"]["sshpass"]:
            print(
                "warning: sshpass is missing; password SSH, remote log pulling, "
                "and Live Patch are unavailable"
            )
        if not tooling["recommended"]["rg"]:
            print(
                "warning: rg is missing; source evidence search will use a slower "
                "fallback"
            )
    if credential_result == "missing":
        _, credential_detail = credentials_status(credentials_path(home))
        print(
            "warning: credentials are incomplete "
            f"({credential_detail}); run the credentials command"
        )
    knowledge_report: dict[str, object]
    if manage_knowledge_mcp:
        external_clients, managed_stdio, managed_http = knowledge_mcp_transport_summary(
            clients,
            mcp_state,
        )
        if managed_stdio:
            healthy, detail, tools, configured = knowledge_mcp_health(
                Path(knowledge_state["launcher_path"]), home
            ) if not args.dry_run else (True, "planned", [], False)
            knowledge_report = {
                "managed": True,
                "healthy": healthy,
                "configured": configured,
                "transport": "stdio",
                "detail": detail,
                "tools": tools,
                "clients": managed_stdio,
            }
            print(f"{KNOWLEDGE_MCP_NAME}: {detail}")
        elif managed_http:
            healthy, detail = knowledge_http_health(str(args.knowledge_url))
            knowledge_report = {
                "managed": True,
                "healthy": healthy,
                "transport": "http",
                "detail": detail,
                "url": args.knowledge_url,
            }
            if healthy:
                print(f"{KNOWLEDGE_MCP_NAME}: {detail}")
            else:
                print(f"warning: {KNOWLEDGE_MCP_NAME} is unavailable: {detail}")
        elif external_clients:
            knowledge_report = {
                "managed": True,
                "healthy": True,
                "transport": "external-stdio",
                "detail": (
                    "external stdio configuration preserved; the client starts it "
                    "on demand"
                ),
                "clients": external_clients,
            }
            print(
                f"{KNOWLEDGE_MCP_NAME}: external stdio configuration preserved; "
                "the client starts it on demand"
            )
        else:
            knowledge_report = {
                "managed": True,
                "healthy": False,
                "transport": "unavailable",
                "detail": "no supported MCP client adapter",
            }
            print(
                f"warning: {KNOWLEDGE_MCP_NAME} has no supported MCP client adapter"
            )
    else:
        knowledge_report = {
            "managed": False,
            "healthy": False,
            "transport": "external",
            "detail": f"not managed by {selected_profile} profile",
        }
        print(f"{KNOWLEDGE_MCP_NAME}: not managed by {selected_profile} profile")
    setattr(args, "_knowledge_mcp_report", knowledge_report)
    completed_action = {
        "install": "installed",
        "repair": "repaired",
        "update": "updated",
        "refresh": "refreshed",
    }.get(args.command, "installed")
    planned_action = {
        "install": "would be installed",
        "repair": "would be repaired",
        "update": "would be updated",
        "refresh": "would be refreshed",
    }.get(args.command, "would be installed")
    print(
        f"openUBMC workflow {planned_action if args.dry_run else completed_action}: "
        f"skills={len(selected_bundle)} profile={selected_profile} "
        f"clients={','.join(clients)} source={source_mode} "
        f"commit={state['source_commit']}"
        + (
            " preserved=" + ",".join(preserved_skills)
            if preserved_skills
            else ""
        )
    )
    return 0


def check_toml_mcp(
    path: Path, url: str, record: dict[str, Any] | None = None
) -> bool:
    try:
        entry = toml_knowledge_mcp_entry(path)
    except (OSError, UnicodeError, SetupError):
        return False
    if record and record.get("ownership") == "external":
        return entry is not None
    if record and record.get("command"):
        return entry == {"transport": "stdio", "command": record.get("command")}
    return (
        entry is not None
        and entry.get("transport") == "http"
        and entry.get("url") == url
    )


def check_json_mcp(
    path: Path, url: str, record: dict[str, Any] | None = None
) -> bool:
    try:
        entry = json_mcp_entry(path)
    except SetupError:
        return False
    if not isinstance(entry, dict):
        return False
    if record and record.get("ownership") == "external":
        return True
    if record and record.get("command"):
        return entry == stdio_mcp_entry(str(record.get("command")))
    return entry.get("url") == url


def check_toml_runtime_mcp(path: Path, launcher: Path) -> bool:
    try:
        return toml_stdio_mcp_entry(path) == stdio_mcp_entry(launcher)
    except (OSError, UnicodeError, SetupError):
        return False


def check_json_runtime_mcp(path: Path, launcher: Path) -> bool:
    try:
        return json_named_mcp_entry(
            path,
            TARGET_RUNTIME_MCP_NAME,
        ) == stdio_mcp_entry(launcher)
    except SetupError:
        return False


def inspect_runtime_installation(state: dict[str, object]) -> dict[str, object]:
    recorded = state.get("runtime")
    if not isinstance(recorded, dict):
        return {
            "healthy": False,
            "matches_installed_state": False,
            "api_version": "unknown",
            "content_digest": "unknown",
            "detail": "Runtime state is missing; run openubmc-environment-setup repair",
        }
    package = Path(str(recorded.get("package_path", "")))
    launcher = Path(str(recorded.get("launcher_path", "")))
    manifest = Path(str(recorded.get("manifest_path", "")))
    expected_api = str(recorded.get("api_version", ""))
    expected_digest = str(recorded.get("content_digest", ""))
    try:
        actual_api = read_runtime_api_version(package)
        actual_digest = runtime_content_digest(package)
        actual_entrypoint_digest = file_content_digest(
            Path(str(recorded.get("mcp_entrypoint", ""))),
            domain=b"openubmc-mcp-entrypoint-v1" + bytes([0]),
        )
        manifest_document = json.loads(manifest.read_text(encoding="utf-8"))
        actual_composition = runtime_composition_files(
            Path(str(recorded.get("composition_source", "")))
        )
        launcher_content = launcher.read_text(encoding="utf-8")
    except (SetupError, OSError, UnicodeError, json.JSONDecodeError) as error:
        return {
            "healthy": False,
            "matches_installed_state": False,
            "api_version": "unknown",
            "content_digest": "unknown",
            "package_path": str(package),
            "launcher_path": str(launcher),
            "detail": f"{error}; run openubmc-environment-setup repair",
        }
    manifest_matches = isinstance(manifest_document, dict) and all(
        manifest_document.get(key) == recorded.get(key)
        for key in (
            "schema_version",
            "api_version",
            "content_digest",
            "package_path",
            "launcher_path",
            "mcp_entrypoint",
            "mcp_entrypoint_digest",
            "composition_source",
            "composition_files",
        )
    )
    launcher_ready = launcher.is_file() and not launcher.is_symlink() and os.access(
        launcher, os.X_OK
    )
    matches = (
        expected_api == TARGET_RUNTIME_API_VERSION
        and actual_api == expected_api
        and actual_digest == expected_digest
        and actual_entrypoint_digest == str(recorded.get("mcp_entrypoint_digest", ""))
        and manifest_matches
        and launcher_ready
        and launcher_content == render_runtime_launcher(recorded)
        and actual_composition == recorded.get("composition_files")
    )
    detail = (
        "ok"
        if matches
        else "Runtime API, digest, manifest, or launcher mismatch; "
        "run openubmc-environment-setup repair"
    )
    return {
        "healthy": matches,
        "matches_installed_state": matches,
        "api_version": actual_api,
        "content_digest": actual_digest,
        "mcp_entrypoint_digest": actual_entrypoint_digest,
        "expected_api_version": expected_api,
        "expected_content_digest": expected_digest,
        "package_path": str(package),
        "launcher_path": str(launcher),
        "manifest_path": str(manifest),
        "detail": detail,
    }


def runtime_mcp_health(
    launcher: Path,
    home: Path,
    timeout: float = 15.0,
) -> tuple[bool, str, list[str]]:
    if not launcher.is_file() or launcher.is_symlink() or not os.access(launcher, os.X_OK):
        return False, "launcher is missing or not executable", []
    requests = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
        '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":'
        '{"name":"openubmc-environment-setup","version":"1"}}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
    )
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    try:
        result = subprocess.run(
            [str(launcher)],
            input=requests,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error), []
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "launcher failed"
        return False, detail, []
    responses: dict[object, dict[str, object]] = {}
    try:
        for line in result.stdout.splitlines():
            document = json.loads(line)
            if isinstance(document, dict):
                responses[document.get("id")] = document
    except json.JSONDecodeError:
        return False, "MCP launcher returned invalid JSON", []
    initialize = responses.get(1, {}).get("result", {})
    tools_result = responses.get(2, {}).get("result", {})
    if not all(isinstance(value, dict) for value in (initialize, tools_result)):
        return False, "MCP initialize or tools/list response is missing", []
    server = initialize.get("serverInfo", {})
    if not isinstance(server, dict) or server.get("version") != TARGET_RUNTIME_API_VERSION:
        return False, "MCP Runtime API version mismatch", []
    tool_entries = tools_result.get("tools", [])
    if not isinstance(tool_entries, list):
        return False, "MCP tools/list result is invalid", []
    tools_found = sorted(
        str(entry.get("name"))
        for entry in tool_entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    )
    if tools_found != ["execute", "observe"]:
        return False, "MCP semantic Agent tools are incomplete", tools_found
    encoded_tools = json.dumps(tool_entries, separators=(",", ":")).encode("utf-8")
    if len(encoded_tools) > 8 * 1024:
        return False, "MCP tools/list exceeds the 8KB Agent budget", tools_found
    return True, f"ok ({len(tools_found)} semantic tools)", tools_found


def knowledge_mcp_health(
    launcher: Path,
    home: Path,
    timeout: float = 15.0,
) -> tuple[bool, str, list[str], bool]:
    if not launcher.is_file() or launcher.is_symlink() or not os.access(launcher, os.X_OK):
        return False, "launcher is missing or not executable", [], False
    requests = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
        '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":'
        '{"name":"openubmc-environment-setup","version":"1"}}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
        '{"name":"openubmc_kb_status","arguments":{}}}\n'
    )
    environment = {**os.environ, "HOME": str(home)}
    try:
        result = subprocess.run(
            [str(launcher)],
            input=requests,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error), [], False
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "launcher failed"
        return False, detail, [], False
    responses: dict[object, dict[str, object]] = {}
    try:
        for line in result.stdout.splitlines():
            document = json.loads(line)
            if isinstance(document, dict):
                responses[document.get("id")] = document
    except json.JSONDecodeError:
        return False, "MCP launcher returned invalid JSON", [], False
    initialize = responses.get(1, {}).get("result", {})
    tools_result = responses.get(2, {}).get("result", {})
    status_result = responses.get(3, {}).get("result", {})
    if not all(isinstance(value, dict) for value in (initialize, tools_result, status_result)):
        return False, "MCP initialize, tools/list, or status response is missing", [], False
    server = initialize.get("serverInfo", {})
    if not isinstance(server, dict) or server.get("version") != KNOWLEDGE_MCP_VERSION:
        return False, "openUBMC KB MCP version mismatch", [], False
    entries = tools_result.get("tools", [])
    if not isinstance(entries, list):
        return False, "openUBMC KB MCP tools/list result is invalid", [], False
    tools_found = sorted(
        str(entry.get("name"))
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    )
    required = {"openubmc_kb_query", "openubmc_kb_status", "openubmc_kb_list"}
    if not required.issubset(tools_found):
        return False, "openUBMC KB MCP tools are incomplete", tools_found, False
    if status_result.get("isError") is True:
        return False, "openUBMC KB status call failed", tools_found, False
    structured = status_result.get("structuredContent")
    payload = structured.get("result") if isinstance(structured, Mapping) else None
    configured = bool(payload.get("configured")) if isinstance(payload, Mapping) else False
    return True, f"ok ({len(tools_found)} read-only tools; configured={str(configured).lower()})", tools_found, configured


def collect_check_report(args: argparse.Namespace) -> dict[str, Any]:
    home = args.home.expanduser().absolute()
    checks: list[dict[str, Any]] = []
    messages: list[str] = []

    def record(
        name: str,
        ok: bool,
        detail: str,
        message: str,
        *,
        category: str = "core",
        blocking: bool = True,
    ) -> None:
        checks.append(
            {
                "name": name,
                "ok": ok,
                "detail": detail,
                "category": category,
                "blocking": blocking,
            }
        )
        messages.append(message)

    try:
        state = load_state(home)
    except SetupError as error:
        readiness = CheckReadiness(False, False, False, False)
        record(
            "state",
            False,
            str(error),
            f"state: missing or invalid ({error})",
        )
        return {
            **readiness.top_level_fields(),
            "readiness": {
                "core": False,
                "credentials": False,
                "runtime": False,
                "mcp": False,
                "engine": False,
                "knowledge": False,
                "studio": False,
                "tooling": False,
                "client": False,
                "password_ssh": False,
                "source_search": False,
                **readiness.readiness_fields(),
            },
            "source": {"mode": "unknown"},
            "runtime": {"healthy": False, "detail": "not checked"},
            "runtime_mcp": {"healthy": False, "detail": "not checked", "tools": []},
            "engines": {"mcp": False, "cli": False, "one_shot": False},
            "tooling": {
                "ready": False,
                "client_ready": False,
                "required": {},
                "conditional": {},
                "recommended": {},
                "clients": {},
            },
            "next_actions": [],
            "checks": checks,
            "knowledge_mcp": {"healthy": False, "detail": "not checked"},
            "studio": {"healthy": False, "detail": "not checked"},
            "_messages": messages,
        }

    try:
        selected_policy = skill_profile_from_state(state)
        selected_profile = selected_policy.name
        selected_bundle = selected_policy.bundle
        record(
            "skill_profile",
            True,
            selected_profile,
            f"Skill profile: {selected_profile}",
        )
    except SetupError as error:
        selected_policy = resolve_skill_profile(DEFAULT_SKILL_PROFILE)
        selected_profile = selected_policy.name
        selected_bundle = selected_policy.bundle
        record(
            "skill_profile",
            False,
            str(error),
            f"Skill profile: invalid ({error})",
        )
    manage_knowledge_mcp = selected_policy.manages_knowledge_mcp
    try:
        preserved_skills = parse_preserved_skills(
            ",".join(recorded_string_list(state, "preserved_skills")),
            selected_bundle,
        )
        record(
            "preserved_skills",
            True,
            ", ".join(preserved_skills) if preserved_skills else "none",
            "preserved Skills: "
            + (", ".join(preserved_skills) if preserved_skills else "none"),
        )
    except SetupError as error:
        preserved_skills = ()
        record(
            "preserved_skills",
            False,
            str(error),
            f"preserved Skills: invalid ({error})",
        )

    try:
        source = source_root_from_state(state)
    except SetupError as error:
        source = home / ".invalid-openubmc-source"
        record(
            "source_root",
            False,
            str(error),
            f"source root: invalid ({error})",
        )
    try:
        source_mode = source_mode_from_state(state)
        record(
            "source_mode",
            True,
            source_mode,
            f"source mode: {source_mode}",
        )
    except SetupError as error:
        source_mode = "unknown"
        record(
            "source_mode",
            False,
            str(error),
            f"source mode: invalid ({error})",
        )
    expected_commit = str(state.get("source_commit", ""))
    requested_ref = str(state.get("requested_ref", state.get("ref", "")))
    resolved_commit = str(
        state.get("resolved_commit", state.get("source_commit", ""))
    )
    ref_kind = "unknown"
    source_revision_ok = False
    try:
        ref_kind = ref_kind_from_state(state, source_mode)
        if source_mode == "managed" and ref_kind == "legacy-branch":
            raise SetupError(
                "mutable legacy branch source; rerun bootstrap with an immutable --ref"
            )
        if source_mode == "managed" and ref_kind in {"tag", "commit"}:
            if release_ref_kind(requested_ref) != ref_kind:
                raise SetupError(
                    "recorded requested ref does not match its immutable ref kind"
                )
            if not FULL_COMMIT.fullmatch(resolved_commit):
                raise SetupError("recorded resolved release commit is not complete")
            if resolved_commit.lower() != expected_commit.lower():
                raise SetupError(
                    "recorded resolved commit does not match source commit"
                )
        record(
            "source_revision",
            True,
            f"{ref_kind} {requested_ref or resolved_commit}",
            f"source revision: {ref_kind} {requested_ref or resolved_commit}",
        )
        source_revision_ok = True
    except SetupError as error:
        record(
            "source_revision",
            False,
            str(error),
            f"source revision: invalid ({error})",
        )
    try:
        validate_source(source, selected_bundle)
        source_valid = True
        record("source", True, str(source), f"source: ok ({source})")
    except SetupError as error:
        source_valid = False
        record("source", False, str(error), f"source: failed ({error})")

    actual_commit = git_commit(source) if source.exists() else "missing"
    commit_ok = not expected_commit or actual_commit == expected_commit
    if not commit_ok:
        record(
            "source_commit",
            False,
            f"installed={expected_commit}, current={actual_commit}",
            f"source commit: changed (installed={expected_commit}, current={actual_commit})",
        )
    else:
        record(
            "source_commit",
            True,
            actual_commit,
            f"source commit: {actual_commit}",
        )

    dirty_paths = None if args.deep else bundle_git_paths(selected_bundle)
    dirty = git_dirty(source, paths=dirty_paths) if source.exists() else False
    dirty_scope = "full" if args.deep else "bundle"
    if dirty and source_mode == "managed":
        record(
            "source_worktree",
            False,
            f"dirty managed checkout ({dirty_scope} scope)",
            "source worktree: dirty managed checkout",
        )
    elif dirty:
        record(
            "source_worktree",
            False,
            f"dirty linked checkout ({dirty_scope} scope)",
            "source worktree: dirty user-managed checkout (non-blocking)",
            blocking=False,
        )
    else:
        record(
            "source_worktree",
            True,
            f"clean ({dirty_scope} scope)",
            "source worktree: clean",
        )

    release_report: dict[str, object] = {}
    try:
        actual_release = release_identity(
            source,
            source_mode=("managed" if source_mode == "managed" else "linked"),
            dry_run=False,
        )
        release_report = dict(actual_release)
        recorded_release = recorded_object(state, "release")
        expected_lock = str(recorded_release.get("lock_digest", ""))
        actual_lock = str(actual_release.get("lock_digest", ""))
        if expected_lock and actual_lock != expected_lock:
            raise SetupError(
                "installed release lock identity changed: "
                f"expected={expected_lock}, actual={actual_lock or 'missing'}"
            )
        identity_valid = not actual_release.get("validation_error")
        immutable = bool(actual_release.get("immutable")) and identity_valid
        release_detail = (
            f"{actual_release.get('release_version', '')} "
            f"{actual_release.get('lock_digest', actual_release.get('schema', ''))}"
        ).strip()
        record(
            "release_identity",
            immutable,
            release_detail,
            "release identity: " + release_detail,
            blocking=source_mode == "managed",
        )
    except SetupError as error:
        release_report = {
            "schema": "invalid-release-identity",
            "immutable": False,
            "validation_error": str(error),
        }
        record(
            "release_identity",
            False,
            str(error),
            f"release identity: invalid ({error})",
            blocking=source_mode == "managed",
        )

    runtime_report = inspect_runtime_installation(state)
    runtime_ok = bool(runtime_report.get("healthy"))
    record(
        "target_runtime",
        runtime_ok,
        str(runtime_report.get("detail", "unknown")),
        "Target Runtime: " + str(runtime_report.get("detail", "unknown")),
    )

    client_values = state.get("clients", [])
    if not isinstance(client_values, list) or not client_values:
        clients = []
        record("clients", False, "missing or invalid", "clients: missing or invalid")
    else:
        invalid_clients = [
            repr(client)
            for client in client_values
            if not isinstance(client, str) or client not in CLIENTS
        ]
        clients = [
            client
            for client in client_values
            if isinstance(client, str) and client in CLIENTS
        ]
        if invalid_clients:
            detail = "invalid entries: " + ", ".join(invalid_clients)
            record("clients", False, detail, "clients: " + detail)
        else:
            detail = ", ".join(map(str, clients))
            record("clients", True, detail, "clients: " + detail)

    try:
        links = recorded_string_mapping(state, "links")
    except SetupError as error:
        links = {}
        record("link_state", False, str(error), f"link state: invalid ({error})")
    expected_links = [
        (
            str(client_skills_dir(home, str(client)) / canonical),
            canonical,
            relative,
        )
        for client in clients
        if client in CLIENTS
        for canonical, relative in selected_bundle
    ]
    for link_text, canonical, relative in sorted(expected_links):
        link = Path(link_text)
        preserved = canonical in preserved_skills
        recorded_target = links.get(link_text, "")
        target_text = recorded_target if preserved else str(source / relative)
        target = Path(target_text) if target_text else source / relative
        if not recorded_target or recorded_target != target_text:
            record(
                f"link:{link}",
                False,
                "missing from installer state",
                f"link {link}: missing from installer state",
            )
            continue
        if preserved and not valid_preserved_skill_target(target):
            record(
                f"link:{link}",
                False,
                f"preserved target unavailable: {target}",
                f"link {link}: preserved target unavailable ({target})",
            )
            continue
        if same_target(link, target):
            detail = f"preserved: {target}" if preserved else "ok"
            record(f"link:{link}", True, detail, f"link {link}: {detail}")
        else:
            record(
                f"link:{link}",
                False,
                "missing or stale",
                f"link {link}: missing or stale",
            )
    for client in clients:
        if client not in CLIENTS:
            continue
        for retired_name, relative in RETIRED_SKILL_LINKS:
            retired = client_skills_dir(home, str(client)) / retired_name
            if same_target(retired, source / relative):
                record(
                    f"retired_link:{retired}",
                    False,
                    "still present",
                    f"retired link {retired}: still present",
                )
        legacy = client_skills_dir(home, str(client)) / "openubmc-environment"
        if legacy.is_symlink():
            record(
                f"legacy_link:{legacy}",
                False,
                "still present",
                f"legacy link {legacy}: still present",
            )

    try:
        tool_dirs = list(recorded_string_list(state, "tool_dirs"))
    except SetupError as error:
        tool_dirs = []
        record(
            "tool_directories",
            False,
            str(error),
            f"tool directories: invalid state ({error})",
        )
    config_dir = openubmc_config_dir(home)
    config_dir_ok = (
        config_dir.is_dir()
        and not config_dir.is_symlink()
        and config_dir.stat().st_uid == os.getuid()
        and stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    )
    config_detail = "ok" if config_dir_ok else "missing or unsafe"
    record(
        "configuration_directory",
        config_dir_ok,
        config_detail,
        f"configuration directory: {config_detail}",
    )
    env_file = config_dir / "env.sh"
    expected_env = render_env(map(str, tool_dirs))
    env_ok = (
        env_file.is_file()
        and not env_file.is_symlink()
        and stat.S_IMODE(env_file.stat().st_mode) == 0o600
        and env_file.read_text(encoding="utf-8") == expected_env
    )
    env_detail = "ok" if env_ok else "missing, changed, or unsafe"
    record("environment_hook", env_ok, env_detail, f"environment hook: {env_detail}")

    profile_values = state.get("profiles", [])
    if not isinstance(profile_values, list):
        profiles = []
        record(
            "profiles",
            False,
            "invalid state",
            "profiles: invalid state",
        )
    else:
        invalid_profiles = [
            repr(profile)
            for profile in profile_values
            if not isinstance(profile, str)
        ]
        profiles = [
            profile for profile in profile_values if isinstance(profile, str)
        ]
        if invalid_profiles:
            detail = "invalid entries: " + ", ".join(invalid_profiles)
            record("profiles", False, detail, "profiles: " + detail)
    required_profiles = {str(home / ".bashrc"), str(home / ".profile")}
    if not required_profiles.issubset(set(map(str, profiles))):
        record(
            "profiles",
            False,
            "installer state is incomplete",
            "profiles: installer state is incomplete",
        )
    for profile_text in profiles:
        profile = Path(profile_text)
        content = profile.read_text(encoding="utf-8", errors="ignore") if profile.is_file() else ""
        installed = (
            not profile.is_symlink()
            and content.count(MARKER_START) == 1
            and content.count(MARKER_END) == 1
            and OLD_MARKER_START not in content
            and LEGACY_CREDENTIALS_START not in content
        )
        detail = "ok" if installed else "missing hook"
        record(f"profile:{profile}", installed, detail, f"profile {profile}: {detail}")

    credentials_ok, credentials_detail = credentials_status(credentials_path(home))
    record(
        "credentials",
        credentials_ok,
        credentials_detail,
        f"credentials: {credentials_detail}",
        category="credentials",
    )
    tooling = inspect_tooling(map(str, tool_dirs), clients)
    for tool, available in tooling["required"].items():
        detail = "ok" if available else "missing"
        record(f"tool:{tool}", available, detail, f"tool {tool}: {detail}")
    for tool, available in tooling["conditional"].items():
        detail = "ok" if available else CONDITIONAL_TOOLS[tool]
        record(
            f"tool:{tool}",
            available,
            detail,
            f"tool {tool}: {detail}",
            category="tooling",
            blocking=False,
        )
    for tool, available in tooling["recommended"].items():
        detail = "ok" if available else RECOMMENDED_TOOLS[tool]
        record(
            f"tool:{tool}",
            available,
            detail,
            f"tool {tool}: {detail}",
            category="tooling",
            blocking=False,
        )
    for client, available in tooling["clients"].items():
        detail = (
            "ok"
            if available
            else (
                "missing; Skill and MCP configuration is staged, but the client "
                "cannot be launched directly in this environment"
            )
        )
        record(
            f"client:{client}",
            available,
            detail,
            f"client {client}: {detail}",
            category="client",
            blocking=False,
        )

    def state_record_map(key: str, label: str) -> dict[str, Any]:
        try:
            return recorded_client_records(state, key)
        except SetupError as error:
            record(key, False, str(error), f"{label} state: invalid ({error})")
            return {}

    url = str(state.get("knowledge_url", state.get("studio_url", "")))
    knowledge_mcp_state = state_record_map("mcp", "openUBMC KB MCP")
    runtime_mcp_state = state_record_map("runtime_mcp", "Target Runtime MCP")
    configured_external: list[str] = []
    configured_managed_stdio: list[str] = []
    configured_managed_http: list[str] = []
    if manage_knowledge_mcp:
        for client in clients:
            if (
                client in SUPPORTED_MCP_CLIENTS
                and not valid_client_ownership_record(
                    knowledge_mcp_state.get(client)
                )
            ):
                detail = "ownership missing or invalid in installer state; run repair"
                record(
                    f"mcp:{client}",
                    False,
                    detail,
                    f"mcp {client}: {detail}",
                )
                continue
            client_record = knowledge_mcp_state.get(client, {})
            if not isinstance(client_record, dict):
                client_record = {}
            if client == "codex":
                configured = check_toml_mcp(
                    home / ".codex" / "config.toml", url, client_record
                )
            elif client == "claude":
                configured = check_json_mcp(home / ".claude.json", url, client_record)
            else:
                record(
                    "mcp:openclaw",
                    False,
                    "adapter unavailable",
                    "mcp openclaw: adapter unavailable (non-blocking)",
                    blocking=False,
                )
                continue
            external = client_record.get("ownership") == "external"
            detail = "external (preserved)" if configured and external else (
                "ok" if configured else "missing or stale"
            )
            record(f"mcp:{client}", configured, detail, f"mcp {client}: {detail}")
            if configured and external:
                configured_external.append(client)
            elif configured and client_record.get("command"):
                configured_managed_stdio.append(client)
            elif configured and client in SUPPORTED_MCP_CLIENTS:
                configured_managed_http.append(client)
    else:
        record(
            "knowledge_configuration",
            True,
            "not managed by this profile",
            (
                f"{KNOWLEDGE_MCP_NAME} configuration: not managed by "
                f"{selected_profile} profile"
            ),
            category="knowledge",
            blocking=False,
        )

    launcher = Path(str(runtime_report.get("launcher_path", runtime_launcher_path(home))))
    runtime_mcp_configured = True
    for client in clients:
        if (
            client in SUPPORTED_MCP_CLIENTS
            and not valid_client_ownership_record(
                runtime_mcp_state.get(client)
            )
        ):
            configured = False
            config_detail = (
                "ownership missing or invalid in installer state; run repair"
            )
        elif client == "codex":
            configured = check_toml_runtime_mcp(
                home / ".codex" / "config.toml", launcher
            )
            config_detail = "ok" if configured else "missing or stale"
        elif client == "claude":
            configured = check_json_runtime_mcp(home / ".claude.json", launcher)
            config_detail = "ok" if configured else "missing or stale"
        else:
            record(
                "runtime_mcp:openclaw",
                False,
                "adapter unavailable",
                "Target Runtime MCP openclaw: adapter unavailable (non-blocking)",
                blocking=False,
            )
            continue
        runtime_mcp_configured = runtime_mcp_configured and configured
        record(
            f"runtime_mcp:{client}",
            configured,
            config_detail,
            f"Target Runtime MCP {client}: {config_detail}",
        )

    if runtime_ok:
        runtime_mcp_healthy, runtime_mcp_detail, runtime_tools = runtime_mcp_health(
            launcher, home
        )
    else:
        runtime_mcp_healthy, runtime_mcp_detail, runtime_tools = (
            False,
            "Runtime installation is not ready",
            [],
        )
    runtime_mcp_ready = runtime_mcp_configured and runtime_mcp_healthy
    record(
        "runtime_mcp_health",
        runtime_mcp_ready,
        runtime_mcp_detail,
        f"Target Runtime MCP health: {runtime_mcp_detail}",
    )

    if "openubmc-debug" in preserved_skills:
        debug_roots = {
            Path(links[str(client_skills_dir(home, client) / "openubmc-debug")])
            for client in clients
            if str(client_skills_dir(home, client) / "openubmc-debug") in links
        }
    else:
        debug_roots = {source / "openubmc-debug"}
    context_cli_ready = bool(debug_roots) and all(
        (debug_root / relative).is_file()
        for debug_root in debug_roots
        for relative in (
            "scripts/_target_runtime_adapter.py",
            "scripts/target_runtime_cli.py",
            "scripts/target_runtime_mcp.py",
            "scripts/workflow_remote.py",
        )
    )
    context_cli_detail = (
        "ok" if context_cli_ready else "missing Debug Context Runtime CLI adapter"
    )
    record(
        "context_cli_engine",
        context_cli_ready,
        context_cli_detail,
        f"Target Runtime Context CLI: {context_cli_detail}",
    )
    engine_ready = runtime_mcp_ready or context_cli_ready
    if manage_knowledge_mcp:
        if configured_managed_stdio:
            knowledge_state = state.get("knowledge_mcp", {})
            knowledge_launcher = Path(
                str(
                    knowledge_state.get("launcher_path", knowledge_launcher_path(home))
                    if isinstance(knowledge_state, Mapping)
                    else knowledge_launcher_path(home)
                )
            )
            healthy, detail, knowledge_tools, configured_credentials = knowledge_mcp_health(
                knowledge_launcher, home
            )
            health_text = detail if healthy else "unavailable (non-blocking): " + detail
            knowledge_report = {
                "managed": True,
                "healthy": healthy,
                "configured": configured_credentials,
                "transport": "stdio",
                "detail": detail,
                "tools": knowledge_tools,
                "clients": configured_managed_stdio,
            }
        elif configured_managed_http:
            healthy, detail = knowledge_http_health(url)
            health_text = detail if healthy else "unavailable (non-blocking): " + detail
            knowledge_report: dict[str, object] = {
                "url": url,
                "managed": True,
                "healthy": healthy,
                "transport": "http",
                "detail": detail,
            }
        elif configured_external:
            healthy = True
            detail = (
                "external stdio configuration preserved for "
                + ", ".join(configured_external)
                + "; the client starts it on demand"
            )
            health_text = detail
            knowledge_report = {
                "url": url,
                "managed": True,
                "healthy": True,
                "transport": "external-stdio",
                "detail": detail,
                "clients": configured_external,
            }
        else:
            healthy = False
            detail = "no supported MCP client adapter is configured"
            health_text = "unavailable (non-blocking): " + detail
            knowledge_report = {
                "url": url,
                "managed": True,
                "healthy": False,
                "transport": "unavailable",
                "detail": detail,
            }
        record(
            "knowledge_health",
            healthy,
            detail,
            f"{KNOWLEDGE_MCP_NAME} health: {health_text}",
            category="knowledge",
            blocking=False,
        )
    else:
        healthy = False
        detail = f"not managed by {selected_profile} profile"
        knowledge_report = {
            "url": url,
            "managed": False,
            "healthy": False,
            "transport": "external",
            "detail": detail,
        }

    core_ok = all(
        check["ok"]
        for check in checks
        if check["category"] == "core" and check["blocking"]
    )
    installation_ok = core_ok and credentials_ok
    operational_ready = (
        credentials_ok and runtime_ok and runtime_mcp_ready and engine_ready
    )
    release_identity_verified = bool(
        source_mode == "managed"
        and ref_kind in {"tag", "commit"}
        and source_revision_ok
        and commit_ok
        and release_report.get("immutable")
        and release_report.get("schema")
        == "openubmc-agent-workflow.release-lock.v1"
        and not release_report.get("validation_error")
    )
    readiness = CheckReadiness(
        installation_ok=installation_ok,
        operational_ready=operational_ready,
        release_identity_verified=release_identity_verified,
        evaluation_ready=(
            installation_ok and operational_ready and release_identity_verified
        ),
    )
    release_report["verified"] = release_identity_verified
    release_report["trust_mode"] = (
        "verified-immutable-source"
        if release_identity_verified
        else (
            "linked-development"
            if source_mode == "linked"
            else "unverified-managed-source"
        )
    )
    repo_url = str(state.get("repo_url", DEFAULT_REPO_URL))
    remediation_command = immutable_release_remediation_command(
        repo_url=repo_url,
        source_mode=source_mode,
        requested_ref=requested_ref,
        ref_kind=ref_kind,
    )
    release_actions = (
        []
        if release_identity_verified
        else [
            {
                "code": "install_immutable_release",
                "required": source_mode == "managed",
                "detail": (
                    "Use a managed installation pinned to an immutable tag or full "
                    "commit before Release qualification."
                ),
                "command": remediation_command,
            }
        ]
    )
    return {
        **readiness.top_level_fields(),
        "readiness": {
            "core": core_ok,
            "credentials": credentials_ok,
            "runtime": runtime_ok,
            "mcp": runtime_mcp_ready,
            "engine": engine_ready,
            "knowledge": healthy,
            "studio": healthy,
            "tooling": bool(tooling["ready"]),
            "client": bool(tooling["client_ready"]),
            "password_ssh": bool(tooling["conditional"]["sshpass"]),
            "source_search": bool(tooling["recommended"]["rg"]),
            **readiness.readiness_fields(),
        },
        "source": {
            "path": str(source),
            "mode": source_mode,
            "valid": source_valid,
            "requested_ref": requested_ref,
            "ref_kind": ref_kind,
            "resolved_commit": resolved_commit,
            "expected_commit": expected_commit,
            "current_commit": actual_commit,
            "dirty": dirty,
            "dirty_scope": dirty_scope,
        },
        "skill_profile": selected_profile,
        "preserved_skills": list(preserved_skills),
        "clients": [str(client) for client in clients],
        "runtime": runtime_report,
        "release": release_report,
        "runtime_mcp": {
            "healthy": runtime_mcp_ready,
            "configured": runtime_mcp_configured,
            "detail": runtime_mcp_detail,
            "tools": runtime_tools,
        },
        "engines": {
            "mcp": runtime_mcp_ready,
            "cli": context_cli_ready,
            "one_shot": context_cli_ready,
        },
        "tooling": tooling,
        "next_actions": [
            *tooling_next_actions(
                tooling,
                credentials_ok=credentials_ok,
            ),
            *knowledge_next_actions(knowledge_report),
            *release_actions,
        ],
        "checks": checks,
        "knowledge_mcp": knowledge_report,
        "studio": knowledge_report,
        "_messages": messages,
    }


def perform_check(args: argparse.Namespace) -> int:
    report = collect_check_report(args)
    messages = report.pop("_messages", [])
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for message in messages:
            print(message)
        print(
            "operational readiness: "
            + ("ready" if report["operational_ready"] else "not ready")
        )
        release = report.get("release", {})
        trust_mode = (
            str(release.get("trust_mode", "unknown"))
            if isinstance(release, Mapping)
            else "unknown"
        )
        print(f"release trust mode: {trust_mode}")
        print(
            "release identity verified: "
            + ("yes" if report["release_identity_verified"] else "no")
        )
        print(
            "evaluation readiness: "
            + ("ready" if report["evaluation_ready"] else "not ready")
        )
        for action in report.get("next_actions", []):
            if not isinstance(action, Mapping):
                continue
            if action.get("code") != "install_immutable_release":
                continue
            detail = str(action.get("detail", "")).strip()
            if detail:
                print(f"next action: {detail}")
            command = str(action.get("command", "")).strip()
            if command:
                print(f"command: {command}")
    return 0 if report["ok"] else 1


def restore_recorded_lifecycle(
    args: argparse.Namespace,
) -> RecordedInstall:
    home = args.home.expanduser().absolute()
    recorded = decode_recorded_install(load_state(home))
    if args.command in {"update", "rollback"} and recorded.source_mode != "managed":
        raise SetupError(
            "source is linked; update or restore the checkout yourself, then use refresh"
        )
    if args.command in {"repair", "update"} and recorded.ref_kind == "legacy-branch":
        raise SetupError(
            "managed source uses a mutable legacy branch; "
            "rerun bootstrap with an immutable --ref"
        )
    if args.command == "refresh" and recorded.source_mode != "linked":
        raise SetupError("source is installer-managed; use update instead of refresh")
    if args.command not in {"repair", "update", "rollback", "refresh"}:
        raise SetupError(f"unsupported recorded lifecycle command: {args.command}")

    args.home = home
    args.source = None
    args.repo_url = recorded.repo_url
    args.ref = recorded.ref
    args.clients = "codex"
    args.skill_profile = recorded.profile.name
    args.knowledge_url = recorded.knowledge_url
    args.target = recorded.target
    args.skip_credentials = True
    return recorded


def perform_recorded_lifecycle(args: argparse.Namespace) -> int:
    recorded = restore_recorded_lifecycle(args)
    if args.command == "rollback":
        if not recorded.rollback_commit:
            raise SetupError("no previous known-good managed revision is recorded")
        checkout_managed_revision(
            recorded.source_root,
            recorded.rollback_commit,
            args.dry_run,
            recorded.profile.bundle,
        )
    return perform_install(
        args,
        update=args.command == "update",
        recorded_state=recorded,
        repair_only=True,
    )


def perform_repair(args: argparse.Namespace) -> int:
    return perform_recorded_lifecycle(args)


def perform_update(args: argparse.Namespace) -> int:
    return perform_recorded_lifecycle(args)


def perform_rollback(args: argparse.Namespace) -> int:
    return perform_recorded_lifecycle(args)


def perform_refresh(args: argparse.Namespace) -> int:
    return perform_recorded_lifecycle(args)


def perform_credentials(args: argparse.Namespace) -> int:
    home = args.home.expanduser().absolute()
    args.home = home
    validate_openubmc_config_dir(home)
    if args.kb or args.kb_config is not None:
        if args.kb_config is not None:
            result = ensure_knowledge_config(home, args.kb_config, args.dry_run)
        else:
            if args.non_interactive or not sys.stdin.isatty():
                raise SetupError("openUBMC KB credential configuration requires a TTY or --kb-config")
            path = knowledge_config_path(home)
            document = default_knowledge_config()
            if path.is_file() and not path.is_symlink():
                try:
                    current = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise SetupError(f"invalid openUBMC KB configuration: {path}") from error
                if isinstance(current, dict):
                    document.update(current)
            current_username = str(document.get("username", "")).strip()
            prompt = "openUBMC OneID username"
            if current_username:
                prompt += f" [{current_username}]"
            username = input(prompt + ": ").strip() or current_username
            password = getpass.getpass("openUBMC OneID password: ")
            if not username or not password:
                raise SetupError("openUBMC KB username and password are required")
            document["username"] = username
            document["password"] = password
            if args.dry_run:
                print(f"would update openUBMC KB credentials in {path}")
            else:
                atomic_write(
                    path,
                    json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    0o600,
                )
            result = "configured"
        print(f"openUBMC KB credentials: {result}")
        return 0
    result = apply_credentials_plan(prepare_credentials(args), args.dry_run)
    print(f"credentials: {result}")
    return 0


def perform_uninstall(args: argparse.Namespace) -> int:
    home = args.home.expanduser().absolute()
    state = load_state(home)
    recorded = decode_recorded_install(state)
    missing_ownership = missing_client_ownership_records(recorded)
    if missing_ownership:
        raise SetupError(
            "installer state has missing or invalid client ownership records: "
            + ", ".join(missing_ownership)
            + "; run repair before uninstalling"
        )
    backups = backup_path(home)
    links = recorded.links
    preserved_link_paths = {
        str(client_skills_dir(home, client) / canonical)
        for client in recorded.clients
        if client in KNOWN_CLIENTS
        for canonical in recorded.preserved_skills
    }
    managed_link_paths: set[str] = set()
    for link_text, target_text in sorted(links.items()):
        link = Path(link_text)
        target = Path(target_text)
        if link_text in preserved_link_paths:
            if same_target(link, target):
                print(f"preserving external Skill link {link}")
            continue
        if same_target(link, target):
            managed_link_paths.add(str(link))
            if args.dry_run:
                print(f"would remove managed link {link}")
            else:
                link.unlink()
    for profile_text in recorded.profiles:
        profile = Path(profile_text)
        if not profile.is_file() or profile.is_symlink():
            continue
        original = profile.read_text(encoding="utf-8", errors="ignore")
        updated = remove_profile_hook(original)
        if updated != original:
            backup_file(profile, backups, args.dry_run)
            if args.dry_run:
                print(f"would remove environment hook from {profile}")
            else:
                atomic_write(profile, updated, None)
    env_file = openubmc_config_dir(home) / "env.sh"
    if env_file.is_file() and not env_file.is_symlink():
        expected = render_env(recorded.tool_dirs)
        if env_file.read_text(encoding="utf-8", errors="ignore") != expected:
            print(f"warning: preserving changed environment file {env_file}")
        elif args.dry_run:
            print(f"would remove {env_file}")
        else:
            env_file.unlink()
    for client in recorded.clients:
        record = recorded.mcp.get(client, {})
        runtime_record = recorded.runtime_mcp.get(client, {})
        if client == "codex":
            if recorded.profile.manages_knowledge_mcp:
                remove_toml_knowledge_mcp(
                    home / ".codex" / "config.toml",
                    record,
                    backups,
                    args.dry_run,
                )
            remove_toml_stdio_mcp(
                home / ".codex" / "config.toml",
                runtime_record,
                backups,
                args.dry_run,
            )
        elif client == "claude":
            if recorded.profile.manages_knowledge_mcp:
                remove_json_knowledge_mcp(
                    home / ".claude.json",
                    record,
                    backups,
                    args.dry_run,
                )
            remove_json_stdio_mcp(
                home / ".claude.json", runtime_record, backups, args.dry_run
            )
    runtime_state = recorded.runtime
    if runtime_state:
        install_root = runtime_install_root(home)
        recorded_package = Path(str(runtime_state.get("package_path", "")))
        recorded_launcher = Path(str(runtime_state.get("launcher_path", "")))
        if (
            recorded_package == runtime_package_path(home)
            and recorded_launcher == runtime_launcher_path(home)
        ):
            if install_root.is_symlink():
                print(f"warning: preserving unexpected Target Runtime symlink {install_root}")
            elif install_root.exists():
                if args.dry_run:
                    print(f"would remove Target Runtime installation {install_root}")
                else:
                    shutil.rmtree(install_root)
    if recorded.profile.manages_knowledge_mcp:
        install_root = knowledge_install_root(home)
        knowledge_state = state.get("knowledge_mcp", {})
        recorded_launcher = Path(
            str(knowledge_state.get("launcher_path", ""))
            if isinstance(knowledge_state, Mapping)
            else ""
        )
        if recorded_launcher == knowledge_launcher_path(home):
            if install_root.is_symlink():
                print(f"warning: preserving unexpected openUBMC KB MCP symlink {install_root}")
            elif install_root.exists():
                if args.dry_run:
                    print(f"would remove openUBMC KB MCP installation {install_root}")
                else:
                    shutil.rmtree(install_root)
    if args.purge_credentials:
        for path in (credentials_path(home), knowledge_config_path(home)):
            if path.is_file() and not path.is_symlink():
                if args.dry_run:
                    print(f"would remove credentials {path}")
                else:
                    path.unlink()
    source = recorded.source_root
    if (
        recorded.source_mode == "managed"
        and source == managed_source_dir(home)
    ):
        if source.is_symlink():
            print(f"warning: preserving unexpected managed source symlink {source}")
        elif source.exists():
            consumers = remaining_links_into_source(
                home,
                KNOWN_CLIENTS,
                source,
                managed_link_paths,
            )
            if consumers:
                detail = ", ".join(str(link) for link in consumers)
                print(
                    "warning: preserving managed source checkout still used by "
                    f"unmanaged Skill links: {detail}"
                )
            else:
                try:
                    validate_source(
                        source,
                        recorded.profile.bundle,
                    )
                    remote = git_output(source, "remote", "get-url", "origin")
                    expected_remote = recorded.repo_url
                    if normalized_repo_url(remote) != normalized_repo_url(expected_remote):
                        raise SetupError(
                            "managed source origin no longer matches installer state"
                        )
                except SetupError as error:
                    print(
                        f"warning: preserving unverifiable managed source {source}: {error}"
                    )
                else:
                    if git_dirty(source):
                        print(f"warning: preserving dirty managed source checkout {source}")
                    elif args.dry_run:
                        print(f"would remove managed source checkout {source}")
                    else:
                        shutil.rmtree(source)
    path = state_path(home)
    if args.dry_run:
        print(f"would remove installer state {path}")
    else:
        path.unlink(missing_ok=True)
    print("openUBMC workflow would be removed" if args.dry_run else "openUBMC workflow removed")
    return 0


def workflow_json_summary(
    state: Mapping[str, object], *, installed: bool
) -> dict[str, object]:
    recorded = decode_recorded_install(state)
    return {
        "installed": installed,
        "skill_profile": recorded.profile.name,
        "skill_count": len(recorded.profile.bundle),
        "preserved_skills": list(recorded.preserved_skills),
        "clients": list(recorded.clients),
        "source": {
            "path": str(recorded.source_root),
            "mode": recorded.source_mode,
            "commit": recorded.source_commit,
            "requested_ref": recorded.requested_ref,
            "ref_kind": recorded.ref_kind,
            "resolved_commit": recorded.resolved_commit,
            "rollback_commit": recorded.rollback_commit,
        },
        "runtime": {
            "api_version": str(recorded.runtime.get("api_version", "")),
            "content_digest": str(recorded.runtime.get("content_digest", "")),
        },
        "release": dict(recorded.release),
        "openubmc_kb_managed": recorded.profile.manages_knowledge_mcp,
        "openubmc_kb": {
            "version": str(recorded_object(state, "knowledge_mcp").get("version", "")),
            "launcher": str(recorded_object(state, "knowledge_mcp").get("launcher_path", "")),
        },
    }


def lifecycle_json_payload(
    args: argparse.Namespace,
    result: int,
    output: str,
) -> dict[str, object]:
    home = args.home.expanduser().absolute()
    payload: dict[str, object] = {
        "ok": result == 0,
        "command": args.command,
        "dry_run": bool(args.dry_run),
        "messages": [line for line in output.splitlines() if line.strip()],
    }
    credentials_ok, credentials_detail = credentials_status(credentials_path(home))
    payload["credentials"] = {
        "configured": credentials_ok,
        "detail": credentials_detail,
        "preserved": args.command == "uninstall" and not bool(args.purge_credentials),
    }
    tooling = getattr(args, "_tooling_report", None)
    if not isinstance(tooling, dict):
        current_state = try_load_state(home)
        if current_state is not None:
            current_install = decode_recorded_install(current_state)
            tooling = inspect_tooling(
                current_install.tool_dirs,
                current_install.clients,
            )
        else:
            tooling = inspect_tooling((), ())
    payload["tooling"] = tooling
    knowledge_report = getattr(args, "_knowledge_mcp_report", None)
    if not isinstance(knowledge_report, dict):
        knowledge_report = {
            "managed": False,
            "healthy": False,
            "transport": "unknown",
            "detail": "not checked by this lifecycle command",
        }
    payload["knowledge_mcp"] = knowledge_report
    payload["next_actions"] = (
        []
        if args.command == "uninstall" and result == 0
        else [
            *tooling_next_actions(
                tooling,
                credentials_ok=credentials_ok,
            ),
            *knowledge_next_actions(knowledge_report),
        ]
    )
    state = try_load_state(home)
    if state is None:
        payload["workflow"] = {"installed": False}
    else:
        payload["workflow"] = workflow_json_summary(state, installed=True)
    planned_state = getattr(args, "_planned_workflow_state", None)
    if args.dry_run and isinstance(planned_state, dict):
        planned = workflow_json_summary(planned_state, installed=False)
        planned.pop("installed", None)
        planned["action"] = args.command
        payload["planned_workflow"] = planned
    return payload


def perform_json_lifecycle(
    args: argparse.Namespace,
    operation: Callable[[argparse.Namespace], int],
) -> int:
    output = io.StringIO()
    with redirect_stdout(output):
        result = operation(args)
    print(
        json.dumps(
            lifecycle_json_payload(args, result, output.getvalue()),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        operations = {
            "install": perform_install,
            "check": perform_check,
            "repair": perform_repair,
            "update": perform_update,
            "rollback": perform_rollback,
            "refresh": perform_refresh,
            "credentials": perform_credentials,
            "uninstall": perform_uninstall,
        }
        operation = operations[args.command]
        if args.json and args.command != "check":
            return perform_json_lifecycle(args, operation)
        return operation(args)
    except (SetupError, OSError, ValueError) as error:
        if args.json:
            print(
                json.dumps(
                    {"ok": False, "command": args.command, "error": str(error)},
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        else:
            print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
