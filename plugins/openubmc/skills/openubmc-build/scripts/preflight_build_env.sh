#!/usr/bin/env bash
set -u
set -o pipefail

PROFILE=""
BOARD=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --board)
      BOARD="${2:-}"
      shift 2
      ;;
    --board=*)
      BOARD="${1#--board=}"
      shift
      ;;
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --profile=*)
      PROFILE="${1#--profile=}"
      shift
      ;;
    -h|--help)
      cat <<'HELP'
Usage: preflight_build_env.sh [--profile 2630-wsl] [--board <board>]

Read-only openUBMC build environment preflight. Checks workspace signals,
common tools, bmcgo/Conan versions, remotes, and optional host profile state.
Pass --board when product build uses a known board selector, such as openUBMC.
HELP
      exit 0
      ;;
    *)
      printf '[WARN] ignoring unknown argument: %s\n' "$1"
      shift
      ;;
  esac
done

section() { printf '\n== %s ==\n' "$1"; }
ok() { printf '[OK] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1"; }

show_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    ok "command found: $1 ($(command -v "$1"))"
  else
    warn "command missing: $1"
  fi
}

run_version() {
  local name="$1"
  shift
  if command -v "$name" >/dev/null 2>&1; then
    printf '$ %s %s\n' "$name" "$*"
    timeout 20s "$name" "$@" 2>&1 | sed 's/^/  /'
  fi
}

section "Host"
printf 'pwd: %s\n' "$PWD"
printf 'host: %s\n' "$(hostname 2>/dev/null || true)"
printf 'kernel: %s\n' "$(uname -a 2>/dev/null || true)"

section "Workspace Signals"
found=0
if [ -f mds/service.json ]; then ok "component signal: mds/service.json"; found=1; fi
if [ -f conanfile.py ]; then ok "package recipe signal: conanfile.py"; found=1; fi
if [ -f .bmcgo/config ]; then ok "bmcgo config signal: .bmcgo/config"; found=1; fi
if [ -f build/frame.py ] || [ -f frame.py ]; then ok "manifest frame signal"; found=1; fi
if [ -d build/product ]; then ok "product manifest signal: build/product"; found=1; fi
if [ -d build/subsys ]; then ok "subsystem dependency signal: build/subsys"; found=1; fi
if [ -f webui/package.json ] || [ -f package.json ]; then ok "node package signal"; fi
if [ "$found" -eq 0 ]; then warn "no component or manifest build signal found in current directory"; fi

section "Manifest Required Files"
if [ -d build/manufacture ]; then
  for required_file in \
    build/manufacture/misc/pme_profile_en.dat \
    build/manufacture/misc/datatocheck_upgrade.dat
  do
    if [ -f "$required_file" ]; then
      if [ -s "$required_file" ]; then
        ok "non-empty required manufacture file: $required_file"
      else
        warn "empty required manufacture file may fail rootfs image build: $required_file"
      fi
    else
      warn "required manufacture file not found from manifest root: $required_file"
    fi
  done
else
  warn "not in a manifest root with build/manufacture"
fi

section "HPM Signing"
if [ -d build/product ] || [ -d temp ]; then
  OPENUBMC_PREFLIGHT_BOARD="$BOARD" python3 - <<'PY' 2>/dev/null || true
import configparser
import os
from pathlib import Path


def status(kind: str, msg: str) -> None:
    print(f"[{kind}] {msg}")


def find_config(start: Path) -> Path | None:
    cur = start.resolve()
    while True:
        path = cur / ".bmcgo" / "config"
        if path.is_file():
            return path
        if cur.parent == cur:
            return None
        cur = cur.parent


root = Path.cwd()
board = os.environ.get("OPENUBMC_PREFLIGHT_BOARD", "").strip().strip("/")
cfg_path = find_config(root)
cfg = configparser.ConfigParser()
has_cfg_sign = False
if cfg_path and cfg.read(cfg_path):
    sign_sections = [name for name in ("hpm_self_sign", "hpm_server_sign") if cfg.has_section(name)]
    if sign_sections:
        has_cfg_sign = True
        status("OK", f"local bmcgo signing section(s): {', '.join(sign_sections)} in {cfg_path}")
    else:
        status("WARN", f"no hpm_self_sign/hpm_server_sign section in local config: {cfg_path}")
else:
    status("WARN", "no local .bmcgo/config found from current directory upward")

product_root = root / "build" / "product"
manifest_paths: list[Path] = []
if product_root.is_dir():
    if board:
        direct = product_root / board / "manifest.yml"
        if direct.is_file():
            manifest_paths.append(direct)
        else:
            matches = [path for path in product_root.rglob("manifest.yml") if path.parent.name == board]
            manifest_paths.extend(matches)
            if not matches:
                status("WARN", f"board manifest not found for --board {board}: {direct}")
    else:
        manifest_paths = sorted(product_root.rglob("manifest.yml"))[:20]

manifest_sign_hits = []
for path in manifest_paths:
    text = path.read_text(encoding="utf-8", errors="ignore")
    keys = [key for key in ("simple_signer_server", "certificates", "signserver") if key in text]
    if keys:
        manifest_sign_hits.append((path, keys))

if manifest_sign_hits:
    for path, keys in manifest_sign_hits:
        status("OK", f"manifest signing config hint: {path} ({', '.join(keys)})")
else:
    if manifest_paths:
        status("WARN", "no manifest signature self/server config hint found in checked product manifest(s)")
    else:
        status("WARN", "no product manifest checked for signature config")

temp_candidates: list[Path] = []
if board:
    temp_candidates.append(root / "temp" / f"board_{board}" / "sign_img.xml")
    if "/" in board:
        temp_candidates.append(root / "temp" / f"board_{Path(board).name}" / "sign_img.xml")
else:
    temp_candidates = sorted((root / "temp").glob("board_*/sign_img.xml")) if (root / "temp").is_dir() else []

if temp_candidates:
    for path in temp_candidates:
        if path.is_file() and path.stat().st_size > 0:
            status("OK", f"generated board sign_img.xml present: {path}")
        else:
            status("WARN", f"generated board sign_img.xml missing or empty: {path}")
else:
    status("WARN", "no temp/board_*/sign_img.xml found yet; this is normal before build, but bmcgo_pro online signing needs it")

for path in (Path("/usr/share/bmcgo/signature/sign_img.xml"), Path("/usr/share/bmcgo/signature_sm2/sign_img.xml")):
    if path.is_file() and path.stat().st_size > 0:
        status("OK", f"bmcgo signature template exists: {path}")
    else:
        status("WARN", f"bmcgo signature template missing: {path}")

if not has_cfg_sign and not manifest_sign_hits:
    jar = Path("/usr/local/signature-jenkins-slave/signature.jar")
    if jar.is_file():
        status("WARN", "no self/server signing config found; bmcgo_pro may use board sign_img.xml and online signature.jar")
    else:
        status("WARN", "no self/server signing config and signature.jar missing; HPM signing is likely to fail unless board sign_img.xml is prepared")
PY
else
  warn "not in a manifest root with product/temp build signals"
fi

section "Tools"
for cmd in python3 pip3 bmcgo conan git make cmake ninja npm; do
  show_cmd "$cmd"
done

run_version python3 --version
run_version bmcgo --version
run_version conan --version

section "Component Version"
if [ -f mds/service.json ]; then
  python3 - <<'PY' 2>/dev/null || true
import json
from pathlib import Path
data = json.loads(Path("mds/service.json").read_text())
print(f'current mds/service.json version: {data.get("version", "<missing>")}')
PY
else
  warn "not in a component root with mds/service.json"
fi

section "bmcgo Config Constraints"
python3 - <<'PY' 2>/dev/null || true
import configparser
from pathlib import Path


def find_config(start: Path) -> Path | None:
    cur = start.resolve()
    while True:
        for rel in (".bmcgo/config", ".bingo/config"):
            path = cur / rel
            if path.is_file():
                return path
        if cur.parent == cur:
            return None
        cur = cur.parent


cfg_path = find_config(Path.cwd())
if not cfg_path:
    print("[WARN] no .bmcgo/config or .bingo/config found from current directory upward")
    raise SystemExit(0)

print(f"config: {cfg_path}")
conf = configparser.ConfigParser()
conf.read(cfg_path)

try:
    from semver import satisfies
except Exception:
    satisfies = None

versions = {}
try:
    import bmcgo
    versions["bingo"] = getattr(bmcgo, "__version__", "")
except Exception:
    pass
try:
    import bmcgo_pro
    versions["bmcgo"] = getattr(bmcgo_pro, "__version__", "")
except Exception:
    pass

for section_name in ("bingo", "bmcgo", "bmc-studio"):
    if not conf.has_option(section_name, "version"):
        continue
    constraint = conf.get(section_name, "version")
    current = versions.get(section_name, "")
    print(f"{section_name}.version constraint: {constraint}")
    if current:
        print(f"{section_name}.current: {current}")
        if satisfies:
            expr = constraint.strip().strip("[]")
            try:
                ok = satisfies(current, expr)
            except Exception:
                ok = None
            if ok is False:
                print(
                    f"[WARN] {section_name} current version does not satisfy {constraint}; "
                    "bmcgo help/build may trigger auto-upgrade"
                )
PY

section "Conan Remotes"
if command -v conan >/dev/null 2>&1; then
  printf '$ conan remote list\n'
  timeout 20s conan remote list 2>&1 | sed 's/^/  /' || warn "conan remote list failed"
fi

if [ "$PROFILE" = "2630-wsl" ]; then
  section "2630 WSL Profile"
  WSL_EXE="${OPENUBMC_WSL_EXE:-/mnt/c/Windows/System32/wsl.exe}"
  if [ -e "$WSL_EXE" ]; then
    ok "Windows wsl.exe exists: $WSL_EXE"
    printf '$ %s -l -v\n' "$WSL_EXE"
    timeout 15s "$WSL_EXE" -l -v 2>&1 | tr -d '\000' | sed 's/^/  /' || warn "wsl.exe distro list failed"

    printf '$ %s -d 2630 --cd / -- sh -s <workspace check>\n' "$WSL_EXE"
    if ! timeout 25s "$WSL_EXE" -d 2630 --cd / -- sh -s 2>&1 <<'REMOTE_2630' | sed 's/^/  /'; then
for p in /home/workspace/manifest /home/workspace/source /home/workspace/general_hardware /home/workspace/bios /home/workspace/vpd; do
  if [ -d "$p" ]; then
    printf "[OK] 2630 directory exists: %s\n" "$p"
  else
    printf "[WARN] 2630 directory missing: %s\n" "$p"
  fi
done
if [ -f /home/workspace/manifest/.bmcgo/config ] || [ -f /home/workspace/manifest/build/frame.py ] || [ -d /home/workspace/manifest/build/product ]; then
  printf "[OK] 2630 manifest root has build signals\n"
else
  printf "[WARN] 2630 manifest root lacks expected build signals\n"
fi
REMOTE_2630
      warn "2630 workspace check failed"
    fi
  else
    warn "Windows wsl.exe not found at $WSL_EXE"
  fi
elif [ -n "$PROFILE" ]; then
  warn "unknown profile: $PROFILE"
fi

section "Next"
printf 'Run bmcgo --help and bmcgo <command> -h in the actual workspace before choosing flags.\n'
printf 'Component builds need mds/service.json or conanfile.py; product packages need manifest/product build signals.\n'
