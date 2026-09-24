"use strict";

const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

function windowsChildEnvironment(environment) {
  const allowed = new Set([
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP", "TMP",
    "LOCALAPPDATA", "USERPROFILE", "CODEX_HOME",
  ]);
  const result = {};
  for (const [key, value] of Object.entries(environment)) {
    if (allowed.has(key.toUpperCase())) result[key] = value;
  }
  return result;
}

function decodeOutput(buffer) {
  if (!buffer || buffer.length === 0) return "";
  const bytes = Buffer.from(buffer);
  const hasNuls = bytes.subarray(0, Math.min(bytes.length, 256)).includes(0);
  return bytes.toString(hasNuls ? "utf16le" : "utf8").replace(/^\uFEFF/, "").replace(/\0/g, "");
}

function createHostAdapter({ pluginRoot, hostPlatform, wslExecutable, environment = process.env }) {
  const childEnvironment = hostPlatform === "win32"
    ? windowsChildEnvironment(environment)
    : { ...environment };
  childEnvironment.PYTHONDONTWRITEBYTECODE = "1";
  delete childEnvironment.PYTHONPATH;
  delete childEnvironment.PYTHONHOME;

  function run(command, args, options = {}) {
    return childProcess.spawnSync(command, args, {
      env: childEnvironment,
      encoding: null,
      maxBuffer: 16 * 1024 * 1024,
      timeout: options.timeout || 30_000,
      windowsHide: true,
    });
  }

  function packageIdentity() {
    try {
      const canonicalize = (value) => {
        if (Array.isArray(value)) return value.map(canonicalize);
        if (value && typeof value === "object") {
          return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
        }
        return value;
      };
      const lock = JSON.parse(fs.readFileSync(path.join(pluginRoot, "plugin-lock.json"), "utf8"));
      const unsigned = { ...lock };
      delete unsigned.content_digest;
      const digest = crypto.createHash("sha256")
        .update(`${JSON.stringify(canonicalize(unsigned), null, 2)}\n`).digest("hex");
      let integrity = digest === lock.content_digest;
      const actual = {};
      let fileCount = 0;
      let totalBytes = 0;
      const visit = (root) => {
        for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
          const absolute = path.join(root, entry.name);
          const relative = path.relative(pluginRoot, absolute).split(path.sep).join("/");
          const info = fs.lstatSync(absolute);
          if (info.isSymbolicLink()) throw new Error("plugin_symlink");
          if (info.isDirectory()) visit(absolute);
          else if (info.isFile() && relative !== "plugin-lock.json"
              && !(relative.endsWith(".pyc") && relative.split("/").includes("__pycache__"))) {
            fileCount += 1;
            totalBytes += info.size;
            if (fileCount > 10_000 || totalBytes > 128 * 1024 * 1024) throw new Error("plugin_size_limit");
            actual[relative] = crypto.createHash("sha256").update(fs.readFileSync(absolute)).digest("hex");
          }
        }
      };
      visit(pluginRoot);
      integrity = integrity && JSON.stringify(canonicalize(actual)) === JSON.stringify(canonicalize(lock.files || {}));
      const manifest = fs.readFileSync(path.join(pluginRoot, ".codex-plugin", "plugin.json"));
      integrity = integrity
        && crypto.createHash("sha256").update(manifest).digest("hex") === lock.manifest_digest;
      return { version: lock.version || null, source_commit: lock.source_commit || null, integrity };
    } catch (_error) {
      return { version: null, source_commit: null, integrity: false };
    }
  }

  function hostConfigPath() {
    const base = environment.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    return path.join(base, "openubmc", "plugin-host.json");
  }

  function readSelectedDistro() {
    if (environment.OPENUBMC_WSL_DISTRO) return environment.OPENUBMC_WSL_DISTRO.trim();
    try {
      const record = JSON.parse(fs.readFileSync(hostConfigPath(), "utf8"));
      return record && record.schema === "openubmc.plugin-host.v1" && typeof record.wsl_distro === "string"
        ? record.wsl_distro.trim()
        : "";
    } catch (_error) {
      return "";
    }
  }

  function listDistros() {
    const listed = run(wslExecutable, ["--list", "--quiet"]);
    if (listed.error || listed.status !== 0) return { ok: false, distros: [] };
    const distros = decodeOutput(listed.stdout).split(/\r?\n/)
      .map((value) => value.trim())
      .filter((value, index, values) => value && values.indexOf(value) === index);
    return { ok: true, distros };
  }

  function resolveWindowsBackend() {
    const discovered = listDistros();
    if (!discovered.ok || discovered.distros.length === 0) {
      return { ok: false, reason: "wsl_unavailable", distros: [] };
    }
    const selected = readSelectedDistro();
    if (selected && !discovered.distros.includes(selected)) {
      return { ok: false, reason: "selected_wsl_unavailable", distros: discovered.distros, selected_wsl: selected };
    }
    if (!selected && discovered.distros.length > 1) {
      return { ok: false, reason: "wsl_selection_required", distros: discovered.distros };
    }
    const distro = selected || discovered.distros[0];
    const converted = run(wslExecutable, ["-d", distro, "--exec", "wslpath", "-a", "-u", pluginRoot]);
    const linuxRoot = decodeOutput(converted.stdout).trim();
    if (converted.error || converted.status !== 0 || !linuxRoot.startsWith("/")) {
      return { ok: false, reason: "plugin_path_unavailable_in_wsl", distros: discovered.distros, selected_wsl: distro };
    }
    const python = run(wslExecutable, ["-d", distro, "--exec", "python3", "-c", "import sys; assert sys.version_info >= (3, 11)"], { timeout: 15_000 });
    if (python.error || python.status !== 0) {
      return { ok: false, reason: "wsl_python_unavailable", distros: discovered.distros, selected_wsl: distro };
    }
    const windowsHome = environment.USERPROFILE || os.homedir();
    const windowsCodex = environment.CODEX_HOME || path.win32.join(windowsHome, ".codex");
    const convertHostPath = (value) => {
      const result = run(wslExecutable, ["-d", distro, "--exec", "wslpath", "-a", "-u", value]);
      return result.error || result.status !== 0 ? "" : decodeOutput(result.stdout).trim();
    };
    const linuxHostHome = convertHostPath(windowsHome);
    const linuxCodexHome = convertHostPath(windowsCodex);
    if (!linuxHostHome.startsWith("/") || !linuxCodexHome.startsWith("/")) {
      return { ok: false, reason: "windows_configuration_path_unavailable_in_wsl", distros: discovered.distros, selected_wsl: distro };
    }
    const identityEnvironment = [];
    for (const key of [
      "OPENUBMC_MCP_CLIENT", "OPENUBMC_MCP_TASK_ID", "OPENUBMC_MCP_SESSION_ID",
      "OPENUBMC_MCP_FORMAL_RUN", "OPENUBMC_MCP_MODEL_IDENTITY", "OPENUBMC_MCP_CODEX_IDENTITY",
      "OPENUBMC_EVALUATION_TASK_ID",
    ]) {
      const value = environment[key];
      if (typeof value === "string" && value.length <= 4096 && !/[\0\r\n]/.test(value)) {
        identityEnvironment.push(`${key}=${value}`);
      }
    }
    return {
      ok: true,
      command: wslExecutable,
      prefix: ["-d", distro, "--exec", "env", "OPENUBMC_EXECUTION_HOST=windows-wsl",
        `OPENUBMC_SELECTED_WSL_DISTRO=${distro}`, ...identityEnvironment,
        "python3", "-I", "-B", `${linuxRoot}/scripts/pluginctl.py`],
      distros: discovered.distros,
      selected_wsl: distro,
      configurationArgs: ["--home", linuxHostHome, "--codex-home", linuxCodexHome],
    };
  }

  function resolvePosixBackend() {
    const python = environment.OPENUBMC_PLUGIN_PYTHON || "python3";
    const checked = run(python, ["-c", "import sys; assert sys.version_info >= (3, 11)"], { timeout: 15_000 });
    if (checked.error || checked.status !== 0) return { ok: false, reason: "python_unavailable" };
    return { ok: true, command: python,
      prefix: ["-I", "-B", path.join(pluginRoot, "scripts", "pluginctl.py")], configurationArgs: [] };
  }

  function resolveBackend() {
    return hostPlatform === "win32" ? resolveWindowsBackend() : resolvePosixBackend();
  }

  function saveSelectedDistro(distro, available) {
    if (typeof distro !== "string" || !available.includes(distro)) {
      throw new Error("Select one of the available WSL distributions exactly as listed.");
    }
    const target = hostConfigPath();
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const temporary = `${target}.${process.pid}.tmp`;
    fs.writeFileSync(temporary,
      `${JSON.stringify({ schema: "openubmc.plugin-host.v1", wsl_distro: distro }, null, 2)}\n`,
      { mode: 0o600 });
    fs.renameSync(temporary, target);
  }

  return { childEnvironment, decodeOutput, hostPlatform, packageIdentity, resolveBackend, run, saveSelectedDistro };
}

module.exports = { createHostAdapter, windowsChildEnvironment };
