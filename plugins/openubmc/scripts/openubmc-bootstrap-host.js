"use strict";

const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { performance } = require("perf_hooks");

function windowsChildEnvironment(environment) {
  const allowed = new Set([
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP", "TMP",
    "LOCALAPPDATA", "USERPROFILE", "CODEX_HOME",
    "OPENUBMC_MCP_CLIENT", "OPENUBMC_MCP_TASK_ID", "OPENUBMC_MCP_SESSION_ID",
    "OPENUBMC_MCP_FORMAL_RUN", "OPENUBMC_MCP_MODEL_IDENTITY", "OPENUBMC_MCP_CODEX_IDENTITY",
    "OPENUBMC_EVALUATION_TASK_ID",
    "OPENUBMC_TARGET_RUNTIME_STATE_DIR", "OPENUBMC_HOST_MEASUREMENTS_FILE",
    "OPENUBMC_HOST_PROVIDER_REPORT", "OPENUBMC_HOST_PROVIDER_REF", "OPENUBMC_HOST_EVIDENCE_KIND",
  ]);
  const result = {};
  for (const [key, value] of Object.entries(environment)) {
    if (allowed.has(key.toUpperCase())) result[key] = value;
  }
  const localData = environment.LOCALAPPDATA || path.win32.join(environment.USERPROFILE || os.homedir(), "AppData", "Local");
  result.XDG_CONFIG_HOME = environment.XDG_CONFIG_HOME || localData;
  result.XDG_DATA_HOME = environment.XDG_DATA_HOME || localData;
  result.XDG_CACHE_HOME = environment.XDG_CACHE_HOME || localData;
  result.XDG_STATE_HOME = environment.XDG_STATE_HOME || localData;
  result.OPENUBMC_EXECUTION_HOST = "windows-native";
  return result;
}

function decodeOutput(buffer) {
  if (!buffer || buffer.length === 0) return "";
  const bytes = Buffer.from(buffer);
  const hasNuls = bytes.subarray(0, Math.min(bytes.length, 256)).includes(0);
  return bytes.toString(hasNuls ? "utf16le" : "utf8").replace(/^\uFEFF/, "").replace(/\0/g, "");
}

function createHostAdapter({ pluginRoot, hostPlatform, environment = process.env, deadlineMs = Infinity }) {
  const childEnvironment = hostPlatform === "win32"
    ? windowsChildEnvironment(environment)
    : { ...environment };
  childEnvironment.PYTHONDONTWRITEBYTECODE = "1";
  delete childEnvironment.PYTHONPATH;
  delete childEnvironment.PYTHONHOME;

  function run(command, args, options = {}) {
    const timeout = Math.min(options.timeout || 30_000, Math.ceil(deadlineMs - performance.now()));
    if (timeout <= 0) throw new Error("host_deadline_exceeded");
    return childProcess.spawnSync(command, args, {
      env: childEnvironment,
      input: options.input,
      encoding: options.encoding || null,
      maxBuffer: options.maxBuffer || 16 * 1024 * 1024,
      timeout,
      // A deadline-bound hook must also stop a child that ignores SIGTERM.
      killSignal: Number.isFinite(deadlineMs) ? "SIGKILL" : undefined,
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

  function resolvePosixBackend() {
    const python = environment.OPENUBMC_PLUGIN_PYTHON || "python3";
    const checked = run(python, ["-c", "import sys; assert sys.version_info >= (3, 11)"], { timeout: 15_000 });
    if (checked.error || checked.status !== 0) return { ok: false, reason: "python_unavailable" };
    return { ok: true, command: python,
      prefix: ["-I", "-B", path.join(pluginRoot, "scripts", "pluginctl.py")], configurationArgs: [] };
  }

  function resolveBackend() {
    return hostPlatform === "win32" ? resolveNativeWindowsBackend() : resolvePosixBackend();
  }

  function resolveNativeWindowsBackend() {
    const requested = environment.OPENUBMC_PLUGIN_WINDOWS_PYTHON;
    const candidates = requested ? [[requested, []]] : [["python", []], ["py", ["-3.12"]]];
    if (!requested) {
      const discovered = run("py", ["-0p"], { timeout: 10_000 });
      for (const line of decodeOutput(discovered.stdout).split(/\r?\n/)) {
        const match = line.match(/([A-Za-z]:\\[^\r\n]*?python\.exe)\s*$/i);
        if (match) candidates.push([match[1], []]);
      }
    }
    const probe = "import sys; assert sys.platform == 'win32' and sys.version_info[:2] == (3, 12)";
    for (const [python, selector] of candidates) {
      const checked = run(python, [...selector, "-I", "-B", "-c", probe], { timeout: 15_000 });
      if (!checked.error && checked.status === 0) {
        return { ok: true, command: python,
          prefix: [...selector, "-I", "-B", path.join(pluginRoot, "scripts", "pluginctl.py")],
          configurationArgs: [], execution_host: "windows-native" };
      }
    }
    return { ok: false, reason: "windows_python_unavailable", execution_host: "windows-native" };
  }

  return { childEnvironment, decodeOutput, hostPlatform, packageIdentity, resolveBackend, run };
}

module.exports = { createHostAdapter, windowsChildEnvironment };
