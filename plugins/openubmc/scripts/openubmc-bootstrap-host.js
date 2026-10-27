"use strict";

const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { performance } = require("perf_hooks");

function decodeOutput(buffer) {
  if (!buffer || buffer.length === 0) return "";
  const bytes = Buffer.from(buffer);
  const hasNuls = bytes.subarray(0, Math.min(bytes.length, 256)).includes(0);
  return bytes.toString(hasNuls ? "utf16le" : "utf8").replace(/^\uFEFF/, "").replace(/\0/g, "");
}

function createHostAdapter({ pluginRoot, hostPlatform, environment = process.env, deadlineMs = Infinity }) {
  const selectedWsl = hostPlatform === "linux" && environment.OPENUBMC_EXECUTION_HOST === "wsl"
    && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(environment.OPENUBMC_SELECTED_WSL_DISTRO || "")
    ? environment.OPENUBMC_SELECTED_WSL_DISTRO : null;
  const executionHost = selectedWsl ? "wsl" : hostPlatform === "win32" ? "windows-native" : hostPlatform;
  const clientEnvironment = selectedWsl || hostPlatform === "win32" ? "windows" : hostPlatform;
  const childEnvironment = { ...environment };
  const childCwd = os.homedir();
  childEnvironment.PYTHONDONTWRITEBYTECODE = "1";
  delete childEnvironment.PYTHONPATH;
  delete childEnvironment.PYTHONHOME;

  function run(command, args, options = {}) {
    const timeout = Math.min(options.timeout || 30_000, Math.ceil(deadlineMs - performance.now()));
    if (timeout <= 0) throw new Error("host_deadline_exceeded");
    return childProcess.spawnSync(command, args, {
      env: childEnvironment,
      cwd: childCwd,
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
      prefix: ["-I", "-B", path.join(pluginRoot, "scripts", "pluginctl.py")], configurationArgs: [],
      execution_host: executionHost, selected_wsl: selectedWsl };
  }

  function resolveBackend() {
    if (hostPlatform === "win32") return { ok: false, reason: "unsupported_platform",
      execution_host: "windows-native", recovery_action: "Run the plugin inside Linux or WSL; connect the Windows client through an explicit WSL stdio command." };
    return resolvePosixBackend();
  }

  return { childEnvironment, childCwd, clientEnvironment, decodeOutput, executionHost, hostPlatform,
    packageIdentity, resolveBackend, run, selectedWsl };
}

module.exports = { createHostAdapter };
