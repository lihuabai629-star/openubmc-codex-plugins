#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");
const { parseArgs } = require("node:util");

const IDENTITY = new Set([
  "OPENUBMC_MCP_CLIENT", "OPENUBMC_MCP_TASK_ID", "OPENUBMC_MCP_SESSION_ID",
  "OPENUBMC_MCP_FORMAL_RUN", "OPENUBMC_MCP_MODEL_IDENTITY", "OPENUBMC_MCP_CODEX_IDENTITY",
]);

// This client bridge owns no dependencies, credentials, or Runtime state.
function wslCommand({ distribution, pluginRoot, capability, environment = process.env }) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(distribution || "")) throw new Error("Select an explicit WSL distribution.");
  if (!pluginRoot?.startsWith("/") || /[\0\r\n]/.test(pluginRoot)) throw new Error("Select an absolute Linux plugin root.");
  if (!["runtime", "kb", "panel", "host-hook"].includes(capability)) throw new Error("Invalid bridge capability.");
  const env = {};
  for (const [key, value] of Object.entries(environment)) {
    if (["SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA"].includes(key.toUpperCase())) env[key] = value;
  }
  const identity = Object.entries(environment).filter(([key, value]) => IDENTITY.has(key)
    && typeof value === "string" && Buffer.byteLength(value) <= 4096 && !value.includes("\0"));
  const entry = capability === "panel" ? "panel/native.mjs"
    : capability === "host-hook" ? "scripts/openubmc-continuity-hook.js" : "scripts/openubmc-mcp-bootstrap.js";
  return { command: "wsl.exe", env, args: ["--distribution", distribution, "--cd", "/", "--exec", "/usr/bin/env",
    "OPENUBMC_EXECUTION_HOST=wsl", `OPENUBMC_SELECTED_WSL_DISTRO=${distribution}`,
    ...identity.map(([key, value]) => `${key}=${value}`), "node", path.posix.join(pluginRoot, entry),
    ...(["runtime", "kb"].includes(capability) ? [capability] : [])] };
}

function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    distribution: { type: "string" }, "plugin-root": { type: "string" },
  } });
  const selected = wslCommand({ distribution: values.distribution, pluginRoot: values["plugin-root"], capability: positionals[0] });
  const child = spawn(selected.command, selected.args, { env: selected.env, stdio: "inherit", windowsHide: true });
  process.once("SIGINT", () => child.kill("SIGINT"));
  process.once("SIGTERM", () => child.kill("SIGTERM"));
  child.once("error", () => { process.stderr.write("WSL bridge failed. Check the selected distribution and Linux plugin installation.\n"); process.exitCode = 1; });
  child.once("exit", code => { process.exitCode = code ?? 1; });
}

module.exports = { wslCommand };
if (require.main === module) {
  try { main(); } catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 2; }
}
