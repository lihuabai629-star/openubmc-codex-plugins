#!/usr/bin/env node
"use strict";

// Offline analysis has no Runtime, device-account or dependency-install requirement.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const readline = require("readline");
const { spawn } = require("child_process");
const { createHostAdapter } = require("./openubmc-bootstrap-host.js");

const root = path.resolve(__dirname, "..");
const lockBytes = fs.readFileSync(path.join(root, "plugin-lock.json"));
const identity = createHostAdapter({ pluginRoot: root, hostPlatform: process.platform }).packageIdentity();
if (!identity.integrity || !lockBytes.equals(fs.readFileSync(path.join(root, "plugin-lock.json")))) {
  process.stderr.write("openUBMC offline package integrity failed; reinstall a verified archive.\n");
  process.exit(1);
}
const lock = JSON.parse(lockBytes);
const snapshot = fs.mkdtempSync(path.join(os.tmpdir(), "openubmc-offline-"));
const prefix = "skills/openubmc-log-bundle-analyzer/";
try {
  for (const [name, digest] of Object.entries(lock.files)) {
    if (!name.startsWith(prefix)) continue;
    const source = path.join(root, name);
    const content = fs.readFileSync(source);
    if (!fs.lstatSync(source).isFile() || crypto.createHash("sha256").update(content).digest("hex") !== digest) {
      throw new Error("offline_source_changed");
    }
    const target = path.join(snapshot, name.slice(prefix.length));
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.writeFileSync(target, content, { flag: "wx", mode: 0o600 });
  }
} catch (_error) {
  fs.rmSync(snapshot, { recursive: true, force: true });
  process.stderr.write("openUBMC offline source verification failed; reinstall a verified archive.\n");
  process.exit(1);
}
const definitions = JSON.parse(fs.readFileSync(path.join(snapshot, "references/offline-tools.json"), "utf8"));
const worker = path.toNamespacedPath(path.join(snapshot, "scripts/offline_tools.py"));
const python = process.env.OPENUBMC_PLUGIN_PYTHON || (process.platform === "win32" ? "python" : "python3");
function setting(name, fallback, maximum) {
  const value = process.env[name] === undefined ? fallback : Number(process.env[name]);
  if (!Number.isInteger(value) || value < 1 || value > maximum) throw new Error(`Invalid ${name}`);
  return value;
}
const timeoutMs = setting("OPENUBMC_OFFLINE_TIMEOUT_SECONDS", 300, 3600) * 1000;
const concurrency = setting("OPENUBMC_OFFLINE_MAX_CONCURRENCY", 2, 16);
const state = process.env.OPENUBMC_OFFLINE_OUTPUT_DIR || path.join(
  process.platform === "win32" ? process.env.LOCALAPPDATA || os.homedir()
    : process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local/state"), "openubmc", "offline-analysis");
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
  !/KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|COOKIE/i.test(name) && !/^PYTHON(?:PATH|HOME)$/i.test(name)));
environment.PYTHONDONTWRITEBYTECODE = "1";
environment.PYTHONUTF8 = "1";
const active = new Map();
let stopping = false;
const failure = (code, error) => ({ schema: "openubmc.offline-tools.v1", ok: false, code, error });
function write(value) { if (!stopping) process.stdout.write(JSON.stringify(value) + "\n"); }
function result(id, value) {
  write({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value, isError: value.ok === false } });
}
function invoke(id, name, args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    result(id, failure("invalid_request", "Tool arguments must be an object."));
    return;
  }
  for (const field of ["source", "bundle_dir", "output_dir"]) {
    if (field in args && (typeof args[field] !== "string" || !path.isAbsolute(args[field]))) {
      result(id, failure("absolute_path_required", "Codex offline tools require absolute local paths."));
      return;
    }
  }
  if (active.size >= concurrency || active.has(id)) {
    result(id, failure("offline_busy", "Wait for the current offline calls to finish."));
    return;
  }
  const child = spawn(python, ["-I", "-B", "-X", "utf8", "-c",
    "import sys,runpy; sys.pycache_prefix=sys.argv[2]; sys.path.insert(0,sys.argv[1]); runpy.run_path(sys.argv[3],run_name='openubmc_offline')['main']()",
    path.dirname(worker), path.toNamespacedPath(path.join(snapshot, "unused-pycache")), worker],
  { env: environment, windowsHide: true, stdio: ["pipe", "pipe", "ignore"] });
  let output = Buffer.alloc(0);
  let failed;
  const stop = (code, error) => { failed ||= failure(code, error); child.kill("SIGKILL"); };
  const timer = setTimeout(() => stop("offline_timeout", "Offline analysis exceeded its configured deadline."), timeoutMs);
  active.set(id, { child, stop });
  child.stdout.on("data", chunk => {
    if (output.length + chunk.length > 1024 * 1024) stop("output_limit", "Offline response exceeded 1 MiB.");
    else output = Buffer.concat([output, chunk]);
  });
  child.once("error", () => { failed = failure("python_unavailable", "Check OPENUBMC_PLUGIN_PYTHON and Python 3.11 or later."); });
  child.stdin.on("error", () => { stop("worker_input_failed", "Offline worker closed its input."); });
  child.once("close", code => {
    clearTimeout(timer);
    active.delete(id);
    let value = failed;
    if (!value) {
      try {
        if (code !== 0) throw new Error("worker_failed");
        value = JSON.parse(output.toString("utf8"));
        if (!value || value.schema !== "openubmc.offline-tools.v1" || typeof value.ok !== "boolean") throw new Error("invalid_response");
      } catch (_error) { value = failure("worker_failed", "Offline worker did not return a valid result."); }
    }
    result(id, value);
    if (stopping && active.size === 0) fs.rmSync(snapshot, { recursive: true, force: true });
  });
  child.stdin.end(JSON.stringify({ tool: name, arguments: args, cwd: process.cwd(), artifact_dir: state }) + "\n");
}
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", line => {
  let request;
  try {
    if (Buffer.byteLength(line, "utf8") > 1024 * 1024) throw new Error("request_limit");
    request = JSON.parse(line);
    if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("invalid_request");
  } catch (_error) { write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Invalid offline MCP request." } }); return; }
  if (request.method === "notifications/cancelled") {
    active.get(request.params?.requestId)?.stop("cancelled", "Offline call cancelled.");
    return;
  }
  if (request.id === undefined || stopping) return;
  if (request.method === "initialize") {
    write({ jsonrpc: "2.0", id: request.id, result: { protocolVersion: request.params?.protocolVersion || "2024-11-05",
      capabilities: { tools: {} }, serverInfo: { name: "openubmc-offline", version: identity.version } } });
  } else if (request.method === "ping") write({ jsonrpc: "2.0", id: request.id, result: {} });
  else if (request.method === "tools/list") write({ jsonrpc: "2.0", id: request.id, result: { tools: definitions } });
  else if (request.method === "tools/call") {
    const name = request.params?.name;
    if (!definitions.some(tool => tool.name === name)) result(request.id, failure("unknown_tool", "Unknown offline tool."));
    else invoke(request.id, name, request.params?.arguments);
  } else write({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found." } });
});
function close() {
  if (stopping) return;
  stopping = true;
  input.close();
  for (const operation of active.values()) operation.stop("cancelled", "Offline MCP closed.");
  if (active.size === 0) fs.rmSync(snapshot, { recursive: true, force: true });
}
input.once("close", close);
process.once("SIGINT", close);
process.once("SIGTERM", close);
process.stdout.on("error", close);
