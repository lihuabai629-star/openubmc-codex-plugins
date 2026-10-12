"use strict";

// Transport routing only. Runtime owns Run, Gate, Effect, and Outcome state.
// The bootstrap cannot observe or authorize shell calls made by the host.
const crypto = require("crypto");

const SCHEMA = "openubmc.execution-routing/v1";
const RUNTIME_TOOLS = new Set(["observe", "execute"]);
// The Runtime's 256 KiB budget applies to arguments.  JSON-RPC framing and
// encoding whitespace need their own bounded allowance on the transport line.
const MAX_MCP_LINE_BYTES = 512 * 1024;
const MAX_ARGUMENT_BYTES = 256 * 1024;
const MAX_ARGUMENT_NODES = 8192;
const MAX_ARGUMENT_DEPTH = 32;
// Never serialize this key. A process-local MAC cannot be used for an offline
// password guess after a routing receipt is logged or persisted by the Host.
const scopeKey = crypto.randomBytes(32);

function canonicalArguments(value) {
  let nodes = 0;
  function visit(item, depth) {
    nodes += 1;
    if (nodes > MAX_ARGUMENT_NODES) {
      throw new Error("routing_request_too_large");
    }
    if (Array.isArray(item)) {
      if (depth > MAX_ARGUMENT_DEPTH) throw new Error("routing_request_too_large");
      return item.map((child) => visit(child, depth + 1));
    }
    if (item !== null && typeof item === "object") {
      if (depth > MAX_ARGUMENT_DEPTH) throw new Error("routing_request_too_large");
      const canonical = Object.create(null);
      for (const key of Object.keys(item).sort()) canonical[key] = visit(item[key], depth + 1);
      return canonical;
    }
    if (item === null || typeof item === "string" || typeof item === "boolean"
        || (typeof item === "number" && Number.isFinite(item))) return item;
    throw new Error("routing_request_invalid");
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error("routing_request_invalid");
  }
  const encoded = JSON.stringify(visit(value, 0));
  if (Buffer.byteLength(encoded, "utf8") > MAX_ARGUMENT_BYTES) {
    throw new Error("routing_request_too_large");
  }
  return encoded;
}

function runtimeProtocolHealthy(report) {
  const health = report?.mcp_health?.runtime;
  if (health?.ok !== true) return false;
  // pluginctl.doctor obtains the names from a bounded MCP initialize/tools/list
  // probe. A missing list cannot establish this Agent Interface.
  return Array.isArray(health.tools)
    && health.tools.includes("observe") && health.tools.includes("execute");
}

function operationFor(request) {
  if (request?.method !== "tools/call") return null;
  const name = request?.params?.name;
  if (!RUNTIME_TOOLS.has(name)) return null;
  if (name === "observe") return "evidence";
  const argumentsValue = request?.params?.arguments;
  const intent = argumentsValue && typeof argumentsValue === "object" ? argumentsValue.intent : null;
  if (intent === "upgrade-and-verify") return "upgrade";
  if (intent === "diagnosis-only" || intent === "diagnose-and-fix") return "diagnose";
  // A continuation is bound to its durable Run; the transport cannot safely
  // reconstruct its original intent from this single message.
  return "runtime-execute";
}

function routeRuntimeCall(request, { report, hostPlatform, selectedWsl = null, sequence }) {
  const operation = operationFor(request);
  if (operation === null) return null;
  if (!runtimeProtocolHealthy(report)) {
    return { allowed: false, reason_code: "mcp_protocol_unhealthy" };
  }
  const argumentsValue = request?.params?.arguments === undefined ? {} : request.params.arguments;
  let canonical;
  try {
    canonical = canonicalArguments(argumentsValue);
  } catch (error) {
    return { allowed: false, reason_code: error.message === "routing_request_too_large"
      ? "routing_request_too_large" : "routing_request_invalid" };
  }
  const scopeMac = crypto.createHmac("sha256", scopeKey).update(canonical).digest("hex");
  const receipt = {
    schema: SCHEMA,
    receipt_id: crypto.randomUUID(),
    path: "structured-runtime-mcp",
    operation,
    tool: request.params.name,
    client_environment: hostPlatform === "win32" ? "windows" : hostPlatform,
    execution_host: hostPlatform === "win32" ? "windows-native" : hostPlatform,
    selected_wsl: null,
    requested_scope_mac: `hmac-sha256:${scopeMac}`,
    evidence_boundary: "typed_runtime_mcp_result",
    protocol: { healthy: true, source: "pluginctl.doctor", probe: "initialize/tools/list" },
    fallback: null,
    structured_call_number: sequence,
  };
  return { allowed: true, receipt };
}

module.exports = { MAX_MCP_LINE_BYTES, routeRuntimeCall, runtimeProtocolHealthy };
