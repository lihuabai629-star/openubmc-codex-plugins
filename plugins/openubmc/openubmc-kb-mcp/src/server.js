#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { ReloadingKnowledgeClient } from "./reloading-client.js";
import { loadConfig } from "./config.js";
import {
  McpProcessLifecycle,
  installMcpProcessSignalHandlers
} from "./process-lifecycle.js";
import { registerTools } from "./tools.js";


function configPath(argv) {
  const index = argv.indexOf("--config");
  return index >= 0 ? argv[index + 1] : undefined;
}


export async function createServer(path, processLifecycle = null) {
  const config = await loadConfig(path, { allowMissingCredentials: true });
  const lightrag = new ReloadingKnowledgeClient(config);
  const server = new McpServer(
    { name: "openubmc-kb-mcp-server", version: "1.3.0" },
    {
      instructions: "Use the read-only openUBMC knowledge-base tools for candidate discovery. Runtime and repository evidence remain authoritative."
    }
  );
  registerTools(server, lightrag, processLifecycle);
  return server;
}


function positiveEnvironmentNumber(name, fallback) {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || !(value > 0)) {
    throw new Error(`${name} must be finite and positive`);
  }
  return value;
}


function identityEnvironment(name) {
  const raw = process.env[name]?.trim();
  if (!raw) return { value: {}, error: null };
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { value: {}, error: `${name} must be a JSON object` };
    }
    return { value, error: null };
  } catch {
    return { value: {}, error: `${name} must be a JSON object` };
  }
}


function formalRunEnvironment() {
  const raw = process.env.OPENUBMC_MCP_FORMAL_RUN?.trim().toLowerCase();
  if (!raw) return { value: false, error: null };
  if (["1", "true", "yes"].includes(raw)) return { value: true, error: null };
  if (["0", "false", "no"].includes(raw)) return { value: false, error: null };
  return { value: false, error: "OPENUBMC_MCP_FORMAL_RUN must be boolean" };
}


function createProcessLifecycle(path) {
  const configuredTask = process.env.OPENUBMC_MCP_TASK_ID?.trim()
    || process.env.CODEX_TASK_ID?.trim()
    || process.env.OPENUBMC_EVALUATION_TASK_ID?.trim();
  const configuredSession = process.env.OPENUBMC_MCP_SESSION_ID?.trim();
  const sessionId = configuredSession || configuredTask || "unknown-session";
  const taskId = configuredTask || "unknown-task";
  let client = process.env.OPENUBMC_MCP_CLIENT?.trim();
  if (!client && process.env.CODEX_TASK_ID?.trim()) client = "codex";
  else if (!client && process.env.OPENUBMC_EVALUATION_TASK_ID?.trim()) client = "dsh";
  client ||= "unknown-client";
  const sourceCommit = process.env.OPENUBMC_MCP_SOURCE_COMMIT?.trim()
    || "unknown-source-commit";
  const modelIdentity = identityEnvironment("OPENUBMC_MCP_MODEL_IDENTITY");
  const codexIdentity = identityEnvironment("OPENUBMC_MCP_CODEX_IDENTITY");
  const formalRun = formalRunEnvironment();
  const configuredParentPid = process.env.OPENUBMC_MCP_PARENT_PID?.trim();
  let parentPid = configuredParentPid ? Number(configuredParentPid) : process.ppid;
  let startupError = null;
  if (
    (configuredParentPid && !/^[0-9]+$/.test(configuredParentPid))
    || !Number.isInteger(parentPid)
    || parentPid < 0
  ) {
    parentPid = 0;
    startupError = "OPENUBMC_MCP_PARENT_PID must be a non-negative integer";
  }
  const statePath = resolve(
    process.env.OPENUBMC_KB_STATE_PATH?.trim()
      || path
      || join(homedir(), ".config", "openubmc", "kb-mcp.json")
  );
  const runtimeStateRoot = process.env.OPENUBMC_TARGET_RUNTIME_STATE_DIR?.trim()
    || "";
  const lifecycleRoot = resolve(
    process.env.OPENUBMC_MCP_LIFECYCLE_DIR?.trim()
      || join(homedir(), ".local", "state", "openubmc-agent-workflow", "mcp-processes")
  );
  let idleTimeoutSeconds = 1800;
  try {
    idleTimeoutSeconds = positiveEnvironmentNumber(
      "OPENUBMC_MCP_IDLE_TIMEOUT_SECONDS",
      1800
    );
  } catch (error) {
    startupError ||= error.message;
  }
  startupError ||= modelIdentity.error || codexIdentity.error || formalRun.error;
  if (
    startupError === null
    && formalRun.value
    && (
      Object.keys(modelIdentity.value).length === 0
      || Object.keys(codexIdentity.value).length === 0
    )
  ) {
    startupError = "formal MCP run requires model and Codex identity";
  }
  if (startupError === null && formalRun.value) {
    const requirements = [];
    if (client !== "codex") requirements.push("Codex client identity");
    if (!configuredTask) requirements.push("task ID");
    if (!configuredSession) requirements.push("session ID");
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sourceCommit)) {
      requirements.push("full source commit");
    }
    if (!runtimeStateRoot) requirements.push("Runtime state root");
    if (!process.env.OPENUBMC_MCP_LIFECYCLE_DIR?.trim()) {
      requirements.push("lifecycle root");
    }
    if (requirements.length > 0) {
      startupError = `formal MCP run requires ${requirements.join(", ")}`;
    }
  }
  if (
    startupError === null
    && formalRun.value
    && parentPid !== process.ppid
  ) {
    startupError = "formal MCP run requires direct parent identity";
  }
  const lifecycle = new McpProcessLifecycle({
    component: "knowledge-mcp",
    version: "1.3.0",
    client,
    taskId,
    sessionId,
    sourceCommit,
    modelIdentity: modelIdentity.value,
    codexIdentity: codexIdentity.value,
    formalRun: formalRun.value,
    parentPid,
    statePath,
    runtimeStateRoot,
    lifecycleRoot,
    idleTimeoutSeconds
  });
  if (
    startupError === null
    && formalRun.value
    && lifecycle.status().parent_identity_verified !== true
  ) {
    startupError = "formal MCP run requires verified parent identity";
  }
  return {
    lifecycle,
    startupError
  };
}


export class PendingResponses {
  constructor() {
    this.requests = new Map();
  }

  add(requestId, onFinish = null) {
    const requests = this.requests.get(requestId) || [];
    requests.push(onFinish);
    this.requests.set(requestId, requests);
  }

  finish(requestId) {
    const requests = this.requests.get(requestId);
    if (!requests?.length) return false;
    const onFinish = requests.shift();
    if (!requests.length) this.requests.delete(requestId);
    onFinish?.();
    return true;
  }

  get size() {
    return this.requests.size;
  }
}


async function main() {
  const selectedConfigPath = configPath(process.argv.slice(2));
  const { lifecycle: processLifecycle, startupError } = createProcessLifecycle(
    selectedConfigPath
  );
  process.once("exit", () => {
    try {
      processLifecycle.recordExit("process-exit");
    } catch {
      // Active requests remain non-terminal until their response drains.
    }
  });
  if (startupError !== null) {
    processLifecycle.recordExit("startup-error");
    throw new Error(startupError);
  }
  let pollMilliseconds;
  try {
    pollMilliseconds = positiveEnvironmentNumber(
      "OPENUBMC_MCP_LIFECYCLE_POLL_SECONDS",
      0.25
    ) * 1000;
  } catch (error) {
    processLifecycle.recordExit("startup-error");
    throw error;
  }
  let server;
  try {
    server = await createServer(selectedConfigPath, processLifecycle);
  } catch (error) {
    processLifecycle.recordExit("startup-error");
    throw error;
  }
  const transport = new StdioServerTransport();
  const pendingResponses = new PendingResponses();
  transport.onmessage = message => {
    if (!Object.hasOwn(message, "id")) return;
    if (message.method === "tools/call") {
      // Tool work is tracked by its handler, even when the SDK omits a cancelled response.
      pendingResponses.add(message.id);
    } else {
      processLifecycle.beginRequest();
      pendingResponses.add(message.id, () => processLifecycle.endRequest());
    }
  };
  let stdinClosed = false;
  transport.onerror = error => {
    console.error(error instanceof Error ? error.message : "MCP stdio transport error");
  };
  let stopping = false;
  let pendingExitReason = null;
  let monitor;
  const send = transport.send.bind(transport);
  transport.send = async message => {
    const hasResponseId = Object.hasOwn(message, "id");
    const responseId = message.id;
    try {
      await send(message);
    } finally {
      if (hasResponseId) pendingResponses.finish(responseId);
    }
    monitor.unref();
    if (stdinClosed && pendingResponses.size === 0) {
      stop("stdin-closed", { exitProcess: true }).catch(() => {});
    }
  };
  const stop = async (reason, { exitProcess = false } = {}) => {
    if (stopping) return;
    const selectedReason = processLifecycle.shutdownReason || reason;
    if (processLifecycle.activeRequests > 0 || pendingResponses.size > 0) {
      processLifecycle.requestExit(selectedReason);
      pendingExitReason = selectedReason;
      return;
    }
    stopping = true;
    if (monitor !== undefined) clearInterval(monitor);
    processLifecycle.recordExit(selectedReason);
    await server.close().catch(() => {});
    if (exitProcess) process.exit(0);
  };
  const removeSignalHandlers = installMcpProcessSignalHandlers(processLifecycle);
  const stdinEnded = () => {
    stdinClosed = true;
    if (pendingResponses.size === 0) {
      stop("stdin-closed", { exitProcess: true }).catch(() => {});
    }
  };
  process.stdin.once("end", stdinEnded);
  process.stdin.once("close", stdinEnded);
  monitor = setInterval(async () => {
    if (
      pendingExitReason !== null
      && processLifecycle.activeRequests === 0
      && pendingResponses.size === 0
    ) {
      const reason = pendingExitReason;
      pendingExitReason = null;
      await stop(reason, { exitProcess: true });
      return;
    }
    const reason = processLifecycle.exitReasonIfDue();
    if (reason === null || stopping) return;
    await stop(reason, { exitProcess: true });
  }, pollMilliseconds);
  await server.connect(transport);
  const dispatch = transport.onmessage;
  transport.onmessage = (message, extra) => {
    const hasResponse = Object.hasOwn(message, "id");
    if (!hasResponse && message.method === "notifications/cancelled") {
      dispatch?.(message, extra);
      pendingResponses.finish(message.params?.requestId);
      return;
    }
    if (processLifecycle.shutdownRequested) {
      if (hasResponse) {
        send({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32000, message: "MCP process is shutting down" }
        }).catch(() => {});
      }
      return;
    }
    if (hasResponse) {
      const requestId = message.id;
      try {
        dispatch?.(message, extra);
      } catch (error) {
        pendingResponses.finish(requestId);
        throw error;
      }
      return;
    }
    dispatch?.(message, extra);
    if (message.method === "notifications/openubmc-task-complete") {
      processLifecycle.requestTaskCloseout();
      pendingExitReason = "task-closeout";
      if (processLifecycle.activeRequests === 0 && pendingResponses.size === 0) {
        stop("task-closeout", { exitProcess: true }).catch(() => {});
      }
    }
  };
  process.once("exit", () => {
    removeSignalHandlers();
    if (processLifecycle.activeRequests > 0) {
      processLifecycle.recordForcedExit("process-exit");
    }
  });
}


if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
