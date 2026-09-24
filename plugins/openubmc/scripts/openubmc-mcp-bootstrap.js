#!/usr/bin/env node
"use strict";

// This entrypoint uses only Node built-ins so setup remains available before
// either packaged backend has prepared its locked dependencies.
const childProcess = require("child_process");
const path = require("path");
const readline = require("readline");
const { createHostAdapter } = require("./openubmc-bootstrap-host.js");
const { createSetupOperations } = require("./openubmc-bootstrap-operations.js");

const capability = process.argv[2];
if (!new Set(["runtime", "kb"]).has(capability)) {
  process.stderr.write("usage: openubmc-mcp-bootstrap.js runtime|kb\n");
  process.exit(2);
}

const hostPlatform = process.env.OPENUBMC_PLUGIN_HOST_PLATFORM || process.platform;
const adapter = createHostAdapter({
  pluginRoot: path.resolve(__dirname, ".."),
  hostPlatform,
  wslExecutable: process.env.OPENUBMC_PLUGIN_WSL_EXE || "wsl.exe",
});
const operations = createSetupOperations(adapter, capability);

function safeWriteError(value) {
  if (value) process.stderr.write(String(value).slice(-8192));
}

function proxyBackend(backend) {
  const child = childProcess.spawn(backend.command, [...backend.prefix, capability], {
    env: adapter.childEnvironment,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  process.stdin.pipe(child.stdin);
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);
  const stop = () => {
    if (!child.killed) child.kill();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  process.stdin.once("end", () => child.stdin.end());
  child.once("error", (error) => {
    safeWriteError(`openUBMC backend failed to start: ${error.code || "spawn_failed"}\n`);
    process.exitCode = 1;
  });
  child.once("exit", (code) => {
    process.exitCode = code === null ? 1 : code;
  });
}

function serveSetup(initialFailure) {
  const initialStatus = operations.publicStatus(initialFailure);
  const lineReader = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const reply = (id, result) => process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
  const error = (id, code, message) => process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
  const toolReply = (id, response, isError = false) => reply(id, {
    content: [{ type: "text", text: JSON.stringify(response) }],
    structuredContent: response,
    isError,
  });
  const refreshedStatus = () => {
    const backend = adapter.resolveBackend();
    if (!backend.ok) return operations.publicStatus(backend);
    const preflight = operations.preflightBackend(backend);
    return operations.publicStatus({ ...backend, ...preflight, ok: false });
  };

  lineReader.on("line", (line) => {
    if (!line.trim()) return;
    let request;
    try {
      request = JSON.parse(line);
    } catch (_parseError) {
      error(null, -32700, "Parse error");
      return;
    }
    if (request.id === undefined || request.id === null) return;
    if (request.method === "initialize") {
      reply(request.id, {
        protocolVersion: request.params?.protocolVersion || "2024-11-05",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: `openubmc-${capability}-setup`, version: "1" },
        instructions: "The openUBMC backend needs local setup. Call openubmc_setup_status for the structured reason.",
      });
      return;
    }
    if (request.method === "ping") {
      reply(request.id, {});
      return;
    }
    if (request.method === "tools/list") {
      reply(request.id, { tools: [
        { name: "openubmc_setup_status",
          description: "Return separate package, host, dependency, configuration and protocol-health facts without exposing credentials.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false } },
        { name: "openubmc_setup_select_wsl",
          description: "Select an installed WSL distribution for the openUBMC Linux backend.",
          inputSchema: { type: "object", properties: { distro: { type: "string", description: "An exact name from available_wsl_distros." } }, required: ["distro"], additionalProperties: false } },
        { name: "openubmc_setup_prepare",
          description: "Prepare the locked dependencies for this openUBMC capability outside MCP initialization.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false } },
        { name: "openubmc_setup_open_configuration",
          description: "Open the private local openUBMC configuration page and return its loopback URL.",
          inputSchema: { type: "object", properties: { kind: { type: "string", enum: ["targets", "kb", "conan"] } }, required: ["kind"], additionalProperties: false } },
        { name: "openubmc_setup_repair_configuration",
          description: "Back up and repair recognized stale openUBMC MCP overrides and exact-name loose Skills.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false } },
      ] });
      return;
    }
    if (request.method === "tools/call") {
      const name = request.params?.name;
      if (name === "openubmc_setup_status") {
        toolReply(request.id, refreshedStatus());
        return;
      }
      if (name === "openubmc_setup_select_wsl") {
        try {
          adapter.saveSelectedDistro(request.params?.arguments?.distro,
            refreshedStatus().available_wsl_distros || initialStatus.available_wsl_distros || []);
          toolReply(request.id, { schema: initialStatus.schema, status: "configuration_saved",
            selected_wsl: request.params.arguments.distro,
            next_action: "Start a new Codex task to initialize the openUBMC backend." });
        } catch (selectionError) {
          toolReply(request.id, { ...refreshedStatus(), error: selectionError.message }, true);
        }
        return;
      }
      if (name === "openubmc_setup_prepare") {
        const backend = adapter.resolveBackend();
        if (!backend.ok) {
          toolReply(request.id, operations.publicStatus(backend), true);
          return;
        }
        const prepared = operations.prepareBackend(backend);
        if (!prepared.ok) {
          toolReply(request.id, operations.publicStatus({ ...backend, ...prepared, ok: false }), true);
          return;
        }
        toolReply(request.id, { schema: initialStatus.schema, status: "preparation_completed", capability,
          next_action: "Start a new Codex task to use the prepared openUBMC backend." });
        return;
      }
      if (name === "openubmc_setup_open_configuration") {
        const kind = request.params?.arguments?.kind;
        if (!new Set(["targets", "kb", "conan"]).has(kind)) {
          error(request.id, -32602, "Invalid configuration kind");
          return;
        }
        const backend = adapter.resolveBackend();
        if (!backend.ok) {
          toolReply(request.id, operations.publicStatus(backend), true);
          return;
        }
        operations.openConfiguration(backend, kind).then((url) => toolReply(request.id, {
          schema: initialStatus.schema, status: "configuration_page_ready", kind, url,
          next_action: "Open the loopback URL and keep this task running while editing.",
        })).catch((configurationError) => toolReply(request.id,
          operations.publicStatus({ ...backend, reason: configurationError.message }), true));
        return;
      }
      if (name === "openubmc_setup_repair_configuration") {
        const backend = adapter.resolveBackend();
        if (!backend.ok) {
          toolReply(request.id, operations.publicStatus(backend), true);
          return;
        }
        const repaired = operations.repairConfiguration(backend);
        if (!repaired.ok) {
          toolReply(request.id, operations.publicStatus({ ...backend, ...repaired }), true);
          return;
        }
        toolReply(request.id, { schema: initialStatus.schema, status: "configuration_repaired",
          operations: repaired.operations,
          next_action: "Start a new Codex task and check openUBMC Runtime and knowledge service health." });
        return;
      }
      error(request.id, -32602, "Unknown setup tool");
      return;
    }
    if (request.method === "resources/list" || request.method === "prompts/list") {
      reply(request.id, { [request.method.startsWith("resources") ? "resources" : "prompts"]: [] });
      return;
    }
    error(request.id, -32601, "Method not found");
  });
  lineReader.once("close", operations.closeConfigurationProcesses);
}

const backend = adapter.resolveBackend();
if (!backend.ok) {
  serveSetup(backend);
} else {
  const preflight = operations.preflightBackend(backend);
  if (!preflight.ok) serveSetup({ ...backend, ...preflight, ok: false });
  else proxyBackend(backend);
}
