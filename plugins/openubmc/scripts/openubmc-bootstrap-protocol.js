"use strict";

const { randomUUID } = require("crypto");
const readline = require("readline");

// Qualify the process that will actually serve the client. No tool call is
// forwarded until its initialize and private tools/list have both succeeded.
function createProtocolGate({ child, capability, expectedVersion, forward, output,
  onReady, onFailure, timeoutMs = 12_000 }) {
  const probeId = `openubmc-protocol-${randomUUID()}`;
  const expected = capability === "runtime" ? ["execute", "observe"]
    : ["openubmc_kb_list", "openubmc_kb_query", "openubmc_kb_status"];
  let initialize, initialized, timer, ready = false, failed = false, ended = false;
  let queuedBytes = 0;
  const queued = [];
  const responses = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });

  function fail(reason = "mcp_protocol_unhealthy") {
    if (failed || ready) return;
    failed = true;
    clearTimeout(timer);
    onFailure(reason, queued.splice(0), ended);
  }
  function send(value) { child.stdin.write(JSON.stringify(value) + "\n"); }
  responses.on("line", line => {
    if (failed) return;
    if (ready) return output(line);
    let response;
    try { response = JSON.parse(line); } catch { return fail(); }
    if (!initialize) return;
    if (!initialized && response.id === initialize.id) {
      const info = response.result?.serverInfo;
      if (response.error || !info || typeof info !== "object" || Array.isArray(info)
          || (capability === "kb" && info.version !== expectedVersion)) return fail();
      initialized = response;
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
      send({ jsonrpc: "2.0", id: probeId, method: "tools/list", params: {} });
    } else if (initialized && response.id === probeId) {
      const tools = response.result?.tools;
      const names = Array.isArray(tools) ? tools.map(tool => tool?.name).sort() : [];
      if (response.error || JSON.stringify(names) !== JSON.stringify(expected)) return fail();
      ready = true;
      clearTimeout(timer);
      onReady({ ok: true, checked: true, server: initialized.result.serverInfo,
        tools: names, version_matches_package: true, source: "live-mcp-session" });
      output(JSON.stringify(initialized));
      for (const request of queued.splice(0).slice(1)) accept(request);
      if (ended) child.stdin.end();
    }
  });
  responses.once("close", () => { if (!ready && !failed) fail(); });
  child.once("error", () => fail());
  child.once("exit", () => { if (!ready && !failed) fail(); });

  function accept(line) {
    if (failed) return;
    let request;
    try { request = JSON.parse(line); } catch {
      return output(JSON.stringify({ jsonrpc: "2.0", id: null,
        error: { code: -32700, message: "routing_request_invalid" } }));
    }
    if (ready) {
      // The child has already received this notification for the private probe.
      if (request?.method !== "notifications/initialized") forward(line);
      return;
    }
    queuedBytes += Buffer.byteLength(line, "utf8");
    if (queued.length >= 128 || queuedBytes > 2 * 1024 * 1024) return fail("mcp_startup_queue_limit");
    queued.push(line);
    if (!initialize) {
      if (request?.method !== "initialize" || request.id === undefined) return fail();
      initialize = request;
      timer = setTimeout(() => fail("mcp_protocol_timeout"), timeoutMs);
      send(request);
    }
  }
  return { accept, end() {
    ended = true;
    if (ready || !initialize) child.stdin.end();
  }, get failed() { return failed; } };
}

module.exports = { createProtocolGate };
