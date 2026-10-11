#!/usr/bin/env node
"use strict";

// Advisory host hook. Reuse the same Linux/WSL selection as MCP without setup,
// target connections, installation, trust changes, or raw exception output.
const path = require("path");
const { performance } = require("perf_hooks");
const { createHostAdapter } = require("./openubmc-bootstrap-host.js");

function workflowContext(adapter, eventName) {
  if (!["SessionStart", "UserPromptSubmit"].includes(eventName)) return {};
  const identity = adapter.packageIdentity();
  if (!identity.integrity) return {};
  const guide = path.join(__dirname, "..", "skills", "openubmc-debug", "references", "skill-routing.md");
  return { hookSpecificOutput: { hookEventName: eventName, additionalContext:
    `For openUBMC tasks, before the first workflow action and when the stage changes, ` +
    `read ${JSON.stringify(guide)}, select the current owner from the active Skill catalog, ` +
    `and read that owner's SKILL.md. Use the ordinary direct path for specified mechanical edits. ` +
    `Carry existing authorization and Run identity; continue authorized work without new Skill confirmations. ` +
    `For unrelated tasks, proceed normally. This is advisory, not proof of loading or execution. ` +
    `Plugin version: ${identity.version}; source: ${identity.source_commit}.` } };
}

function withWorkflowContext(output, guidance) {
  if (!guidance.hookSpecificOutput) return output;
  const specific = output.hookSpecificOutput || {};
  return { ...output, hookSpecificOutput: { ...specific,
    hookEventName: guidance.hookSpecificOutput.hookEventName,
    additionalContext: [specific.additionalContext, guidance.hookSpecificOutput.additionalContext]
      .filter((value) => typeof value === "string" && value).join("\n\n") } };
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  if (Buffer.byteLength(input) > 65536) {
    process.stdout.write("{}\n");
    process.exit(0);
  }
});
process.stdin.on("end", () => {
  let guidance = {};
  try {
    const event = JSON.parse(input);
    if (!event || typeof event !== "object" || Array.isArray(event)
        || !["SessionStart", "UserPromptSubmit", "Stop"].includes(event.hook_event_name)) {
      process.stdout.write("{}\n");
      return;
    }
    const adapter = createHostAdapter({
      pluginRoot: path.resolve(__dirname, ".."),
      hostPlatform: process.env.OPENUBMC_PLUGIN_HOST_PLATFORM || process.platform,
      wslExecutable: process.env.OPENUBMC_PLUGIN_WSL_EXE || "wsl.exe",
      // The Host allows 15 seconds. Share one deadline across all Python
      // probes and the backend, leaving time to return local guidance.
      deadlineMs: performance.now() + 10_000,
    });
    guidance = workflowContext(adapter, event.hook_event_name);
    // Guidance survives backend failure. Still forward prompt events so the
    // existing trusted workspace selection is refreshed for subsequent Runs.
    const backend = adapter.resolveBackend();
    if (!backend.ok) throw new Error("host_unavailable");
    if (adapter.hostPlatform === "win32" && backend.selected_wsl && typeof event.cwd === "string") {
      const converted = adapter.run(process.env.OPENUBMC_PLUGIN_WSL_EXE || "wsl.exe",
        ["-d", backend.selected_wsl, "--exec", "wslpath", "-a", "-u", event.cwd]);
      if (converted.error || converted.status !== 0) throw new Error("host_cwd_unavailable");
      event.cwd = adapter.decodeOutput(converted.stdout).trim();
      input = JSON.stringify(event);
    }
    const result = adapter.run(backend.command, [...backend.prefix, "host-hook"], {
      input, encoding: "utf8", timeout: 8000, maxBuffer: 65536,
    });
    if (result.error || result.status !== 0) throw new Error("hook_unavailable");
    const output = JSON.parse(result.stdout);
    if (!output || typeof output !== "object" || Array.isArray(output)) throw new Error("invalid_output");
    process.stdout.write(JSON.stringify(withWorkflowContext(output, guidance)) + "\n");
  } catch (_) {
    process.stdout.write(JSON.stringify(guidance) + "\n");
  }
});
