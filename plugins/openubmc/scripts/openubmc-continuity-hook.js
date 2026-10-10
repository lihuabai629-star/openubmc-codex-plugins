#!/usr/bin/env node
"use strict";

// Advisory host hook. Reuse the same Linux/WSL selection as MCP without setup,
// target connections, installation, trust changes, or raw exception output.
const childProcess = require("child_process");
const path = require("path");
const { createHostAdapter } = require("./openubmc-bootstrap-host.js");

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
  try {
    const event = JSON.parse(input);
    if (!event || !["SessionStart", "UserPromptSubmit", "Stop"].includes(event.hook_event_name)) {
      process.stdout.write("{}\n");
      return;
    }
    const adapter = createHostAdapter({
      pluginRoot: path.resolve(__dirname, ".."),
      hostPlatform: process.env.OPENUBMC_PLUGIN_HOST_PLATFORM || process.platform,
      wslExecutable: process.env.OPENUBMC_PLUGIN_WSL_EXE || "wsl.exe",
    });
    const backend = adapter.resolveBackend();
    if (!backend.ok) throw new Error("host_unavailable");
    if (adapter.hostPlatform === "win32" && backend.selected_wsl && typeof event.cwd === "string") {
      const converted = adapter.run(process.env.OPENUBMC_PLUGIN_WSL_EXE || "wsl.exe",
        ["-d", backend.selected_wsl, "--exec", "wslpath", "-a", "-u", event.cwd]);
      if (converted.error || converted.status !== 0) throw new Error("host_cwd_unavailable");
      event.cwd = adapter.decodeOutput(converted.stdout).trim();
      input = JSON.stringify(event);
    }
    const result = childProcess.spawnSync(backend.command, [...backend.prefix, "host-hook"], {
      input, encoding: "utf8", env: adapter.childEnvironment, timeout: 8000,
      maxBuffer: 65536, windowsHide: true,
    });
    if (result.error || result.status !== 0) throw new Error("hook_unavailable");
    const output = JSON.parse(result.stdout);
    if (!output || typeof output !== "object" || Array.isArray(output)) throw new Error("invalid_output");
    process.stdout.write(JSON.stringify(output) + "\n");
  } catch (_) {
    process.stdout.write("{}\n");
  }
});
