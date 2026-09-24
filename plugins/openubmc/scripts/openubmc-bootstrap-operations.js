"use strict";

const childProcess = require("child_process");

const recoveryActions = Object.freeze({
  pip_unavailable: "Install Python pip in the selected Linux/WSL environment, then retry preparation.",
  npm_unavailable: "Install Node.js 20 or newer and npm in the selected Linux/WSL environment, then retry preparation.",
  registry_unavailable: "Restore package registry or DNS access in the selected Linux/WSL environment, then retry preparation.",
  proxy_failure: "Correct the proxy configuration in the selected Linux/WSL environment, then retry preparation.",
  dependency_prepare_timeout: "Check registry reachability and retry preparation after the timed-out worker exits.",
  dependency_prepare_interrupted: "Retry preparation; the incomplete staging cache was not activated.",
  dependency_hash_mismatch: "Use packages matching the release lock hashes, then retry preparation.",
  dependency_prepare_failed: "Review local package-manager connectivity and retry preparation.",
});

function parseJsonOutput(adapter, buffer) {
  try {
    const value = JSON.parse(adapter.decodeOutput(buffer));
    return value && typeof value === "object" ? value : null;
  } catch (_error) {
    return null;
  }
}

function progressRecords(adapter, buffer) {
  const records = [];
  for (const line of adapter.decodeOutput(buffer).split(/\r?\n/)) {
    try {
      const value = JSON.parse(line);
      if (value && typeof value === "object") records.push(value);
    } catch (_error) {
      // Unstructured package-manager output is never projected to the Agent.
    }
  }
  return records;
}

function relaySafeProgress(adapter, buffer) {
  for (const value of progressRecords(adapter, buffer)) {
    const progress = {};
    for (const key of ["stage", "status", "pid", "timeout_seconds", "elapsed_seconds", "exit_code"]) {
      if (Object.hasOwn(value, key)) progress[key] = value[key];
    }
    if (progress.stage && progress.status) process.stderr.write(`${JSON.stringify(progress)}\n`);
  }
}

function preparationFailure(adapter, prepared) {
  if (prepared.error?.code === "ETIMEDOUT") return "dependency_prepare_timeout";
  const records = progressRecords(adapter, prepared.stderr);
  const typed = records.map((record) => record.error_code).find((value) => recoveryActions[value]);
  if (typed) return typed;
  const text = records.map((record) => `${record.stage || ""} ${record.status || ""} ${record.error || ""}`).join(" ").toLowerCase();
  if (prepared.status === 130 || prepared.status === 143 || /interrupt|cancel/.test(text)) return "dependency_prepare_interrupted";
  if (/timeout|timed out/.test(text)) return "dependency_prepare_timeout";
  if (/proxy/.test(text)) return "proxy_failure";
  if (/could not resolve|registry|eai_again|enotfound|offline/.test(text)) return "registry_unavailable";
  if (/pip/.test(text) && /no module|enoent|not found|unavailable/.test(text)) return "pip_unavailable";
  if (/npm/.test(text) && /enoent|not found|unavailable/.test(text)) return "npm_unavailable";
  return "dependency_prepare_failed";
}

function createSetupOperations(adapter, capability) {
  function prepareBackend(backend) {
    const prepared = adapter.run(backend.command,
      [...backend.prefix, "prepare", "--capability", capability], { timeout: 600_000 });
    relaySafeProgress(adapter, prepared.stderr);
    if (prepared.error || prepared.status !== 0) {
      const reason = preparationFailure(adapter, prepared);
      return { ok: false, reason, recovery_action: recoveryActions[reason] };
    }
    return { ok: true };
  }

  function preflightBackend(backend) {
    const cleanup = adapter.run(backend.command, [...backend.prefix, "cleanup-retired"], { timeout: 15_000 });
    const cleanupReport = parseJsonOutput(adapter, cleanup.stdout);
    const checked = adapter.run(backend.command,
      [...backend.prefix, "doctor", "--capability", "all", ...backend.configurationArgs], { timeout: 45_000 });
    const report = parseJsonOutput(adapter, checked.stdout);
    const selected = report?.capabilities?.[capability];
    if (selected?.startup_ready && report?.codex_configuration?.ready) {
      return { ok: true, cleanup: cleanupReport, report };
    }
    const rawError = String(selected?.error || "").toLowerCase();
    let reason = "dependency_preflight_failed";
    if (rawError.includes("not prepared")) reason = "dependencies_not_prepared";
    else if (rawError.includes("cache drift")) reason = "dependency_cache_drift";
    else if (rawError.includes("node 20")) reason = "wsl_node_unavailable";
    else if (adapter.decodeOutput(checked.stderr).includes("plugin file inventory mismatch")) reason = "package_integrity_failed";
    else if (report?.codex_configuration && !report.codex_configuration.ready) reason = "configuration_repair_required";
    return { ok: false, reason, cleanup: cleanupReport, report };
  }

  function publicStatus(failure) {
    const report = failure.report || {};
    const packageIdentity = adapter.packageIdentity();
    const configuration = report.codex_configuration || {};
    const status = {
      schema: "openubmc.plugin-setup.v1",
      status: "setup_required",
      capability,
      host: adapter.hostPlatform === "win32" ? "windows" : "linux",
      reason: failure.reason,
      recovery_action: failure.recovery_action || recoveryActions[failure.reason]
        || "Use the openUBMC setup tools to repair the reported local prerequisite.",
      next_action: adapter.hostPlatform === "win32"
        ? "Use the openUBMC setup tools in this task, then start a new task."
        : "Use openubmc_setup_prepare in this task, then start a new task.",
      execution_host: adapter.hostPlatform === "win32" ? "wsl" : "linux",
      native_windows_build_supported: false,
      plugin: {
        version: report.version || packageIdentity.version,
        source_commit: report.source_commit || packageIdentity.source_commit,
        integrity: report.package_integrity === true || packageIdentity.integrity,
      },
      backend: {
        host: adapter.hostPlatform === "win32" ? "windows" : "linux",
        execution_host: adapter.hostPlatform === "win32" ? "wsl" : "linux",
        selected_wsl: failure.selected_wsl || null,
        native_windows_build_supported: false,
      },
      dependencies: Object.fromEntries(Object.entries(report.capabilities || {}).map(([name, value]) => [name, {
        ready: value.dependencies_ready === true,
        startup_ready: value.startup_ready === true,
      }])),
      protocol_health: report.mcp_health || {},
      local_configuration: report.local_configuration || {
        targets: { configured: false, active_revision: null },
        kb: { configured: false, active_revision: null },
        conan: { configured: false, active_revision: null },
      },
      knowledge_authentication: report.knowledge_authentication || "not_checked",
      remote_target_authentication: report.remote_target_authentication || "not_checked",
      configuration: {
        ready: configuration.ready === true,
        conflict: Boolean(configuration.conflicts?.length),
        mcp_servers: configuration.changes?.mcp_servers || [],
        skills: configuration.changes?.skills || [],
      },
    };
    if (Array.isArray(failure.distros)) status.available_wsl_distros = failure.distros;
    if (failure.selected_wsl) status.selected_wsl = failure.selected_wsl;
    return status;
  }

  function repairConfiguration(backend) {
    const operations = [];
    for (const command of ["repair-overrides", "migrate"]) {
      const mode = command === "migrate" ? ["--disable-only"] : [];
      const preview = adapter.run(backend.command,
        [...backend.prefix, command, ...mode, "--preview", ...backend.configurationArgs], { timeout: 30_000 });
      const previewReport = parseJsonOutput(adapter, preview.stdout);
      if (preview.error || !previewReport?.ok) return { ok: false, reason: "configuration_repair_conflict" };
      if (!previewReport.would_change) continue;
      const applied = adapter.run(backend.command,
        [...backend.prefix, command, ...mode, ...backend.configurationArgs], { timeout: 30_000 });
      const appliedReport = parseJsonOutput(adapter, applied.stdout);
      if (applied.error || applied.status !== 0 || !appliedReport?.ok) {
        return { ok: false, reason: "configuration_repair_failed" };
      }
      operations.push({ operation: command, transaction: appliedReport.transaction || null,
        mcp_servers: appliedReport.changes?.mcp_servers || [],
        skill_count: appliedReport.changes?.skills?.length || 0 });
    }
    return { ok: true, operations };
  }

  const configurationProcesses = new Set();
  function openConfiguration(backend, kind) {
    return new Promise((resolve, reject) => {
      const child = childProcess.spawn(backend.command,
        [...backend.prefix, "configure", "--kind", kind, "--open-browser"],
        { env: adapter.childEnvironment, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      configurationProcesses.add(child);
      let output = "";
      let settled = false;
      const fail = (reason) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        reject(new Error(reason));
      };
      const timer = setTimeout(() => fail("configuration_page_timeout"), 15_000);
      child.stdout.on("data", (chunk) => {
        if (settled) return;
        output += chunk.toString("utf8");
        if (!output.includes("\n")) return;
        const line = output.split(/\r?\n/, 1)[0].trim();
        if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\]):[0-9]+\/#[-A-Za-z0-9_]+$/.test(line)) {
          fail("configuration_page_invalid_url");
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(line);
      });
      child.stderr.resume();
      child.once("error", () => fail("configuration_page_start_failed"));
      child.once("exit", () => {
        configurationProcesses.delete(child);
        fail("configuration_page_start_failed");
      });
    });
  }

  function closeConfigurationProcesses() {
    for (const child of configurationProcesses) child.kill();
  }

  return { closeConfigurationProcesses, openConfiguration, preflightBackend,
    prepareBackend, publicStatus, repairConfiguration };
}

module.exports = { createSetupOperations, preparationFailure };
