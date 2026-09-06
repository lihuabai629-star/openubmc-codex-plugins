import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync
} from "node:fs";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";


export const MCP_PROCESS_LIFECYCLE_SCHEMA = "openubmc.mcp-process-lifecycle.v1";


export function installMcpProcessSignalHandlers(
  lifecycle,
  processObject = process
) {
  const handler = () => lifecycle.requestExit("client-terminated");
  for (const signal of ["SIGTERM", "SIGINT"]) {
    processObject.on(signal, handler);
  }
  return () => {
    for (const signal of ["SIGTERM", "SIGINT"]) {
      processObject.removeListener(signal, handler);
    }
  };
}


function required(value, name) {
  if (typeof value !== "string") throw new Error(`${name} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${name} must not be empty`);
  return normalized;
}


function normalizedJsonObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  try {
    const normalized = JSON.parse(JSON.stringify(value));
    if (!normalized || typeof normalized !== "object" || Array.isArray(normalized)) {
      throw new Error(`${name} must be an object`);
    }
    return normalized;
  } catch (error) {
    if (error instanceof Error && error.message === `${name} must be an object`) {
      throw error;
    }
    throw new Error(`${name} must be JSON serializable`);
  }
}


function defaultProcessAlive(processId) {
  if (!Number.isInteger(processId) || processId <= 1) return false;
  try {
    process.kill(processId, 0);
  } catch (error) {
    return error?.code === "EPERM";
  }
  try {
    const stat = readFileSync(`/proc/${processId}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    const fields = commandEnd >= 0
      ? stat.slice(commandEnd + 2).trim().split(/\s+/)
      : [];
    return fields[0] !== "Z";
  } catch {
    return true;
  }
}


function defaultProcessIdentity(processId) {
  try {
    const stat = readFileSync(`/proc/${processId}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    const fields = commandEnd >= 0
      ? stat.slice(commandEnd + 2).trim().split(/\s+/)
      : [];
    return fields[19] || "unknown";
  } catch {
    return "unknown";
  }
}


export class McpProcessLifecycle {
  constructor({
    component,
    version,
    client,
    taskId,
    sessionId,
    sourceCommit = "unknown-source-commit",
    modelIdentity = {},
    codexIdentity = {},
    formalRun = false,
    parentPid,
    statePath,
    lifecycleRoot,
    idleTimeoutSeconds,
    processId = process.pid,
    runtimeStateRoot = "",
    monotonicClock = () => performance.now() / 1000,
    wallClock = () => Date.now(),
    processAlive = defaultProcessAlive,
    processIdentity = defaultProcessIdentity
  }) {
    this.component = required(component, "component");
    this.version = required(version, "version");
    this.client = required(client, "client");
    this.taskId = required(taskId, "taskId");
    this.sessionId = required(sessionId, "sessionId");
    this.sourceCommit = required(sourceCommit, "sourceCommit");
    this.modelIdentity = normalizedJsonObject(modelIdentity, "modelIdentity");
    this.codexIdentity = normalizedJsonObject(codexIdentity, "codexIdentity");
    if (typeof formalRun !== "boolean") {
      throw new Error("formalRun must be a boolean");
    }
    this.formalRun = formalRun;
    this.parentPid = Number(parentPid);
    this.processId = Number(processId);
    if (!Number.isInteger(this.parentPid) || this.parentPid < 0) {
      throw new Error("parentPid must be a non-negative integer");
    }
    if (!Number.isInteger(this.processId) || this.processId <= 0) {
      throw new Error("processId must be a positive integer");
    }
    this.statePath = resolve(statePath);
    this.runtimeStateRoot = runtimeStateRoot ? resolve(runtimeStateRoot) : "";
    this.lifecycleRoot = resolve(lifecycleRoot);
    this.idleTimeoutSeconds = Number(idleTimeoutSeconds);
    if (!Number.isFinite(this.idleTimeoutSeconds) || !(this.idleTimeoutSeconds > 0)) {
      throw new Error("idleTimeoutSeconds must be finite and positive");
    }
    this.monotonicClock = monotonicClock;
    this.wallClock = wallClock;
    this.processAlive = processAlive;
    this.identityReader = processIdentity;
    this.processIdentity = processIdentity(this.processId);
    this.parentIdentity = this.parentPid > 1 && processAlive(this.parentPid)
      ? processIdentity(this.parentPid)
      : "unknown";
    this.parentIdentityVerifiedEver = this.parentIdentity !== "unknown"
      && this.parentIdentityCurrentlyVerified();
    this.startedMonotonic = monotonicClock();
    this.lastActivity = this.startedMonotonic;
    this.startedAt = this.timestamp();
    this.activeRequests = 0;
    this.exitReason = null;
    this.requestedExitReason = null;
    this.lastPersistedState = "";
    mkdirSync(this.lifecycleRoot, { recursive: true, mode: 0o700 });
    const safeComponent = this.component.replace(/[^A-Za-z0-9.-]/g, "-");
    const identityKey = this.processIdentity === "unknown"
      ? this.startedAt
      : this.processIdentity;
    const safeIdentity = identityKey.replace(/[^A-Za-z0-9.-]/g, "-");
    this.recordPath = join(
      this.lifecycleRoot,
      `${safeComponent}-${this.processId}-${safeIdentity}.json`
    );
    this.persist();
  }

  timestamp() {
    return new Date(this.wallClock()).toISOString();
  }

  lifecycleState() {
    if (this.exitReason !== null) return "stopped";
    if (this.parentPid <= 1) return "unknown-owner";
    try {
      if (!this.processAlive(this.parentPid)) return "orphaned";
      const currentParentIdentity = this.identityReader(this.parentPid);
      if (this.parentIdentity === "unknown") {
        if (currentParentIdentity === "unknown") return "unknown-owner";
        this.parentIdentity = currentParentIdentity;
      }
      if (
        this.parentIdentity !== "unknown"
        && currentParentIdentity === "unknown"
      ) return "unknown-owner";
      if (
        this.parentIdentity !== "unknown"
        && currentParentIdentity !== this.parentIdentity
      ) return "orphaned";
      this.parentIdentityVerifiedEver = true;
    } catch {
      return "unknown-owner";
    }
    if (this.client === "unknown-client" || this.taskId === "unknown-task") {
      return "unknown-owner";
    }
    return this.activeRequests > 0 ? "active" : "idle";
  }

  parentIdentityCurrentlyVerified() {
    if (this.parentPid <= 1 || this.parentIdentity === "unknown") return false;
    try {
      return this.processAlive(this.parentPid)
        && this.identityReader(this.parentPid) === this.parentIdentity;
    } catch {
      return false;
    }
  }

  status() {
    const lifecycleState = this.lifecycleState();
    const parentIdentityCurrentlyVerified = this.parentIdentityCurrentlyVerified();
    if (parentIdentityCurrentlyVerified) this.parentIdentityVerifiedEver = true;
    return {
      schema: MCP_PROCESS_LIFECYCLE_SCHEMA,
      component: this.component,
      version: this.version,
      client: this.client,
      task_id: this.taskId,
      session_id: this.sessionId,
      source_commit: this.sourceCommit,
      model_identity: { ...this.modelIdentity },
      codex_identity: { ...this.codexIdentity },
      formal_run: this.formalRun,
      parent_pid: this.parentPid,
      parent_identity: this.parentIdentity,
      parent_identity_verified: this.parentIdentityVerifiedEver,
      parent_identity_currently_verified: parentIdentityCurrentlyVerified,
      process_id: this.processId,
      process_identity: this.processIdentity,
      start_time: this.startedAt,
      updated_at: this.timestamp(),
      state_path: this.statePath,
      runtime_state_root: this.runtimeStateRoot,
      lifecycle_state: lifecycleState,
      active_requests: this.activeRequests,
      idle_seconds: Math.max(0, this.monotonicClock() - this.lastActivity),
      idle_timeout_seconds: this.idleTimeoutSeconds,
      shutdown_requested: this.requestedExitReason,
      exit_reason: this.exitReason
    };
  }

  attribute({ client, taskId, sessionId } = {}) {
    let changed = false;
    if (this.client === "unknown-client" && client) {
      this.client = required(client, "client");
      changed = true;
    }
    if (this.taskId === "unknown-task" && taskId) {
      this.taskId = required(taskId, "taskId");
      changed = true;
    }
    if (this.sessionId === "unknown-session" && sessionId) {
      this.sessionId = required(sessionId, "sessionId");
      changed = true;
    }
    if (changed) this.persist();
  }

  persist() {
    const temporary = `${this.recordPath}.tmp`;
    const status = this.status();
    writeFileSync(temporary, `${JSON.stringify(status, null, 2)}\n`, "utf8");
    chmodSync(temporary, 0o600);
    renameSync(temporary, this.recordPath);
    this.lastPersistedState = status.lifecycle_state;
  }

  async request(callback) {
    this.beginRequest();
    try {
      return await callback();
    } finally {
      this.endRequest();
    }
  }

  beginRequest() {
    const reason = this.exitReason || this.requestedExitReason;
    if (reason !== null) {
      throw new Error(`MCP process is shutting down: ${reason}`);
    }
    this.activeRequests += 1;
    this.lastActivity = this.monotonicClock();
    this.persist();
  }

  endRequest() {
    if (this.activeRequests <= 0) {
      throw new Error("cannot finish an inactive MCP request");
    }
    this.activeRequests -= 1;
    this.lastActivity = this.monotonicClock();
    this.persist();
  }

  exitReasonIfDue() {
    if (this.exitReason !== null) return this.exitReason;
    const status = this.status();
    if (this.activeRequests > 0) {
      if (
        status.lifecycle_state === "orphaned"
        && this.requestedExitReason === null
      ) {
        this.requestedExitReason = "parent-exited";
      }
      if (status.lifecycle_state !== this.lastPersistedState) this.persist();
      else if (this.requestedExitReason !== null) this.persist();
      return null;
    }
    let reason = null;
    if (this.requestedExitReason !== null) reason = this.requestedExitReason;
    else if (status.lifecycle_state === "orphaned") reason = "parent-exited";
    else if (
      status.lifecycle_state === "idle"
      && status.idle_seconds >= this.idleTimeoutSeconds
    ) reason = "idle-timeout";
    if (reason === null) {
      if (status.lifecycle_state !== this.lastPersistedState) this.persist();
      return null;
    }
    this.exitReason = reason;
    this.requestedExitReason = null;
    this.persist();
    return reason;
  }

  requestExit(reason) {
    if (this.exitReason === null && this.requestedExitReason === null) {
      this.requestedExitReason = required(reason, "exitReason");
      this.persist();
    }
  }

  requestTaskCloseout() {
    this.requestExit("task-closeout");
  }

  get shutdownRequested() {
    return this.requestedExitReason !== null || this.exitReason !== null;
  }

  get shutdownReason() {
    return this.exitReason || this.requestedExitReason;
  }

  recordExit(reason) {
    if (this.activeRequests > 0) {
      throw new Error("cannot stop an MCP process with active requests");
    }
    if (this.exitReason === null) this.exitReason = required(reason, "exitReason");
    this.persist();
  }

  recordForcedExit(reason) {
    if (this.exitReason === null) this.exitReason = required(reason, "exitReason");
    this.requestedExitReason = null;
    this.activeRequests = 0;
    this.persist();
  }
}
