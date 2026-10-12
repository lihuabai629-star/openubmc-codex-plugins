import { spawnSync } from "node:child_process";

function helperEnvironment() {
  const allowed = ["SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP",
    "TMP", "LOCALAPPDATA", "USERPROFILE"];
  const environment = { PYTHONDONTWRITEBYTECODE: "1" };
  for (const name of allowed) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  return environment;
}

function invoke(action, value) {
  if (process.platform !== "win32") return { ok: true };
  const python = process.env.OPENUBMC_WINDOWS_PYTHON;
  const helper = process.env.OPENUBMC_WINDOWS_HELPER;
  if (!python || !helper) throw new Error("Windows private-store helper is unavailable");
  const result = spawnSync(python, ["-I", "-B", helper, action, String(value)], {
    encoding: "utf8", env: helperEnvironment(), windowsHide: true, timeout: 5000,
    maxBuffer: 4096
  });
  if (result.error || result.status !== 0) {
    throw new Error("Windows private-store check failed");
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("Windows private-store check returned invalid data");
  }
}

export function ensurePrivateDirectory(path) {
  invoke("ensure-directory", path);
}

export function verifyPrivatePath(path) {
  invoke("verify-path", path);
}

export function hardenNewFile(path) {
  invoke("harden-file", path);
}

export function windowsProcessState(pid) {
  return invoke("process-state", pid);
}
