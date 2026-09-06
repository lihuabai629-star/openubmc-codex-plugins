import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function normalizeToken(value) {
  if (!value || typeof value !== "object") return undefined;
  const accessToken = nonEmptyString(value.accessToken);
  const refreshToken = nonEmptyString(value.refreshToken);
  const expiresAt = Number(value.expiresAt);
  if (!accessToken && !refreshToken) return undefined;
  return {
    accessToken,
    refreshToken,
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : 0
  };
}

export function createTokenOwner(config) {
  return createHash("sha256")
    .update(`${config.userCenterUrl}\0${config.clientId}\0${config.username}`)
    .digest("hex");
}

export class FileTokenStore {
  constructor(path, owner) {
    this.path = path;
    this.owner = owner;
  }

  async load() {
    try {
      const value = JSON.parse(await readFile(this.path, "utf8"));
      if (value?.version !== 1 || value?.owner !== this.owner) return undefined;
      return normalizeToken(value);
    } catch {
      return undefined;
    }
  }

  async save(token) {
    try {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      const normalized = normalizeToken(token);
      const value = {
        version: 1,
        owner: this.owner,
        ...(normalized?.accessToken ? { accessToken: normalized.accessToken } : {}),
        ...(normalized?.refreshToken ? { refreshToken: normalized.refreshToken } : {}),
        ...(normalized ? { expiresAt: normalized.expiresAt } : {})
      };
      await writeFile(this.path, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
      if (process.platform !== "win32") await chmod(this.path, 0o600);
      return true;
    } catch {
      return false;
    }
  }

  clear() {
    return this.save(undefined);
  }
}
