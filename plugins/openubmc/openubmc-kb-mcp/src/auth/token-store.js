import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { spawn } from "node:child_process";
import { constants } from "node:fs";

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
    .update(JSON.stringify([config.userCenterUrl, config.oauthBaseUrl, config.lightragUrl,
      config.clientId, config.username, config.configurationRevision || null,
      config.knowledgeMcpVersion || null]))
    .digest("hex");
}

export class FileTokenStore {
  constructor(path, owner) {
    // Account/configuration revisions cannot replace another owner's cache.
    this.path = `${path}.${createHash("sha256").update(owner).digest("hex")}`;
    this.owner = owner;
  }

  async withLock(operation, { signal } = {}) {
    signal?.throwIfAborted();
    let file;
    try {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      file = await open(`${this.path}.lock`, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    } catch {
      throw Object.assign(new Error("KB token coordination cannot access the private cache"),
        { code: "KB_AUTH_LOCK_UNAVAILABLE" });
    }
    try {
      // flock and this process share the open file description. The kernel
      // releases the lock on close/process exit, with no stale lock eviction.
      await new Promise((resolve, reject) => {
        const child = spawn("flock", ["--exclusive", "--timeout", "30", "3"], {
          stdio: ["ignore", "ignore", "ignore", file.fd], signal
        });
        let failure;
        child.on("error", error => { failure = error; });
        child.on("close", code => {
          if (signal?.aborted) reject(signal.reason);
          else if (failure || code !== 0) reject(Object.assign(
            new Error(failure ? "KB token coordination requires the local flock utility" : "KB token cache lock timed out"),
            { code: failure ? "KB_AUTH_LOCK_UNAVAILABLE" : "KB_AUTH_LOCK_TIMEOUT" }));
          else resolve();
        });
      });
      signal?.throwIfAborted();
      return await operation();
    } finally {
      await file.close();
    }
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
    const temporary = `${this.path}.${randomUUID()}.tmp`;
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
      const file = await open(temporary, "wx", 0o600);
      try {
        await file.writeFile(`${JSON.stringify(value)}\n`, "utf8");
        await file.sync();
      } finally {
        await file.close();
      }
      await chmod(temporary, 0o600);
      await rename(temporary, this.path);
      return true;
    } catch {
      await unlink(temporary).catch(() => {});
      return false;
    }
  }

  clear() {
    return this.save(undefined);
  }
}
