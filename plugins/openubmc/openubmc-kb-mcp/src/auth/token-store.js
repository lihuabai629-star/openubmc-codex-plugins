import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { ensurePrivateDirectory, hardenNewFile, verifyPrivatePath } from "../windows-private.js";

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
    this.path = path;
    this.owner = owner;
  }

  async load() {
    try {
      if (process.platform === "win32") {
        verifyPrivatePath(dirname(this.path));
        verifyPrivatePath(this.path);
      }
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
      if (process.platform === "win32") ensurePrivateDirectory(dirname(this.path));
      else await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
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
        if (process.platform === "win32") hardenNewFile(temporary);
        await file.writeFile(`${JSON.stringify(value)}\n`, "utf8");
        await file.sync();
      } finally {
        await file.close();
      }
      if (process.platform !== "win32") await chmod(temporary, 0o600);
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
