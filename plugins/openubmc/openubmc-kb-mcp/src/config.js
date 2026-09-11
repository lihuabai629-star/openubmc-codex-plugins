import { activeConfiguration, readConfigurationJson } from "./configuration.js";
import { homedir } from "node:os";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { requestTimeoutMs } from "./http/request-lifetime.js";

const DEFAULTS = Object.freeze({
  lightragUrl: "https://discuss.openubmc.cn/rag",
  userCenterUrl: "https://usercenter.openubmc.cn",
  oauthBaseUrl: "https://omapi.openubmc.cn",
  clientId: "694bab197dd332233c960f7e",
  redirectUri: "openubmc://openubmc.openubmc-auth/callback",
  scopes: ["openid", "profile", "email", "offline_access"]
});

const requiredStrings = [
  "lightragUrl",
  "userCenterUrl",
  "oauthBaseUrl",
  "clientId",
  "redirectUri"
];

function normalizeUrl(value, field) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid URL in configuration field: ${field}`);
  }
  return url.toString().replace(/\/$/, "");
}

function normalizeLightRagUrl(value) {
  const normalized = normalizeUrl(value, "lightragUrl");
  const url = new URL(normalized);
  const loopback = ["localhost", "[::1]"].includes(url.hostname)
    || (isIP(url.hostname) === 4 && url.hostname.startsWith("127."));
  if (url.protocol !== "https:" && !loopback) {
    throw new Error("lightragUrl must use HTTPS unless it points to a loopback address");
  }
  return normalized;
}

function tokenCachePath(parsed, configPath) {
  if (typeof process.env.OPENUBMC_MCP_TOKEN_CACHE === "string" && process.env.OPENUBMC_MCP_TOKEN_CACHE.trim()) {
    return resolve(process.env.OPENUBMC_MCP_TOKEN_CACHE);
  }
  if (typeof parsed.tokenCachePath === "string" && parsed.tokenCachePath.trim()) {
    return resolve(dirname(configPath), parsed.tokenCachePath);
  }
  if (process.platform === "win32") {
    return join(process.env.LOCALAPPDATA || dirname(configPath), "openubmc-mcp", "token-cache.json");
  }
  return join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "openubmc-mcp", "token-cache.json");
}

function credentialValue(parsed, field, environmentName) {
  const environmentValue = process.env[environmentName];
  const normalize = value => typeof value === "string" ? (field === "username" ? value.trim() : value) : "";
  return normalize(environmentValue) || normalize(parsed[field]);
}

function defaultConfigPath() {
  const configHome = process.env.XDG_CONFIG_HOME?.trim();
  return join(configHome ? resolve(configHome) : join(homedir(), ".config"), "openubmc", "kb-mcp.json");
}

export async function loadConfig(
  path = process.env.OPENUBMC_KB_CONFIG || process.env.OPENUBMC_MCP_CONFIG || defaultConfigPath(),
  { allowMissingCredentials = false } = {}
) {
  const absolutePath = resolve(path);
  const active = await activeConfiguration(absolutePath);
  let parsed = await readConfigurationJson(active.path, {
    privateFile: active.revision !== null,
    missing: allowMissingCredentials && active.revision === null
  }) || {};

  parsed = { ...DEFAULTS, ...parsed };
  const username = credentialValue(parsed, "username", "OPENUBMC_KB_USERNAME");
  const password = credentialValue(parsed, "password", "OPENUBMC_KB_PASSWORD");
  const clientSecret = credentialValue(parsed, "clientSecret", "OPENUBMC_KB_CLIENT_SECRET");

  for (const field of requiredStrings) {
    if (typeof parsed[field] !== "string" || parsed[field].trim() === "") {
      throw new Error(`Missing required configuration field: ${field}`);
    }
  }
  if (!Array.isArray(parsed.scopes) || parsed.scopes.length === 0) {
    throw new Error("Missing required configuration field: scopes");
  }
  if (!allowMissingCredentials && !username) {
    throw new Error("Missing required configuration field: username");
  }
  if (!allowMissingCredentials && !password) {
    throw new Error("Missing required configuration field: password");
  }
  if (!allowMissingCredentials && !clientSecret) {
    throw new Error("Missing required configuration field: clientSecret");
  }

  const oauthBaseUrl = normalizeUrl(parsed.oauthBaseUrl, "oauthBaseUrl");
  return Object.freeze({
    ...parsed,
    requestTimeoutMs: requestTimeoutMs(parsed.requestTimeoutMs),
    username,
    password,
    credentialsConfigured: Boolean(username && password && clientSecret),
    configPath: absolutePath,
    configurationRevision: active.revision,
    clientSecret,
    lightragUrl: normalizeLightRagUrl(parsed.lightragUrl),
    userCenterUrl: normalizeUrl(parsed.userCenterUrl, "userCenterUrl"),
    oauthBaseUrl,
    authorizationEndpoint: `${oauthBaseUrl}/oneid/oidc/authorize`,
    tokenEndpoint: `${oauthBaseUrl}/oneid/oidc/token`,
    userInfoEndpoint: `${oauthBaseUrl}/oneid/oidc/user`,
    tokenCachePath: tokenCachePath(parsed, absolutePath)
  });
}
