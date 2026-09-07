import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const { loadConfig } = await import(process.env.OPENUBMC_TEST_PLUGIN_ROOT
  ? pathToFileURL(join(process.env.OPENUBMC_TEST_PLUGIN_ROOT, "openubmc-kb-mcp/src/config.js"))
  : "../src/config.js");

const valid = {
  lightragUrl: "http://127.0.0.1:8899",
  userCenterUrl: "https://usercenter.example.com",
  oauthBaseUrl: "https://oauth.example.com",
  clientId: "client",
  clientSecret: "secret",
  redirectUri: "openubmc://openubmc.openubmc-auth/callback",
  scopes: ["openid", "offline_access"],
  username: "user",
  password: "password"
};

async function configFile(value) {
  const dir = await mkdtemp(join(tmpdir(), "openubmc-mcp-"));
  const path = join(dir, "config.json");
  await writeFile(path, JSON.stringify(value));
  return path;
}

test("loads and normalizes a complete local configuration", async () => {
  const path = await configFile({ ...valid, tokenCachePath: "private/token.json" });
  const config = await loadConfig(path);
  assert.equal(config.lightragUrl, "http://127.0.0.1:8899");
  assert.equal(config.authorizationEndpoint, "https://oauth.example.com/oneid/oidc/authorize");
  assert.equal(config.tokenEndpoint, "https://oauth.example.com/oneid/oidc/token");
  assert.equal(config.tokenCachePath, join(dirname(path), "private", "token.json"));
});

test("preserves exact file and environment secrets while normalizing usernames", async () => {
  const fields = ["OPENUBMC_KB_USERNAME", "OPENUBMC_KB_PASSWORD", "OPENUBMC_KB_CLIENT_SECRET"];
  const previous = fields.map(field => process.env[field]);
  const path = await configFile({ ...valid, username: " user ", password: " password!'  ", clientSecret: " secret!'  " });
  try {
    for (const field of fields) delete process.env[field];
    let config = await loadConfig(path);
    assert.equal(config.username, "user");
    assert.equal(config.password, " password!'  ");
    assert.equal(config.clientSecret, " secret!'  ");
    process.env.OPENUBMC_KB_USERNAME = " env-user ";
    process.env.OPENUBMC_KB_PASSWORD = " env-password!'  ";
    process.env.OPENUBMC_KB_CLIENT_SECRET = " env-secret!'  ";
    config = await loadConfig(path);
    assert.equal(config.username, "env-user");
    assert.equal(config.password, " env-password!'  ");
    assert.equal(config.clientSecret, " env-secret!'  ");
  } finally {
    fields.forEach((field, index) => {
      if (previous[index] === undefined) delete process.env[field];
      else process.env[field] = previous[index];
    });
  }
});

test("rejects missing credentials without including secret values", async () => {
  const path = await configFile({ ...valid, username: "", password: "do-not-print" });
  await assert.rejects(() => loadConfig(path), error => {
    assert.match(error.message, /username/);
    assert.doesNotMatch(error.message, /do-not-print/);
    return true;
  });
});

test("starts with bundled endpoints when credentials are not configured", async () => {
  const path = join(await mkdtemp(join(tmpdir(), "openubmc-mcp-")), "missing.json");
  const config = await loadConfig(path, { allowMissingCredentials: true });
  assert.equal(config.credentialsConfigured, false);
  assert.equal(config.lightragUrl, "https://discuss.openubmc.cn/rag");
});

test("uses the managed user configuration path by default", async () => {
  const previousConfig = process.env.OPENUBMC_KB_CONFIG;
  const previousLegacyConfig = process.env.OPENUBMC_MCP_CONFIG;
  const previousXdgConfigHome = process.env.XDG_CONFIG_HOME;
  const root = await mkdtemp(join(tmpdir(), "openubmc-config-home-"));
  delete process.env.OPENUBMC_KB_CONFIG;
  delete process.env.OPENUBMC_MCP_CONFIG;
  process.env.XDG_CONFIG_HOME = root;
  try {
    const config = await loadConfig(undefined, { allowMissingCredentials: true });
    assert.equal(config.configPath, join(root, "openubmc", "kb-mcp.json"));
  } finally {
    if (previousConfig === undefined) delete process.env.OPENUBMC_KB_CONFIG;
    else process.env.OPENUBMC_KB_CONFIG = previousConfig;
    if (previousLegacyConfig === undefined) delete process.env.OPENUBMC_MCP_CONFIG;
    else process.env.OPENUBMC_MCP_CONFIG = previousLegacyConfig;
    if (previousXdgConfigHome === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousXdgConfigHome;
  }
});

test("requires an external OAuth client secret and starts unconfigured without it", async () => {
  const { clientSecret, ...withoutSecret } = valid;
  const path = await configFile(withoutSecret);
  await assert.rejects(() => loadConfig(path), /clientSecret/);
  const config = await loadConfig(path, { allowMissingCredentials: true });
  assert.equal(config.clientSecret, "");
  assert.equal(config.credentialsConfigured, false);
});

test("uses a private environment client secret without writing it to configuration", async () => {
  const previous = process.env.OPENUBMC_KB_CLIENT_SECRET;
  process.env.OPENUBMC_KB_CLIENT_SECRET = "external-test-client-secret";
  try {
    const { clientSecret, ...withoutSecret } = valid;
    const config = await loadConfig(await configFile(withoutSecret));
    assert.equal(config.clientSecret, "external-test-client-secret");
    assert.equal(config.credentialsConfigured, true);
  } finally {
    if (previous === undefined) delete process.env.OPENUBMC_KB_CLIENT_SECRET;
    else process.env.OPENUBMC_KB_CLIENT_SECRET = previous;
  }
});

test("rejects insecure non-loopback LightRAG URLs", async () => {
  const path = await configFile({ ...valid, lightragUrl: "http://kb.example.com" });
  await assert.rejects(
    () => loadConfig(path),
    /HTTPS/
  );
});
