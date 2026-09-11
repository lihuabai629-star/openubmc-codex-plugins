import { readResponseText } from "../http/read-response.js";
import { constants, publicEncrypt, randomBytes } from "node:crypto";
import { CookieJar } from "../http/cookie-jar.js";
import { createTokenOwner, FileTokenStore } from "./token-store.js";
import { waitForRequest } from "../http/request-lifetime.js";

const TOKEN_EXPIRY_MARGIN_MS = 180_000;
const DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;

export class CaptchaRequiredError extends Error {
  constructor() {
    super("openUBMC login requires an interactive CAPTCHA; knowledge-base access was blocked");
    this.name = "CaptchaRequiredError";
    this.code = "KB_INTERACTION_REQUIRED";
  }
}

function unwrap(value) {
  return value?.data?.data ?? value?.data ?? value;
}

async function responseJson(response, operation) {
  const text = await readResponseText(response, 256 * 1024);
  let value;
  try { value = text ? JSON.parse(text) : {}; } catch { value = {}; }
  if (!response.ok) {
    const detail = value?.msg?.message_zh
      ?? value?.msg?.message_en
      ?? (typeof value?.msg === "string" ? value.msg : undefined)
      ?? value?.error_description
      ?? value?.error
      ?? (typeof value?.message === "string" ? value.message : undefined);
    const suffix = typeof detail === "string" && detail.trim() ? `: ${detail.trim().slice(0, 200)}` : "";
    const error = new Error(`${operation} failed with HTTP ${response.status}${suffix}`);
    error.status = response.status;
    throw error;
  }
  return value;
}

function tokenFromResponse(value, now, previousRefreshToken) {
  if (!value?.access_token) throw new Error("OAuth token response does not contain access_token");
  const expiresIn = Number(value.expires_in);
  const lifetimeSeconds = Number.isFinite(expiresIn) && expiresIn > 0
    ? expiresIn
    : DEFAULT_TOKEN_LIFETIME_SECONDS;
  return {
    accessToken: value.access_token,
    refreshToken: value.refresh_token || previousRefreshToken,
    expiresAt: now() + lifetimeSeconds * 1000
  };
}

export class OneIdClient {
  constructor(config, dependencies = {}) {
    this.config = config;
    this.fetch = dependencies.fetch || globalThis.fetch;
    this.stateFactory = dependencies.stateFactory || (() => randomBytes(32).toString("base64url"));
    this.now = dependencies.now || (() => Date.now());
    this.tokenStore = dependencies.tokenStore || new FileTokenStore(config.tokenCachePath, createTokenOwner(config));
    this.jar = new CookieJar();
    this.token = undefined;
    this.cacheLoaded = false;
    this.cacheLoadPromise = undefined;
    this.tokenPromise = undefined;
  }

  async loadCachedToken() {
    if (this.cacheLoaded) return;
    if (!this.cacheLoadPromise) {
      this.cacheLoadPromise = this.tokenStore.load().then(token => {
        this.token = token;
        this.cacheLoaded = true;
      });
    }
    await this.cacheLoadPromise;
  }

  async clearToken() {
    await this.loadCachedToken();
    this.token = this.token?.refreshToken
      ? { refreshToken: this.token.refreshToken, expiresAt: 0 }
      : undefined;
    if (this.token) await this.tokenStore.save(this.token);
    else await this.tokenStore.clear();
  }

  async getAccessToken(options = {}) {
    options.signal?.throwIfAborted();
    const configured = this.config.credentialsConfigured
      ?? Boolean(this.config.username && this.config.password);
    if (!configured) {
      const error = new Error(
        "openUBMC KB credentials are not configured; configure username, password and clientSecret in the private KB configuration"
      );
      error.code = "KB_CREDENTIALS_MISSING";
      throw error;
    }
    await waitForRequest(this.loadCachedToken(), options.signal);
    options.signal?.throwIfAborted();
    if (this.token?.accessToken && this.now() < this.token.expiresAt - TOKEN_EXPIRY_MARGIN_MS) {
      return this.token.accessToken;
    }
    if (!this.tokenPromise) {
      const pending = { controller: new AbortController(), waiters: 0, settled: false };
      this.tokenPromise = pending;
      pending.promise = this.obtainToken({ signal: pending.controller.signal });
      pending.promise.finally(() => {
        pending.settled = true;
        if (this.tokenPromise === pending) this.tokenPromise = undefined;
      }).catch(() => {});
    }
    const pending = this.tokenPromise;
    pending.waiters += 1;
    try {
      return await waitForRequest(pending.promise, options.signal);
    } finally {
      pending.waiters -= 1;
      if (!pending.waiters && !pending.settled) {
        if (this.tokenPromise === pending) this.tokenPromise = undefined;
        pending.controller.abort(options.signal?.reason);
      }
    }
  }

  async obtainToken({ signal } = {}) {
    signal?.throwIfAborted();
    const previous = this.token;
    if (previous?.refreshToken) {
      try {
        const refreshed = await this.refreshAccessToken(previous.refreshToken, { signal });
        signal?.throwIfAborted();
        this.token = refreshed;
        await this.tokenStore.save(refreshed);
        return refreshed.accessToken;
      } catch (error) {
        if (signal?.aborted) throw signal.reason;
        if (error?.code === "KB_RESPONSE_TOO_LARGE") throw error;
        this.token = previous;
      }
    }

    const authenticated = await this.authenticate({ signal });
    signal?.throwIfAborted();
    this.token = authenticated;
    await this.tokenStore.save(authenticated);
    return authenticated.accessToken;
  }

  async request(url, options = {}) {
    options.signal?.throwIfAborted();
    const headers = new Headers(options.headers || {});
    const cookie = this.jar.header(url);
    if (cookie) headers.set("cookie", cookie);
    const response = await this.fetch(url, { ...options, headers });
    options.signal?.throwIfAborted();
    this.jar.store(url, response);
    return response;
  }

  async authenticate({ signal } = {}) {
    const checkResponse = await this.request(`${this.config.userCenterUrl}/oneid/captcha/checkLogin`, {
      signal,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ account: this.config.username })
    });
    const check = unwrap(await responseJson(checkResponse, "CAPTCHA check"));
    if (check?.need_captcha_verification) throw new CaptchaRequiredError();

    const keyResponse = await this.request(`${this.config.userCenterUrl}/oneid/public/key?community=openubmc`, { signal });
    const keyData = unwrap(await responseJson(keyResponse, "public-key request"));
    const publicKey = keyData?.rsa?.publicKey ?? keyData?.publicKey ?? keyData;
    if (typeof publicKey !== "string" || !publicKey.includes("PUBLIC KEY")) throw new Error("OneID public key response is invalid");
    const encryptedPassword = publicEncrypt(
      { key: publicKey, padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(this.config.password, "utf8")
    ).toString("hex");

    const loginPage = new URL(`${this.config.userCenterUrl}/login`);
    loginPage.search = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      scope: this.config.scopes.join(" "),
      redirect_uri: this.config.redirectUri,
      response_mode: "query",
      state: "mcp-login"
    }).toString();
    const loginResponse = await this.request(`${this.config.userCenterUrl}/oneid/login`, {
      signal,
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: this.config.userCenterUrl,
        referer: loginPage.toString()
      },
      body: JSON.stringify({
        permission: "sigRead",
        account: this.config.username,
        client_id: this.config.clientId,
        password: encryptedPassword
      })
    });
    const loginData = unwrap(await responseJson(loginResponse, "OneID login"));
    const ssoToken = typeof loginData?.token === "string" && loginData.token
      ? loginData.token
      : undefined;
    if (ssoToken) {
      this.jar.set({ name: "_U_T_", value: ssoToken, domain: "openubmc.cn", secure: true });
    }

    const state = this.stateFactory();
    const authorizationUrl = new URL(`${this.config.userCenterUrl}/oneid/oidc/auth`);
    authorizationUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(" "),
      state
    }).toString();
    const authorizationResponse = await this.request(authorizationUrl, {
      signal,
      headers: {
        ...(ssoToken ? { token: ssoToken } : {}),
        origin: this.config.userCenterUrl,
        referer: loginPage.toString()
      }
    });
    const authorizationData = unwrap(await responseJson(authorizationResponse, "OAuth authorization"));
    if (typeof authorizationData?.body !== "string") {
      throw new Error("OAuth authorization response does not contain a callback URL");
    }
    const callback = new URL(authorizationData.body);
    if (callback.searchParams.get("state") !== state) throw new Error("OAuth state validation failed");
    const code = callback.searchParams.get("code");
    if (!code) throw new Error("OAuth authorization code is missing");

    const tokenBody = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    });
    const tokenResponse = await this.request(this.config.tokenEndpoint, {
      signal,
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: tokenBody.toString()
    });
    const token = await responseJson(tokenResponse, "OAuth token exchange");
    return tokenFromResponse(token, this.now);
  }

  async refreshAccessToken(refreshToken, { signal } = {}) {
    const tokenBody = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    });
    const tokenResponse = await this.request(this.config.tokenEndpoint, {
      signal,
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: tokenBody.toString()
    });
    const token = await responseJson(tokenResponse, "OAuth token refresh");
    return tokenFromResponse(token, this.now, refreshToken);
  }
}
