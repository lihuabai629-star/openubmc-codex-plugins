import { readResponseText } from "./http/read-response.js";
import { DEFAULT_REQUEST_TIMEOUT_MS, withRequestDeadline } from "./http/request-lifetime.js";

async function parseResponse(response, operation) {
  const text = await readResponseText(response, 2 * 1024 * 1024);
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!response.ok) {
    const detail = data?.message
      ?? data?.error_description
      ?? (typeof data?.error === "string" ? data.error : undefined)
      ?? (Array.isArray(data?.detail) ? data.detail[0]?.msg : undefined);
    const suffix = typeof detail === "string" && detail.trim()
      ? `: ${detail.trim().slice(0, 240)}`
      : "";
    const error = new Error(`${operation} failed with HTTP ${response.status}${suffix}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

export class LightRagClient {
  constructor(config, authClient, fetchImpl = globalThis.fetch) {
    this.baseUrl = config.lightragUrl.replace(/\/$/, "");
    this.configPath = config.configPath;
    this.credentialsConfigured = config.credentialsConfigured !== false;
    this.auth = authClient;
    this.fetch = fetchImpl;
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  async authenticatedRequest(path, options = {}, retry = true) {
    const token = await this.auth.getAccessToken({ signal: options.signal });
    const headers = {
      "content-type": "application/json",
      ...(options.headers || {}),
      authorization: `Bearer ${token}`
    };
    const response = await this.fetch(`${this.baseUrl}${path}`, { ...options, headers });
    if (retry && response.status === 401) {
      await response.body?.cancel();
      await this.auth.clearToken();
      return this.authenticatedRequest(path, options, false);
    }
    return parseResponse(response, `LightRAG ${path}`);
  }

  query(input, options = {}) {
    return withRequestDeadline(this.requestTimeoutMs, signal => this.authenticatedRequest("/api/v1/rag/retrieve", {
      signal,
      method: "POST",
      body: JSON.stringify({
        query: input.query,
        mode: input.mode || "mix",
        top_k: input.top_k ?? 10,
        chunk_top_k: input.chunk_top_k ?? 5,
        include_references: input.include_references ?? false,
        enable_rerank: input.enable_rerank ?? true,
        only_need_context: input.only_need_context ?? true,
        only_need_prompt: false,
        stream: false
      })
    }), options.signal);
  }

  status(options = {}) {
    return withRequestDeadline(this.requestTimeoutMs, async signal => {
      if (!this.credentialsConfigured) {
        return {
          configured: false,
          endpoint: this.baseUrl,
          config_path: this.configPath,
          detail: "OneID credentials are not configured"
        };
      }
      const [pipeline, counts] = await Promise.all([
        this.authenticatedRequest("/api/v1/rag/documents/pipeline_status", { signal }),
        this.authenticatedRequest("/api/v1/rag/documents/status_counts", { signal })
      ]);
      return { configured: true, endpoint: this.baseUrl, pipeline, counts };
    }, options.signal);
  }

  list(input = {}, options = {}) {
    return withRequestDeadline(this.requestTimeoutMs, async signal => {
      const request = {
        page: input.page ?? 1,
        page_size: input.page_size ?? 10,
        sort_field: input.sort_field ?? "updated_at",
        sort_direction: input.sort_direction ?? "desc",
        ...(input.status_filter ? { status_filter: input.status_filter } : {})
      };
      const result = await this.authenticatedRequest("/api/v1/rag/documents/paginated", {
        signal,
        method: "POST",
        body: JSON.stringify(request)
      });
      return result;
    }, options.signal);
  }
}
