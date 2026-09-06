async function parseResponse(response, operation) {
  const text = await response.text();
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
  }

  async authenticatedRequest(path, options = {}, retry = true) {
    const token = await this.auth.getAccessToken();
    const headers = {
      "content-type": "application/json",
      ...(options.headers || {}),
      authorization: `Bearer ${token}`
    };
    const response = await this.fetch(`${this.baseUrl}${path}`, { ...options, headers });
    if (retry && (response.status === 401 || response.status === 403)) {
      await this.auth.clearToken();
      return this.authenticatedRequest(path, options, false);
    }
    return parseResponse(response, `LightRAG ${path}`);
  }

  query(input) {
    return this.authenticatedRequest("/api/v1/rag/retrieve", {
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
    });
  }

  async status() {
    if (!this.credentialsConfigured) {
      return {
        configured: false,
        endpoint: this.baseUrl,
        config_path: this.configPath,
        detail: "OneID credentials are not configured"
      };
    }
    const [pipeline, counts] = await Promise.all([
      this.authenticatedRequest("/api/v1/rag/documents/pipeline_status"),
      this.authenticatedRequest("/api/v1/rag/documents/status_counts")
    ]);
    const history = Array.isArray(pipeline?.history_messages)
      ? pipeline.history_messages
      : [];
    const historyLimit = 10;
    return {
      configured: true,
      endpoint: this.baseUrl,
      pipeline: {
        ...pipeline,
        history_messages: history.slice(-historyLimit),
        history_total: history.length,
        history_truncated: history.length > historyLimit
      },
      counts
    };
  }

  async list(input = {}) {
    const request = {
      page: input.page ?? 1,
      page_size: input.page_size ?? 10,
      sort_field: input.sort_field ?? "updated_at",
      sort_direction: input.sort_direction ?? "desc",
      ...(input.status_filter ? { status_filter: input.status_filter } : {})
    };
    const result = await this.authenticatedRequest("/api/v1/rag/documents/paginated", {
      method: "POST",
      body: JSON.stringify(request)
    });
    const documents = Array.isArray(result?.documents) ? result.documents : [];
    return {
      ...result,
      documents: documents.map(document => ({
        id: document?.id,
        file_path: document?.file_path,
        status: document?.status,
        chunks_count: document?.chunks_count,
        content_length: document?.content_length,
        content_summary: typeof document?.content_summary === "string"
          ? document.content_summary.slice(0, 600)
          : document?.content_summary,
        created_at: document?.created_at,
        updated_at: document?.updated_at,
        error_msg: typeof document?.error_msg === "string"
          ? document.error_msg.slice(0, 300)
          : document?.error_msg
      }))
    };
  }
}
