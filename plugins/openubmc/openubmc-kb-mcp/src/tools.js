import * as z from "zod/v4";
import { boundedReceipt } from "./output-budget.js";


const READ_ONLY_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true
});
const OUTPUT_SCHEMA = {
  ok: z.boolean(),
  result: z.unknown().optional(),
  error: z.object({
    code: z.string(),
    message: z.string(),
    retryable: z.boolean(),
    recovery: z.string().optional()
  }).optional()
};


function markdown(name, value) {
  if (name === "openubmc_kb_query") {
    const references = Array.isArray(value?.references)
      ? value.references.map(item => `- ${item.reference_id}: ${item.file_path}`).join("\n")
      : "";
    return [
      value?.response || "No knowledge-base context returned.",
      references ? `\nReferences\n\n${references}` : "",
      value?.truncated ? `\nIncomplete context: ${value.truncation_reasons.join(", ")}.` : ""
    ].filter(Boolean).join("\n");
  }
  if (name === "openubmc_kb_status") {
    const counts = value?.counts?.status_counts || {};
    return [
      `Configured: ${Boolean(value?.configured)}`,
      `Endpoint: ${value?.endpoint || "unknown"}`,
      `Processed: ${counts.processed ?? "unknown"}`,
      `Failed: ${counts.failed ?? "unknown"}`,
      `Pipeline busy: ${Boolean(value?.pipeline?.busy)}`
    ].join("\n");
  }
  const documents = Array.isArray(value?.documents) ? value.documents : [];
  const lines = documents.map(document =>
    `- ${document.file_path || document.id} (${document.status || "unknown"})`
  );
  const page = value?.pagination || {};
  return [
    `Page ${page.page ?? "?"}/${page.total_pages ?? "?"}; total ${page.total_count ?? "?"}`,
    ...lines
  ].join("\n");
}


function textResult(name, source, responseFormat) {
  return boundedReceipt(name, source, value => {
  const structuredContent = { ok: true, result: value };
  return {
    content: [{
      type: "text",
      text: responseFormat === "markdown"
        ? markdown(name, value) + (name !== "openubmc_kb_query" && value.truncated
          ? `\nIncomplete context: ${value.truncation_reasons.join(", ")}.` : "")
        : JSON.stringify(structuredContent, null, 2)
    }],
    structuredContent
  };
  });
}


export function errorResult(error) {
  const failures = {
    KB_CONFIGURATION_INVALID: ["The activated local KB configuration is invalid.", false,
      "Repair and activate the local configuration before retrying."],
    KB_CREDENTIALS_MISSING: ["Knowledge-base credentials are not configured.", false,
      "Configure credentials in the local private KB configuration."],
    KB_INTERACTION_REQUIRED: ["Knowledge-base authentication requires human interaction.", false,
      "Complete interactive authentication locally before retrying."],
    KB_AUTHENTICATION_FAILED: ["Knowledge-base authentication failed.", false,
      "Check the local account credentials and authentication configuration."],
    KB_PERMISSION_DENIED: ["Knowledge-base access was denied.", false,
      "Check that the configured account has permission for this operation."],
    KB_RATE_LIMITED: ["The upstream service rate limit was reached.", true,
      "Wait before retrying this read-only request."],
    KB_SERVICE_UNAVAILABLE: ["The upstream service is temporarily unavailable.", true,
      "Retry this read-only request after the service recovers."],
    KB_NETWORK_ERROR: ["The knowledge-base connection was interrupted.", true,
      "Check connectivity and retry this read-only request."],
    KB_RESPONSE_INVALID: ["The upstream response has an invalid field shape.", false,
      "Check knowledge-base service compatibility before retrying."],
    KB_RESPONSE_TOO_LARGE: ["The upstream response exceeded the byte budget.", false,
      "Narrow the query or reduce the requested page size before retrying."],
    KB_TIMEOUT: ["The knowledge-base request exceeded its total deadline.", true,
      "Check the upstream service before retrying this read-only request."],
    KB_CANCELLED: ["The knowledge-base request was cancelled.", false,
      "Start a new request only if the task still needs this information."],
    KB_TOOL_FAILED: ["The knowledge-base request failed.", false,
      "Inspect local diagnostics before deciding whether to retry."]
  };
  const statusCodes = {
    401: "KB_AUTHENTICATION_FAILED", 403: "KB_PERMISSION_DENIED",
    429: "KB_RATE_LIMITED", 502: "KB_SERVICE_UNAVAILABLE",
    503: "KB_SERVICE_UNAVAILABLE", 504: "KB_SERVICE_UNAVAILABLE"
  };
  const statusCode = Object.hasOwn(statusCodes, error?.status) ? statusCodes[error.status] : undefined;
  const networkCode = ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EAI_AGAIN",
    "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_SOCKET"]
    .includes(error?.cause?.code) ? "KB_NETWORK_ERROR" : undefined;
  const code = Object.hasOwn(failures, error?.code)
    ? error.code : statusCode || networkCode || "KB_TOOL_FAILED";
  const [message, retryable, recovery] = failures[code];
  const structuredContent = {
    ok: false,
    error: {
      code,
      message,
      retryable,
      recovery
    }
  };
  return {
    isError: true,
    content: [{ type: "text", text: `${code}: ${message}\n${recovery}` }],
    structuredContent
  };
}


export function createTools(client) {
  const responseFormat = z.enum(["json", "markdown"])
    .default("json")
    .describe("Return compact JSON or human-readable Markdown text");
  return [
    {
      name: "openubmc_kb_query",
      title: "Query openUBMC knowledge base",
      description: "Search the openUBMC community LightRAG knowledge base and return bounded context for a technical question. Use it for candidate discovery; verify conclusions against source or runtime evidence.",
      annotations: READ_ONLY_ANNOTATIONS,
      inputSchema: {
        query: z.string().trim().min(1).max(2000).describe("Question or search text"),
        mode: z.enum(["local", "global", "hybrid", "mix", "naive"]).default("naive"),
        top_k: z.number().int().min(1).max(100).default(10),
        chunk_top_k: z.number().int().min(1).max(100).default(5),
        include_references: z.boolean().default(true),
        enable_rerank: z.boolean().default(true),
        only_need_context: z.boolean().default(true),
        response_format: responseFormat
      },
      outputSchema: OUTPUT_SCHEMA,
      handler: async (input, options) => {
        if (typeof input?.query !== "string" || input.query.trim() === "") {
          throw new Error("query must be a non-empty string");
        }
        const normalized = { ...input, query: input.query.trim() };
        const result = await client.query(normalized, options);
        return textResult("openubmc_kb_query", result, input.response_format);
      }
    },
    {
      name: "openubmc_kb_status",
      title: "Inspect openUBMC knowledge-base status",
      description: "Report local credential readiness and a bounded summary of the remote LightRAG indexing pipeline and document counts. This is read-only.",
      annotations: READ_ONLY_ANNOTATIONS,
      inputSchema: { response_format: responseFormat },
      outputSchema: OUTPUT_SCHEMA,
      handler: async (input, options) => textResult(
        "openubmc_kb_status",
        await client.status(options),
        input.response_format
      )
    },
    {
      name: "openubmc_kb_list",
      title: "List openUBMC knowledge-base documents",
      description: "List one bounded page of knowledge-base documents. The upstream service requires pages of at least 10; summaries and errors are truncated for context efficiency.",
      annotations: READ_ONLY_ANNOTATIONS,
      inputSchema: {
        page: z.number().int().min(1).default(1),
        page_size: z.number().int().min(10).max(100).default(10),
        status_filter: z.enum(["pending", "processing", "preprocessed", "processed", "failed"]).optional(),
        sort_field: z.enum(["created_at", "updated_at", "file_size"]).default("updated_at"),
        sort_direction: z.enum(["asc", "desc"]).default("desc"),
        response_format: responseFormat
      },
      outputSchema: OUTPUT_SCHEMA,
      handler: async (input, options) => textResult(
        "openubmc_kb_list",
        await client.list(input, options),
        input.response_format
      )
    }
  ];
}


export function registerTools(server, client, processLifecycle = null) {
  for (const tool of createTools(client)) {
    const { name, handler, ...configuration } = tool;
    server.registerTool(name, configuration, async (input, extra = {}) => {
      if (
        processLifecycle !== null
        && typeof processLifecycle.attribute === "function"
      ) {
        const metadata = extra?._meta || {};
        const taskId = metadata["codex/taskId"]
          || metadata.taskId
          || metadata.task_id
          || extra.taskId;
        processLifecycle.attribute({
          client: metadata["codex/taskId"] ? "codex" : undefined,
          taskId,
          sessionId: extra.sessionId || taskId
        });
      }
      const invoke = async () => {
        try {
          return await handler(input, { signal: extra.signal });
        } catch (error) {
          return errorResult(error);
        }
      };
      processLifecycle?.beginRequest?.();
      try {
        return await invoke();
      } finally {
        processLifecycle?.endRequest?.();
      }
    });
  }
}
