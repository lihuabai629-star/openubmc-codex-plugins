import * as z from "zod/v4";


const QUERY_RESPONSE_LIMIT = 24000;
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
    retryable: z.boolean()
  }).optional()
};


function boundedQueryResult(value) {
  if (!value || typeof value !== "object" || typeof value.response !== "string") {
    return value;
  }
  const originalChars = value.response.length;
  const truncated = originalChars > QUERY_RESPONSE_LIMIT;
  return {
    ...value,
    response: truncated
      ? value.response.slice(0, QUERY_RESPONSE_LIMIT)
      : value.response,
    response_chars: originalChars,
    truncated
  };
}


function markdown(name, value) {
  if (name === "openubmc_kb_query") {
    const references = Array.isArray(value?.references)
      ? value.references.map(item => `- ${item.reference_id}: ${item.file_path}`).join("\n")
      : "";
    return [
      value?.response || "No knowledge-base context returned.",
      references ? `\nReferences\n\n${references}` : "",
      value?.truncated ? `\nResponse truncated at ${QUERY_RESPONSE_LIMIT} characters.` : ""
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


function textResult(name, value, responseFormat) {
  const structuredContent = { ok: true, result: value };
  return {
    content: [{
      type: "text",
      text: responseFormat === "markdown"
        ? markdown(name, value)
        : JSON.stringify(structuredContent, null, 2)
    }],
    structuredContent
  };
}


export function errorResult(error) {
  const message = error instanceof Error ? error.message : "Unknown MCP tool error";
  const code = typeof error?.code === "string" ? error.code : "KB_TOOL_FAILED";
  const structuredContent = {
    ok: false,
    error: {
      code,
      message,
      retryable: !["KB_CREDENTIALS_MISSING"].includes(code)
    }
  };
  return {
    isError: true,
    content: [{ type: "text", text: `${code}: ${message}` }],
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
      handler: async input => {
        if (typeof input?.query !== "string" || input.query.trim() === "") {
          throw new Error("query must be a non-empty string");
        }
        const normalized = { ...input, query: input.query.trim() };
        const result = boundedQueryResult(await client.query(normalized));
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
      handler: async input => textResult(
        "openubmc_kb_status",
        await client.status(),
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
      handler: async input => textResult(
        "openubmc_kb_list",
        await client.list(input),
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
          return await handler(input);
        } catch (error) {
          return errorResult(error);
        }
      };
      return invoke();
    });
  }
}
