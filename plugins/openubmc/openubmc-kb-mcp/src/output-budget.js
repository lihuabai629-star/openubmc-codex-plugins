const RECEIPT_BYTES = 64 * 1024;

function invalidResponse() {
  const error = new Error("Upstream response has an invalid field shape");
  error.code = "KB_RESPONSE_INVALID";
  throw error;
}

function requireObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalidResponse();
}

function utf8Prefix(value, bytes) {
  let used = 0;
  let end = 0;
  for (const character of value) {
    used += Buffer.byteLength(character);
    if (used > bytes) break;
    end += character.length;
  }
  return value.slice(0, end);
}

export function boundedReceipt(name, source, render) {
  requireObject(source);
  const reasons = new Set();
  function scalar(value, limit = 1024) {
    if (typeof value === "string") {
      if (Buffer.byteLength(value) > limit) {
        reasons.add("field_bytes_exceeded");
        return utf8Prefix(value, limit);
      }
      return value;
    }
    if (typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value)) || value === null) return value;
    if (value !== undefined) reasons.add("fields_omitted");
    return undefined;
  }
  function fields(value, allowed, nested = []) {
    if (value === undefined) return {};
    requireObject(value);
    if (Object.keys(value).some(key => !allowed.includes(key))) reasons.add("fields_omitted");
    return Object.fromEntries(allowed.filter(key => Object.hasOwn(value, key) && !nested.includes(key))
      .map(key => [key, scalar(value[key], key === "content_summary" ? 600 : key === "error_msg" ? 300 : 1024)]));
  }
  function rows(value, maximum, allowed) {
    if (value === undefined) return [];
    if (!Array.isArray(value)) invalidResponse();
    if (value.length > maximum) reasons.add("items_exceeded");
    return value.slice(0, maximum).map(item => fields(item, allowed));
  }
  let result;
  if (name === "openubmc_kb_query") {
    const allowed = ["response", "answer", "references", "mode"];
    if (source && Object.keys(source).some(key => !allowed.includes(key))) reasons.add("fields_omitted");
    result = {};
    for (const key of ["response", "answer", "mode"]) {
      if (Object.hasOwn(source || {}, key)) result[key] = scalar(source[key], key === "mode" ? 128 : 24000);
    }
    if (typeof source?.response === "string") result.response_chars = source.response.length;
    if (Object.hasOwn(source, "references")) result.references = rows(source.references, 32, ["reference_id", "file_path"]);
  } else if (name === "openubmc_kb_status") {
    result = fields(source, ["configured", "endpoint", "config_path", "detail", "pipeline", "counts"], ["pipeline", "counts"]);
    if (Object.hasOwn(source, "pipeline")) {
      result.pipeline = fields(source.pipeline, ["busy", "job_name", "job_start", "docs", "batchs", "cur_batch", "request_pending", "latest_message", "history_messages", "history_total", "history_truncated"], ["history_messages"]);
      const history = source.pipeline.history_messages;
      if (history !== undefined && !Array.isArray(history)) invalidResponse();
      if (Array.isArray(history)) {
        result.pipeline.history_messages = history.slice(-10).map(item => scalar(item));
        result.pipeline.history_total = history.length;
        result.pipeline.history_truncated = history.length > 10;
        if (history.length > 10 || source.pipeline.history_truncated) reasons.add("items_exceeded");
      }
    }
    if (Object.hasOwn(source, "counts")) {
      result.counts = fields(source.counts, ["status_counts"], ["status_counts"]);
      result.counts.status_counts = fields(source.counts.status_counts, ["pending", "processing", "preprocessed", "processed", "failed"]);
    }
  } else {
    result = fields(source, ["documents", "pagination"], ["documents", "pagination"]);
    result.documents = rows(source?.documents, 100, ["id", "file_path", "status", "chunks_count", "content_length", "content_summary", "created_at", "updated_at", "error_msg"]);
    if (Object.hasOwn(source, "pagination")) result.pagination = fields(source.pagination, ["page", "page_size", "total_count", "total_pages", "has_next", "has_prev"]);
  }
  function receipt() {
    result.truncated = reasons.size > 0;
    result.truncation_reasons = [...reasons].sort();
    return render(result);
  }
  let output = receipt();
  while (Buffer.byteLength(JSON.stringify(output)) > RECEIPT_BYTES) {
    reasons.add("receipt_bytes_exceeded");
    const collection = result.references?.length ? result.references : result.documents;
    if (collection?.length) collection.pop();
    else {
      const strings = [];
      function visit(value) {
        for (const [key, child] of Object.entries(value)) {
          if (key === "truncation_reasons") continue;
          if (typeof child === "string" && child.length) strings.push([value, key, child]);
          else if (child && typeof child === "object") visit(child);
        }
      }
      visit(result);
      strings.sort((a, b) => Buffer.byteLength(JSON.stringify(b[2])) - Buffer.byteLength(JSON.stringify(a[2])));
      const [owner, key, value] = strings[0];
      owner[key] = utf8Prefix(value, Math.floor(Buffer.byteLength(value) / 2));
    }
    output = receipt();
  }
  return output;
}
