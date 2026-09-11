export async function readResponseText(response, limit) {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) {
        const error = new Error("Upstream response exceeds the byte budget");
        error.code = "KB_RESPONSE_TOO_LARGE";
        throw error;
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks, bytes).toString("utf8");
  } finally {
    try { await reader.cancel(); } catch { /* Transport may already be aborted. */ }
    reader.releaseLock();
  }
}
