export const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;

export function requestTimeoutMs(value = DEFAULT_REQUEST_TIMEOUT_MS) {
  if (!Number.isInteger(value) || value < 1 || value > 900_000) {
    throw new Error("requestTimeoutMs must be an integer between 1 and 900000");
  }
  return value;
}

export function waitForRequest(promise, signal) {
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    const cancel = () => reject(signal.reason);
    if (signal.aborted) cancel();
    else signal.addEventListener("abort", cancel, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => {
      signal.removeEventListener("abort", cancel);
    });
  });
}

export async function withRequestDeadline(timeoutMs, operation, signal) {
  requestTimeoutMs(timeoutMs);
  const controller = new AbortController();
  const cancel = () => controller.abort(Object.assign(new Error("Knowledge-base request cancelled"), { code: "KB_CANCELLED" }));
  if (signal?.aborted) cancel();
  else signal?.addEventListener("abort", cancel, { once: true });
  const error = Object.assign(new Error("Knowledge-base request deadline exceeded"), { code: "KB_TIMEOUT" });
  const timer = setTimeout(() => controller.abort(error), timeoutMs);
  try {
    controller.signal.throwIfAborted();
    return await waitForRequest(operation(controller.signal), controller.signal);
  } catch (failure) {
    if (controller.signal.aborted) throw controller.signal.reason;
    throw failure;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
    // A failed parallel read must not leave its sibling requests running.
    controller.abort();
  }
}
