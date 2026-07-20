/**
 * Small shared helpers for building MCP tool responses.
 */
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

export function ok(data: unknown): CallToolResult {
  const text =
    typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text", text }] };
}

export function fail(error: unknown): CallToolResult {
  const e = error as { message?: string; errors?: unknown; code?: unknown };
  const message =
    e?.message ?? (typeof error === "string" ? error : "Unknown error");
  const details = e?.errors ? `\nDetails: ${JSON.stringify(e.errors)}` : "";
  return {
    isError: true,
    content: [{ type: "text", text: `Error: ${message}${details}` }],
  };
}

/** Wraps a tool handler so thrown errors become structured MCP error results. */
export function guard<A>(
  fn: (args: A) => Promise<CallToolResult>,
): (args: A) => Promise<CallToolResult> {
  return async (args: A) => {
    try {
      return await fn(args);
    } catch (err) {
      return fail(err);
    }
  };
}

/**
 * Run `fn` over `items` with at most `limit` calls in flight, retrying each
 * call on 429/5xx with exponential backoff. Google enforces a per-user cap on
 * concurrent requests (~50 across ALL clients); unbounded Promise.all over a
 * 30+ item batch trips "429 Too many concurrent requests for user". Results
 * keep input order. `fn` errors are NOT swallowed here — callers keep their
 * own per-item try/catch so one failure doesn't kill the batch.
 */
export async function mapWithLimit<T, R>(
  items: T[],
  fn: (item: T, index: number) => Promise<R>,
  limit = 8,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await withRetry(() => fn(items[i], i));
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
  return results;
}

/** Retry on 429/rate-limit/5xx with exponential backoff (1s, 2s, 4s). */
async function withRetry<R>(fn: () => Promise<R>, attempts = 3): Promise<R> {
  let lastErr: unknown;
  for (let a = 0; a < attempts; a++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const e = err as { code?: number | string; message?: string };
      const code = Number(e?.code);
      const msg = String(e?.message ?? "");
      const retriable =
        code === 429 ||
        code === 500 ||
        code === 503 ||
        /rate ?limit|too many concurrent|quota/i.test(msg);
      if (!retriable || a === attempts - 1) throw err;
      await new Promise((r) => setTimeout(r, 1000 * 2 ** a));
    }
  }
  throw lastErr;
}

/** True for MIME types whose bytes are safe to return inline as UTF-8 text. */
export function isTextual(mime: string): boolean {
  return (
    mime.startsWith("text/") ||
    mime === "application/json" ||
    mime === "application/xml" ||
    mime === "application/csv" ||
    mime.endsWith("+json") ||
    mime.endsWith("+xml")
  );
}
