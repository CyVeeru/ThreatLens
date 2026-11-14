/**
 * Outbound HTTP for AI providers.
 *
 * Async, non-blocking, built on the runtime's global `fetch`. Replaces the
 * previous `spawnSync("curl")` wrapper, which froze the whole event loop for
 * the duration of every model call and exposed API keys in the process list.
 *
 * Guarantees kept from the curl version:
 *   • HTTPS only (plain HTTP only for loopback when THREATLENS_ALLOW_LOCAL_AI=1)
 *   • redirects are followed manually and re-checked against the same rule
 *   • hard wall-clock timeout, response-size cap, never throws — every failure
 *     is reported through `{ ok:false, status, error }`
 */

import { env } from "./env";

export interface HttpResult {
  ok: boolean;
  status: number;
  body: string;
  error?: string;
  latencyMs: number;
}

export interface HttpRequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  /** Wall-clock budget for the whole exchange, including redirects. */
  timeoutSeconds: number;
  maxTimeoutSeconds?: number;
  accept?: string;
  contentType?: string;
  /** Cap on response bytes read (default 64 MiB). */
  maxBytes?: number;
  /** Caller-supplied abort signal (job cancellation). */
  signal?: AbortSignal;
  /** Skip the HTTPS-only rule (used for nothing today; reserved for tests). */
  allowInsecure?: boolean;
}

const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const MAX_REDIRECTS = 3;

function localHttpAllowed(url: string): boolean {
  return (
    env("ALLOW_LOCAL_AI") === "1" &&
    /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(url)
  );
}

/** Returns a reason string when the URL violates the outbound protocol rule. */
export function outboundProtocolViolation(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "invalid URL";
  }
  if (parsed.protocol === "https:") return null;
  if (parsed.protocol === "http:" && localHttpAllowed(url)) return null;
  return `refusing ${parsed.protocol.replace(":", "")} URL — AI providers must be reached over HTTPS`;
}

function sanitizeHeaderValue(value: string): string {
  // Header injection guard: strip CR/LF so a hostile provider label or custom
  // header can never smuggle an extra header line.
  return String(value)
    .replace(/[\r\n]+/g, " ")
    .trim();
}

async function readBodyCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      chunks.push(value.subarray(0, value.byteLength - (total - maxBytes)));
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      break;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c.buffer, c.byteOffset, c.byteLength))).toString("utf8");
}

export async function httpRequest(opts: HttpRequestOptions): Promise<HttpResult> {
  const started = Date.now();
  const maxTimeoutSeconds = opts.maxTimeoutSeconds ?? opts.timeoutSeconds;
  const timeoutMs = Math.max(1, Math.min(maxTimeoutSeconds, opts.timeoutSeconds)) * 1000;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const done = (partial: Omit<HttpResult, "latencyMs">): HttpResult => ({
    ...partial,
    latencyMs: Date.now() - started,
  });

  if (!opts.allowInsecure) {
    const violation = outboundProtocolViolation(opts.url);
    if (violation) return done({ ok: false, status: 0, body: "", error: violation });
  }

  const headers: Record<string, string> = {};
  if (opts.accept) headers["accept"] = opts.accept;
  if (opts.contentType) headers["content-type"] = opts.contentType;
  for (const [k, v] of Object.entries(opts.headers ?? {})) {
    const key = sanitizeHeaderValue(k);
    if (!key) continue;
    headers[key] = sanitizeHeaderValue(v);
  }

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error(`timed out after ${Math.round(timeoutMs / 1000)}s`)),
    timeoutMs,
  );
  const onExternalAbort = () => controller.abort(opts.signal?.reason ?? new Error("aborted"));
  if (opts.signal) {
    if (opts.signal.aborted) onExternalAbort();
    else opts.signal.addEventListener("abort", onExternalAbort, { once: true });
  }

  try {
    let url = opts.url;
    const method = opts.method ?? (opts.body !== undefined ? "POST" : "GET");
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      let res: Response;
      try {
        res = await fetch(url, {
          method,
          headers,
          body: opts.body,
          redirect: "manual",
          signal: controller.signal,
        });
      } catch (e: any) {
        const reason = controller.signal.aborted
          ? String(controller.signal.reason?.message ?? controller.signal.reason ?? "aborted")
          : String(e?.cause?.message ?? e?.message ?? e);
        return done({ ok: false, status: 0, body: "", error: reason });
      }

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get("location");
        try {
          await res.body?.cancel();
        } catch {
          /* ignore */
        }
        if (!location) return done({ ok: false, status: res.status, body: "", error: `redirect without location` });
        const next = new URL(location, url).toString();
        if (!opts.allowInsecure) {
          const violation = outboundProtocolViolation(next);
          if (violation)
            return done({ ok: false, status: res.status, body: "", error: `redirect blocked: ${violation}` });
        }
        url = next;
        continue;
      }

      let body: string;
      try {
        body = await readBodyCapped(res, maxBytes);
      } catch (e: any) {
        const reason = controller.signal.aborted
          ? String(controller.signal.reason?.message ?? controller.signal.reason ?? "aborted")
          : String(e?.message ?? e);
        return done({ ok: false, status: res.status, body: "", error: reason });
      }
      const ok = res.status >= 200 && res.status < 300;
      return done({ ok, status: res.status, body, error: ok ? undefined : `HTTP ${res.status}` });
    }
    return done({ ok: false, status: 0, body: "", error: `too many redirects (>${MAX_REDIRECTS})` });
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onExternalAbort);
  }
}
