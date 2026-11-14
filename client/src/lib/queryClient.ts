import { QueryClient, QueryFunction } from "@tanstack/react-query";
import { STATIC_DEMO_MODE, staticDemoRequest } from "./staticDemoApi";

/** The SPA and the API are always served from the same origin. */
const API_BASE = "";
const API_PATH_RE = /^\/api\/v1\/[A-Za-z0-9/_:?.=&%+#@-]*$/;

/** Resolve a server-rooted asset URL (e.g. "/portraits/<id>.png") to a URL the
 *  browser can load. Absolute URLs pass through; null/undefined are returned
 *  unchanged so callers can pass optional fields straight in. */
export function resolveAssetUrl(path: string | null | undefined): string | null | undefined {
  if (!path) return path;
  // Don't double-prefix absolute URLs.
  if (/^https?:\/\//i.test(path)) return path;
  return `${API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;
}

// Token holder kept outside React tree so apiRequest/getQueryFn can read it.
// Auth context updates it via setAuthToken / setOnUnauthorized.
let authToken: string | null = null;
let onUnauthorized: (() => void) | null = null;
export function setAuthToken(t: string | null) {
  authToken = t;
}
export function setOnUnauthorized(cb: (() => void) | null) {
  onUnauthorized = cb;
}
export function setActiveTenantId(_tid: string | null) {
  // BatchOne is a single-workspace release. Keep this no-op export so older
  // auth/UI code can call it without sending tenant override headers.
}

function authHeaders(extra: HeadersInit = {}): HeadersInit {
  const h: Record<string, string> = { ...(extra as Record<string, string>) };
  if (authToken) h.Authorization = `Bearer ${authToken}`;
  return h;
}

/** A 401 only means "signed out" when the request actually carried the current
 *  session token. A request that raced ahead of token hydration (no token, or a
 *  stale one) must not wipe a perfectly good session. */
function signalUnauthorized(sentToken: string | null) {
  if (sentToken && sentToken === authToken && onUnauthorized) onUnauthorized();
}

async function throwIfResNotOk(res: Response, sentToken: string | null = authToken) {
  if (!res.ok) {
    if (res.status === 401) signalUnauthorized(sentToken);
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(method: string, url: string, data?: unknown | undefined): Promise<Response> {
  if (!API_PATH_RE.test(url)) throw new Error("Invalid API path");
  if (STATIC_DEMO_MODE) {
    const demo = staticDemoRequest(method, url, data);
    if (demo) {
      await throwIfResNotOk(demo.clone());
      return demo;
    }
  }

  const requestUrl = `${API_BASE}${url}`;
  const sentToken = authToken;
  const res = await fetch(requestUrl, {
    method,
    headers: authHeaders(data ? { "Content-Type": "application/json" } : {}),
    body: data ? JSON.stringify(data) : undefined,
  });

  await throwIfResNotOk(res, sentToken);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: { on401: UnauthorizedBehavior }) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const path = queryKey.filter((s) => s !== undefined && s !== null && s !== "").join("/");
    if (!API_PATH_RE.test(path)) throw new Error("Invalid API path");
    if (STATIC_DEMO_MODE) {
      const demo = staticDemoRequest("GET", path);
      if (demo) {
        if (unauthorizedBehavior === "returnNull" && demo.status === 401) return null;
        await throwIfResNotOk(demo.clone());
        return await demo.json();
      }
    }
    const requestUrl = `${API_BASE}${path}`;
    const sentToken = authToken;
    const res = await fetch(requestUrl, { headers: authHeaders() });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) return null;
    await throwIfResNotOk(res, sentToken);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: false,
    },
    mutations: { retry: false },
  },
});
