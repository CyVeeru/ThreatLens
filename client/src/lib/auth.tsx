import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { apiRequest, queryClient, setAuthToken, setOnUnauthorized, setActiveTenantId } from "./queryClient";
import { STATIC_DEMO_MODE, STATIC_DEMO_USER } from "./staticDemoApi";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  tenant: { id: string; name: string; slug: string; plan: string };
  passwordMustChange?: boolean;
  mfaEnabled?: boolean;
  mfaVerifiedAt?: string | null;
  /** Server-side policy: is MFA enrolment mandatory before the app unlocks? */
  mfaRequired?: boolean;
  access_mode?: "credentialed" | "guest";
  capabilities?: string[];
}

interface AuthCtx {
  user: AuthUser | null;
  loading: boolean;
  /** Active tenant id (admin only — for analyst this is always their own tenant). */
  activeTenantId: string | null;
  setActiveTenant: (tid: string | null) => void;
  login: (email: string, password: string, mfaCode?: string) => Promise<void>;
  refreshMe: () => Promise<AuthUser | null>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

/* --------------------------------------------------------------------------
 * Where the bearer token lives, and why.
 *
 * The token is held in React state (memory) and mirrored into
 * `window.history.state` purely so a page refresh or a duplicated tab does not
 * force a re-login. Reviewed alternatives:
 *
 *   localStorage      — shared across every tab and persists indefinitely; a
 *                       token left there outlives the work session.
 *   sessionStorage    — same script-readability as history.state, no benefit.
 *   HttpOnly cookie   — the only option XSS cannot read, and the right answer
 *                       for a multi-user deployment behind TLS. Rejected here
 *                       because it reintroduces CSRF (the API is otherwise
 *                       bearer-only, so it has no CSRF surface at all) and
 *                       `Secure` cookies are not settable over the plain-HTTP
 *                       loopback this tool defaults to.
 *
 * Residual risk, accepted: history.state is script-readable (so any XSS wins
 * regardless of the store) and the browser serialises it into its
 * session-restore file. That exposure is bounded server-side by the absolute
 * and idle session caps in server/session.ts (generous by default for a self-hosted install; tighten via THREATLENS_*_SESSION_* env vars) — so
 * a token recovered from a restored tab is short-lived.
 * -------------------------------------------------------------------------- */
const HISTORY_AUTH_KEY = "__threatlensAuth";
// Self-hosted default: also keep the token in localStorage so a refresh, a new
// tab or a browser restart does not force a re-login. Server-side session
// expiry (server/session.ts) still applies; a dead token is dropped on 401.
const STORAGE_AUTH_KEY = "threatlens.auth.token";

function readStoredToken(): string | null {
  try {
    const t = window.localStorage.getItem(STORAGE_AUTH_KEY);
    return t && t.length > 0 ? t : null;
  } catch {
    return null;
  }
}

function writeStoredToken(token: string | null): void {
  try {
    if (token) window.localStorage.setItem(STORAGE_AUTH_KEY, token);
    else window.localStorage.removeItem(STORAGE_AUTH_KEY);
  } catch {
    /* storage unavailable (private mode) — history.state still covers refresh */
  }
}
let historyAuthPatchInstalled = false;

type HistoryAuthState = {
  [HISTORY_AUTH_KEY]?: {
    token?: string;
  };
};

function readHistoryAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  const token = (window.history.state as HistoryAuthState | null)?.[HISTORY_AUTH_KEY]?.token;
  if (typeof token === "string" && token.length > 0) return token;
  return readStoredToken();
}

function writeHistoryAuthToken(token: string | null): void {
  if (typeof window === "undefined") return;
  writeStoredToken(token);
  const current = window.history.state && typeof window.history.state === "object" ? { ...window.history.state } : {};
  if (token) {
    (current as HistoryAuthState)[HISTORY_AUTH_KEY] = { token };
  } else {
    delete (current as HistoryAuthState)[HISTORY_AUTH_KEY];
  }
  window.history.replaceState(current, "", window.location.href);
}

function patchHistoryAuthState(): void {
  if (typeof window === "undefined" || historyAuthPatchInstalled) return;
  historyAuthPatchInstalled = true;

  const mergeAuthState = (state: unknown): unknown => {
    const existingToken = readHistoryAuthToken();
    if (!existingToken) return state;
    const next = state && typeof state === "object" ? { ...(state as Record<string, unknown>) } : {};
    if (!(HISTORY_AUTH_KEY in next)) {
      (next as HistoryAuthState)[HISTORY_AUTH_KEY] = { token: existingToken };
    }
    return next;
  };

  const originalReplaceState = window.history.replaceState.bind(window.history);
  const originalPushState = window.history.pushState.bind(window.history);

  window.history.replaceState = (state: unknown, unused: string, url?: string | URL | null) => {
    originalReplaceState(mergeAuthState(state), unused, url);
  };
  window.history.pushState = (state: unknown, unused: string, url?: string | URL | null) => {
    originalPushState(mergeAuthState(state), unused, url);
  };
}

export function resolveSessionAccessMode(
  user: Partial<Pick<AuthUser, "access_mode">> | null | undefined,
  session: { accessMode?: "credentialed" | "guest"; access_mode?: "credentialed" | "guest" } | null | undefined,
  fallback: "credentialed" | "guest" = "credentialed",
): "credentialed" | "guest" {
  return user?.access_mode ?? session?.accessMode ?? session?.access_mode ?? fallback;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  patchHistoryAuthState();
  const [token, setTok] = useState<string | null>(() => {
    const initial = STATIC_DEMO_MODE ? "static-demo-token" : readHistoryAuthToken();
    // Hand the token to the request layer synchronously so no child effect can
    // fire an unauthenticated request before the first render commits.
    setAuthToken(initial);
    return initial;
  });
  const [user, setUser] = useState<AuthUser | null>(() => (STATIC_DEMO_MODE ? STATIC_DEMO_USER : null));
  const [loading, setLoading] = useState(() => (STATIC_DEMO_MODE ? false : !!readHistoryAuthToken()));
  const [activeTid, setActiveTid] = useState<string | null>(() =>
    STATIC_DEMO_MODE ? STATIC_DEMO_USER.tenant.id : null,
  );

  // wire token holder used by queryClient
  useEffect(() => {
    setAuthToken(token);
  }, [token]);
  useEffect(() => {
    setActiveTenantId(activeTid);
  }, [activeTid]);

  // Rehydrate a still-valid server session after refresh or duplicated tab.
  // See the token-storage note above for why this uses history.state.
  useEffect(() => {
    if (STATIC_DEMO_MODE) return;
    const bootToken = readHistoryAuthToken();
    if (!bootToken) return;
    let cancelled = false;
    setAuthToken(bootToken);
    setLoading(true);
    apiRequest("GET", "/api/v1/me")
      .then((r) => r.json())
      .then((u: AuthUser) => {
        if (cancelled) return;
        setTok(bootToken);
        setUser(u);
        setActiveTid(u.tenant?.id ?? null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        // Only discard the token when the server rejected it. A network blip
        // or a restarting server must not sign the user out.
        const rejected = /^\s*40[13]:/.test(String((err as Error)?.message ?? ""));
        if (!rejected) return;
        writeHistoryAuthToken(null);
        setTok(null);
        setUser(null);
        setActiveTid(null);
        queryClient.clear();
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // logout on 401
  useEffect(() => {
    setOnUnauthorized(() => {
      writeHistoryAuthToken(null);
      setTok(null);
      setUser(null);
      setActiveTid(null);
      queryClient.clear();
    });
    return () => setOnUnauthorized(null);
  }, []);

  const login = async (email: string, password: string, mfaCode?: string) => {
    setLoading(true);
    try {
      const r = await apiRequest("POST", "/api/v1/auth/login", { email, password, mfaCode });
      const data = await r.json();
      setTok(data.access_token);
      setAuthToken(data.access_token);
      writeHistoryAuthToken(data.access_token);
      const me = await apiRequest("GET", "/api/v1/me");
      if (me.ok) {
        const u = await me.json();
        setUser(u);
        setActiveTid(u.tenant?.id ?? null);
      }
    } finally {
      setLoading(false);
    }
  };

  const refreshMe = async () => {
    const me = await apiRequest("GET", "/api/v1/me");
    if (me.ok) {
      const u = await me.json();
      setUser(u);
      setActiveTid(u.tenant?.id ?? null);
      return u as AuthUser;
    }
    return null;
  };

  const logout = () => {
    if (token) {
      apiRequest("POST", "/api/v1/auth/logout", {}).catch(() => {});
    }
    writeHistoryAuthToken(null);
    setTok(null);
    setUser(null);
    setActiveTid(null);
    queryClient.clear();
  };

  const setActiveTenant = (tid: string | null) => {
    // BatchOne keeps this API shape for older components, but the query
    // client no longer sends tenant override headers.
    setActiveTenantId(tid);
    setActiveTid(tid);
    // Drop any tenant-scoped caches so views refetch with the new header.
    queryClient.invalidateQueries();
  };

  const value = useMemo(
    () => ({ user, loading, activeTenantId: activeTid, setActiveTenant, login, refreshMe, logout }),
    [user, loading, activeTid],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
