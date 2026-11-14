/**
 * Session lifetime policy. Pure (no DB, no filesystem) so it can be unit
 * tested without opening the workspace database.
 */
import { env } from "./env";

/** Read a positive integer from `THREATLENS_<suffix>`, falling back to
 *  `fallback` when unset, non-numeric, zero, or negative. A typo in an `*_MS`
 *  variable must never turn into a `NaN` comparison that disables expiry
 *  entirely. */
export function positiveEnvInt(suffix: string, fallback: number): number {
  const raw = env(suffix);
  if (raw == null || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.warn(
      `[session] ignoring THREATLENS_${suffix}=${JSON.stringify(raw)} (expected a positive integer); using ${fallback}`,
    );
    return fallback;
  }
  return Math.floor(n);
}

export const SESSION_ABSOLUTE_MS = positiveEnvInt("SESSION_ABSOLUTE_MS", 90 * 24 * 60 * 60 * 1000);
export const SESSION_IDLE_TIMEOUT_MS = positiveEnvInt("SESSION_IDLE_MS", 30 * 24 * 60 * 60 * 1000);
export const ADMIN_SESSION_ABSOLUTE_MS = positiveEnvInt("ADMIN_SESSION_ABSOLUTE_MS", 30 * 24 * 60 * 60 * 1000);
export const ADMIN_SESSION_IDLE_TIMEOUT_MS = positiveEnvInt("ADMIN_SESSION_IDLE_MS", 7 * 24 * 60 * 60 * 1000);
export const SESSION_IDLE_TOUCH_MS = positiveEnvInt("SESSION_TOUCH_MS", 5 * 60 * 1000);

/** True when the activity marker is old enough to be worth rewriting. Keeps
 *  polling-heavy pages from issuing an UPDATE on every authenticated call. */
export function shouldTouchSession(lastUsedAt: string | null | undefined, nowMs = Date.now()): boolean {
  if (!lastUsedAt) return true;
  const lastUsedMs = Date.parse(lastUsedAt);
  if (!Number.isFinite(lastUsedMs)) return true;
  return nowMs - lastUsedMs >= SESSION_IDLE_TOUCH_MS;
}

export function sessionExpiryReason(
  session: { issuedAt?: string | null; lastUsedAt?: string | null; role?: string | null; accessMode?: string | null },
  nowMs = Date.now(),
): "absolute" | "idle" | null {
  const issuedMs = Date.parse(session.issuedAt || "");
  const lastUsedMs = Date.parse(session.lastUsedAt || "");
  const adminSession = session.role === "admin" && session.accessMode !== "guest";
  const absoluteMs = adminSession ? ADMIN_SESSION_ABSOLUTE_MS : SESSION_ABSOLUTE_MS;
  const idleMs = adminSession ? ADMIN_SESSION_IDLE_TIMEOUT_MS : SESSION_IDLE_TIMEOUT_MS;
  if (!Number.isFinite(issuedMs) || nowMs - issuedMs >= absoluteMs) return "absolute";
  if (!Number.isFinite(lastUsedMs) || nowMs - lastUsedMs >= idleMs) return "idle";
  return null;
}
