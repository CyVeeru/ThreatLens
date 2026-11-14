import { useSyncExternalStore } from "react";

/**
 * Global ↔ My Organization view switch, shared by the feed and the analyst
 * queue. "global" shows all intel; "org" narrows to findings that match the
 * technology in the organization profile and ranks them by exposure.
 * Persisted per browser so the choice survives refreshes.
 */
export type OrgScope = "global" | "org";

const KEY = "threatlens.orgScope";
const listeners = new Set<() => void>();

function read(): OrgScope {
  try {
    return window.localStorage.getItem(KEY) === "org" ? "org" : "global";
  } catch {
    return "global";
  }
}

let current: OrgScope = typeof window === "undefined" ? "global" : read();

export function setOrgScope(next: OrgScope): void {
  current = next;
  try {
    window.localStorage.setItem(KEY, next);
  } catch {
    /* storage unavailable — keep the in-memory choice for this session */
  }
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useOrgScope(): [OrgScope, (next: OrgScope) => void] {
  const scope = useSyncExternalStore(
    subscribe,
    () => current,
    () => "global" as OrgScope,
  );
  return [scope, setOrgScope];
}

const PRIORITY_RANK = { urgent: 3, high: 2, watch: 1 } as const;

/** Sort comparator: strongest org exposure first. */
export function compareOrgExposure(
  a: { orgRelevance?: { priority: keyof typeof PRIORITY_RANK; score: number } | null },
  b: { orgRelevance?: { priority: keyof typeof PRIORITY_RANK; score: number } | null },
): number {
  const ra = a.orgRelevance ? PRIORITY_RANK[a.orgRelevance.priority] : 0;
  const rb = b.orgRelevance ? PRIORITY_RANK[b.orgRelevance.priority] : 0;
  return rb - ra || (b.orgRelevance?.score ?? 0) - (a.orgRelevance?.score ?? 0);
}
