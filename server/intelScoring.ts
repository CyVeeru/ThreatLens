/**
 * Pure scoring / normalisation helpers shared by the enrichment, coverage and
 * queue modules. No database, no network — safe to import from anywhere
 * (including tests) without triggering workspace initialisation.
 */

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

/** Canonical upper-case CVE id, or null when the input is not a CVE. */
export function normaliseCveId(v: string): string | null {
  const s = String(v || "")
    .trim()
    .toUpperCase();
  return CVE_RE.test(s) ? s : null;
}

/** First ATT&CK technique id found in a string, or null. Sub-techniques keep
 *  their `.001` suffix; tactic ids (TA0001) are not techniques. */
export function normaliseTechniqueId(raw: unknown): string | null {
  const s = String(raw ?? "").toUpperCase();
  if (/\bTA\d{4}\b/.test(s) && !/\bT\d{4}(?!\d)/.test(s.replace(/\bTA\d{4}\b/g, ""))) return null;
  const m = s.replace(/\bTA\d{4}\b/g, "").match(/\bT\d{4}(?:\.\d{3})?\b/);
  return m ? m[0] : null;
}

/**
 * Composite 0-100 priority for a CVE. Exploitation evidence outranks raw
 * severity: a KEV-listed CVSS 5.0 must sort above a CVSS 10.0 with no known
 * exploitation, because the first is being used against people today.
 */
export function cvePriority(e: { kev: boolean; epssScore: number | null; cvssScore: number | null }): number {
  let p = 0;
  if (e.kev) p += 60;
  if (typeof e.epssScore === "number") p += Math.round(e.epssScore * 30);
  if (typeof e.cvssScore === "number") p += Math.round((e.cvssScore / 10) * 10);
  return Math.min(100, p);
}
