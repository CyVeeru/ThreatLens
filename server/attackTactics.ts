/**
 * MITRE ATT&CK Enterprise tactics: slugs, ids and kill-chain order.
 *
 * Pure — no database, no filesystem — so tests import it without booting
 * storage. The same rule as intelScoring.ts: importing attackNavigator pulls in
 * storage, which opens and seeds data/data.db as a side effect.
 */

export const TACTIC_SLUG: Record<string, string> = {
  reconnaissance: "reconnaissance",
  "resource development": "resource-development",
  "initial access": "initial-access",
  execution: "execution",
  persistence: "persistence",
  "privilege escalation": "privilege-escalation",
  "defense evasion": "defense-evasion",
  "credential access": "credential-access",
  discovery: "discovery",
  "lateral movement": "lateral-movement",
  collection: "collection",
  "command and control": "command-and-control",
  exfiltration: "exfiltration",
  impact: "impact",
};
/** ATT&CK tactic id -> slug, for the bare "TA0007" form the AI extractor emits. */
export const TACTIC_ID_SLUG: Record<string, string> = {
  TA0043: "reconnaissance",
  TA0042: "resource-development",
  TA0001: "initial-access",
  TA0002: "execution",
  TA0003: "persistence",
  TA0004: "privilege-escalation",
  TA0005: "defense-evasion",
  TA0006: "credential-access",
  TA0007: "discovery",
  TA0008: "lateral-movement",
  TA0009: "collection",
  TA0011: "command-and-control",
  TA0010: "exfiltration",
  TA0040: "impact",
};

/**
 * Normalise a tactic to one slug.
 *
 * Exported for tests: the three input shapes below all reach this function from
 * different writers, and when bare ids were not handled the matrix rendered a
 * duplicate column per tactic ("initial-access" and "ta0001" side by side).
 */
export function tacticSlug(t: string | null | undefined): string | undefined {
  if (!t) return undefined;
  const raw = t.trim();
  // Three shapes reach this: "Discovery" from hand-authored dossiers,
  // "TA0007 Discovery" from enrichment, and a bare "TA0007" from the
  // AI extraction on findings. All three must collapse to one column.
  const bareId = /^TA\d{4}$/i.exec(raw);
  if (bareId) return TACTIC_ID_SLUG[raw.toUpperCase()];
  const k = raw
    .replace(/^TA\d{4}\s+/i, "")
    .toLowerCase()
    .replace(/[-_]+/g, " ")
    .trim();
  return TACTIC_SLUG[k] ?? (k ? k.replace(/\s+/g, "-") : undefined);
}

/** Enterprise tactics in kill-chain order — the column order of the matrix. */
export const TACTIC_ORDER: Array<{ slug: string; label: string; id: string }> = [
  { slug: "reconnaissance", label: "Reconnaissance", id: "TA0043" },
  { slug: "resource-development", label: "Resource Development", id: "TA0042" },
  { slug: "initial-access", label: "Initial Access", id: "TA0001" },
  { slug: "execution", label: "Execution", id: "TA0002" },
  { slug: "persistence", label: "Persistence", id: "TA0003" },
  { slug: "privilege-escalation", label: "Privilege Escalation", id: "TA0004" },
  { slug: "defense-evasion", label: "Defense Evasion", id: "TA0005" },
  { slug: "credential-access", label: "Credential Access", id: "TA0006" },
  { slug: "discovery", label: "Discovery", id: "TA0007" },
  { slug: "lateral-movement", label: "Lateral Movement", id: "TA0008" },
  { slug: "collection", label: "Collection", id: "TA0009" },
  { slug: "command-and-control", label: "Command and Control", id: "TA0011" },
  { slug: "exfiltration", label: "Exfiltration", id: "TA0010" },
  { slug: "impact", label: "Impact", id: "TA0040" },
];
