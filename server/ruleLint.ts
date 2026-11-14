/**
 * Sanity checks for AI-generated detection content. Models regularly mislabel
 * ATT&CK techniques and sometimes emit rules so broad they would alert on every
 * event. These checks are deterministic: they add `REVIEW:` notes to the rule
 * text so an engineer sees the problem before deploying, and never change the
 * rule logic itself.
 */

/** Resolves an ATT&CK technique id to its official name, or null when unknown. */
export type TechniqueLookup = (id: string) => string | null;

const COMMENT_PREFIX: Record<string, string> = { sigma: "#" };
const commentFor = (language: string) => COMMENT_PREFIX[language] ?? "//";

/** Models are asked to give "technique + tactic", so a tactic name after an id is correct usage. */
const TACTICS = [
  "reconnaissance",
  "recon",
  "resource development",
  "initial access",
  "execution",
  "persistence",
  "privilege escalation",
  "defense evasion",
  "stealth",
  "defense impairment",
  "credential access",
  "discovery",
  "lateral movement",
  "collection",
  "command and control",
  "c2",
  "exfiltration",
  "impact",
];
const isTacticLabel = (claimed: string) => {
  const c = claimed.toLowerCase().trim();
  return TACTICS.some((t) => c === t || c.startsWith(t + " ") || c.endsWith(" " + t));
};

const words = (s: string) =>
  s
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length >= 4);

/** True when the model's label plausibly describes the real technique. */
function labelMatches(official: string, claimed: string): boolean {
  const o = official.toLowerCase();
  const c = claimed.toLowerCase().trim();
  if (!c || isTacticLabel(c)) return true;
  if (o.includes(c) || c.includes(o)) return true;
  const ow = new Set(words(official));
  return words(claimed).some((w) => ow.has(w));
}

export function lintRule(language: string, text: string, lookup: TechniqueLookup | null): string[] {
  const warnings: string[] = [];

  if (lookup) {
    const seen = new Set<string>();
    // "T1588.002 — Exploit Public-Facing Application", "T1059: Command and Scripting Interpreter"
    for (const m of text.matchAll(/\b(T\d{4}(?:\.\d{3})?)\b(?:\s*[—–:\-(]\s*([A-Za-z][A-Za-z0-9 /&'.:-]{2,70}))?/g)) {
      const id = m[1];
      if (seen.has(id)) continue;
      seen.add(id);
      const official = lookup(id);
      if (official === null) {
        warnings.push(`${id} is not a valid ATT&CK technique.`);
      } else if (m[2] && !labelMatches(official, m[2].replace(/[;,|)].*$/, ""))) {
        warnings.push(
          `${id} is "${official}" in ATT&CK, not "${m[2].replace(/[;,|)].*$/, "").trim()}" — check the technique mapping.`,
        );
      }
    }
  }

  if (language === "crowdstrike_ioa") {
    const fields = Array.from(text.matchAll(/^\s*([A-Za-z ]+?)\s+regex(?:\s*\(PCRE\))?:\s*(.+?)\s*$/gim));
    const matchAll = fields.filter((f) => /^\(?\.[*+]\)?$/.test(f[2].trim()));
    if (fields.length > 0 && matchAll.length >= Math.max(2, Math.ceil(fields.length / 2))) {
      warnings.push(
        `Too broad: ${matchAll.length} of ${fields.length} regex fields match everything (.*), so this would fire on nearly every event of its rule type. Narrow the image and command-line patterns.`,
      );
    }
  }

  // Syntax slips that are certain to fail in the target product.
  const query = text
    .split("\n")
    .filter((l) => !/^\s*(\/\/|#)/.test(l))
    .join("\n");
  if (language === "sentinelone_star") {
    if (/(?<![=!<>])==(?!=)/.test(query)) warnings.push('Deep Visibility compares with "=", not "==".');
    const bad = /event\.type\s*=+\s*"([a-z]+(?:_[a-z]+)+)"/.exec(query);
    if (bad)
      warnings.push(
        `event.type "${bad[1]}" is not a Deep Visibility value — use the display form, e.g. "Process Creation".`,
      );
    if (/\bmatches\b/.test(query))
      warnings.push('"matches" is not a Deep Visibility operator — use RegExp, Contains or StartsWith.');
  }
  if (language === "elastic_rule" && /~=/.test(query)) {
    warnings.push('"~=" is not an EQL operator — use ":" (wildcards), "like~" or "regex~".');
  }
  if (language === "defender_rule" && /\|\s*(project|summarize)\b/i.test(query)) {
    const missing = ["Timestamp", "DeviceId", "ReportId"].filter((c) => !new RegExp("\\b" + c + "\\b").test(query));
    if (missing.length)
      warnings.push(
        `Custom detection rules must return ${missing.join(", ")}; the query drops ${missing.length === 1 ? "it" : "them"}.`,
      );
  }

  return warnings;
}

/** Append REVIEW notes to a rule's text; returns the text unchanged when it is clean. */
export function annotateRule(language: string, text: string, lookup: TechniqueLookup | null): string {
  const warnings = lintRule(language, text, lookup);
  if (warnings.length === 0) return text;
  const c = commentFor(language);
  return `${text.replace(/\s+$/, "")}\n${warnings.map((w) => `${c} REVIEW: ${w}`).join("\n")}`;
}
