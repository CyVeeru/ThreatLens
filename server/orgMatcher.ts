/**
 * Pure matching engine for the organization profile: no database access, so it
 * can be unit tested directly. Scores a finding against the org's tech stack
 * and explains why.
 */
import type { OrgAssetDTO, OrgCriticality, OrgMatch, OrgPriority, OrgRelevance, OsintFindingDTO } from "@shared/schema";

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

const CRIT_WEIGHT: Record<OrgCriticality, number> = { critical: 1, high: 0.85, medium: 0.65, low: 0.45 };
const FIELD_WEIGHT = { tech: 1, title: 0.85, text: 0.55 } as const;
/** Terms shorter than this (e.g. "AWS", "IIS") only match tech/title, never free text. */
const MIN_TEXT_TERM_LENGTH = 5;

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface CompiledTerm {
  asset: OrgAssetDTO;
  term: string;
  re: RegExp;
  textAllowed: boolean;
}

/** Compile each asset name/alias to a boundary-aware, case-insensitive pattern.
 *  Spaces/hyphens/underscores inside a term are interchangeable ("Palo Alto" ≈ "palo-alto"). */
export function compileAssets(assets: OrgAssetDTO[]): CompiledTerm[] {
  const out: CompiledTerm[] = [];
  for (const asset of assets) {
    for (const term of [asset.name, ...asset.aliases]) {
      const clean = term.trim();
      if (clean.length < 2) continue;
      const body = clean
        .split(/[\s\-_]+/)
        .map(escapeRegex)
        .join("[\\s\\-_]+");
      out.push({
        asset,
        term: clean,
        re: new RegExp(`(?<![\\p{L}\\p{N}])${body}(?![\\p{L}\\p{N}])`, "iu"),
        textAllowed: clean.length >= MIN_TEXT_TERM_LENGTH,
      });
    }
  }
  return out;
}

function haystacks(f: OsintFindingDTO): { tech: string; title: string; text: string } {
  return {
    tech: (f.affectedTech || []).join("\n"),
    title: f.title || "",
    text: [f.summary, f.aiSummary, f.rawSnippet ? String(f.rawSnippet).slice(0, 2000) : ""].filter(Boolean).join("\n"),
  };
}

function priorityFor(f: OsintFindingDTO, score: number): { priority: OrgPriority; reasons: string[] } {
  const reasons: string[] = [];
  const kev = !!f.cveEnrichment?.kev;
  const epss = f.cveEnrichment?.epssScore ?? null;
  const cvss = f.cveEnrichment?.cvssScore ?? null;
  const sev = String(f.severity || "").toLowerCase();
  if (kev) reasons.push("Known exploited (CISA KEV)");
  if (epss != null && epss >= 0.5) reasons.push(`High exploit likelihood (EPSS ${Math.round(epss * 100)}%)`);
  if (cvss != null && cvss >= 9) reasons.push(`Critical CVSS ${cvss}`);
  else if (cvss != null && cvss >= 7) reasons.push(`High CVSS ${cvss}`);
  if (!kev && sev === "critical") reasons.push("Rated critical");

  let priority: OrgPriority = "watch";
  if (kev || (epss != null && epss >= 0.5) || ((cvss ?? 0) >= 9 && score >= 60)) priority = "urgent";
  else if (sev === "critical" || sev === "high" || (cvss ?? 0) >= 7 || score >= 70) priority = "high";
  return { priority, reasons };
}

/** Score one finding against the compiled org terms. Returns null when nothing matches. */
export function matchFinding(f: OsintFindingDTO, terms: CompiledTerm[]): OrgRelevance | null {
  if (terms.length === 0) return null;
  const hay = haystacks(f);
  const byAsset = new Map<string, OrgMatch & { weight: number }>();
  for (const t of terms) {
    for (const field of ["tech", "title", "text"] as const) {
      if (field === "text" && !t.textAllowed) continue;
      if (!hay[field] || !t.re.test(hay[field])) continue;
      const weight = FIELD_WEIGHT[field] * CRIT_WEIGHT[t.asset.criticality];
      const prev = byAsset.get(t.asset.id);
      if (!prev || weight > prev.weight) {
        byAsset.set(t.asset.id, {
          assetId: t.asset.id,
          assetName: t.asset.name,
          criticality: t.asset.criticality,
          field,
          term: t.term,
          weight,
        });
      }
    }
  }
  if (byAsset.size === 0) return null;
  const matches = Array.from(byAsset.values()).sort((a, b) => b.weight - a.weight);
  const best = matches[0].weight;
  const score = Math.min(100, Math.round(best * 100) + Math.min(15, (matches.length - 1) * 5));
  const { priority, reasons } = priorityFor(f, score);
  const top = matches[0];
  reasons.unshift(
    `Matches ${top.assetName} (${top.criticality} criticality) in ${top.field === "tech" ? "affected technology" : top.field}`,
  );
  return {
    matched: true,
    score,
    priority,
    matches: matches.map(({ weight: _w, ...m }) => m),
    reasons,
  };
}
