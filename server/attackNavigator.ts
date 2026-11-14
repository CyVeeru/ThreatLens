/**
 * MITRE ATT&CK Navigator layer export (layer format 4.5).
 *
 *   • Actor layer   — one actor's TTPs, scored by detection priority and
 *                     coloured by confirmation status.
 *   • Coverage layer— every technique observed across actors + findings in a
 *                     window, coloured by hunt coverage: hunted-with-hit,
 *                     hunted-no-hit, hunt drafted, or no hunt at all.
 */
import { sqlite } from "./storage";
import { latestHuntResultsByQuery } from "./huntResults";
import type { ThreatActorFullDTO } from "@shared/schema";
import { normaliseTechniqueId } from "./intelScoring";
import { TACTIC_ORDER, tacticSlug } from "./attackTactics";

export { normaliseTechniqueId, TACTIC_ORDER, tacticSlug };

const TECH_RE = /^T\d{4}(?:\.\d{3})?$/i;

interface LayerTechnique {
  techniqueID: string;
  tactic?: string;
  score?: number;
  color?: string;
  comment?: string;
  enabled: boolean;
  metadata: Array<{ name: string; value: string }>;
  showSubtechniques: boolean;
}

function baseLayer(
  name: string,
  description: string,
  techniques: LayerTechnique[],
  legend: Array<{ label: string; color: string }>,
) {
  return {
    name,
    versions: { attack: "16", navigator: "5.1.0", layer: "4.5" },
    domain: "enterprise-attack",
    description,
    filters: {
      platforms: [
        "Windows",
        "Linux",
        "macOS",
        "Network",
        "PRE",
        "Containers",
        "Office Suite",
        "Identity Provider",
        "SaaS",
        "IaaS",
      ],
    },
    sorting: 3,
    layout: {
      layout: "side",
      aggregateFunction: "max",
      showID: true,
      showName: true,
      showAggregateScores: true,
      countUnscored: false,
      expandedSubtechniques: "annotated",
    },
    hideDisabled: false,
    techniques,
    gradient: { colors: ["#ffe766", "#ff6666"], minValue: 0, maxValue: 100 },
    legendItems: legend,
    metadata: [
      { name: "generator", value: "ThreatLens BatchOne" },
      { name: "generatedAt", value: new Date().toISOString() },
    ],
    showTacticRowBackground: true,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}

const PRIORITY_SCORE: Record<string, number> = { P1: 100, P2: 75, P3: 50, P4: 25 };
const STATUS_COLOR: Record<string, string> = {
  confirmed: "#c62828",
  likely: "#ef6c00",
  suspected: "#f9a825",
  historical: "#9e9e9e",
};

export function buildActorNavigatorLayer(actor: ThreatActorFullDTO) {
  const byTech = new Map<string, LayerTechnique>();
  for (const t of actor.ttps) {
    const id = normaliseTechniqueId(t.subTechniqueId || t.techniqueId);
    if (!id) continue;
    const key = `${id}|${tacticSlug(t.tactic) ?? ""}`;
    const status = String(t.status || "suspected").toLowerCase();
    const entry: LayerTechnique = {
      techniqueID: id,
      tactic: tacticSlug(t.tactic),
      score: PRIORITY_SCORE[t.detectionPriority] ?? 50,
      color: STATUS_COLOR[status] ?? STATUS_COLOR.suspected,
      comment: [t.techniqueName, t.evidence ? `Evidence: ${t.evidence}` : null, `Origin: ${t.origin}`]
        .filter(Boolean)
        .join("\n"),
      enabled: true,
      metadata: [
        { name: "status", value: t.status },
        { name: "detectionPriority", value: t.detectionPriority },
        { name: "origin", value: t.origin },
      ],
      showSubtechniques: id.includes("."),
    };
    if (!byTech.has(key)) byTech.set(key, entry);
  }
  return baseLayer(
    `${actor.profileId} ${actor.primaryName}`,
    `TTPs attributed to ${actor.primaryName} in ThreatLens (${actor.ttps.length} rows; colour = confirmation status, score = detection priority).`,
    Array.from(byTech.values()),
    [
      { label: "Confirmed", color: STATUS_COLOR.confirmed },
      { label: "Likely", color: STATUS_COLOR.likely },
      { label: "Suspected", color: STATUS_COLOR.suspected },
      { label: "Historical", color: STATUS_COLOR.historical },
    ],
  );
}

const COVERAGE_COLOR = {
  hit: "#2e7d32", // hunted, hit recorded
  hunted: "#1565c0", // hunted, no hit
  drafted: "#f9a825", // hunt query exists, never run
  none: "#c62828", // observed, no hunt
};

export function buildCoverageNavigatorLayer(tenantId: string, opts?: { sinceDays?: number }) {
  const since = new Date(Date.now() - (opts?.sinceDays ?? 90) * 86400_000).toISOString();

  // Techniques observed on findings (AI-extracted) in the window.
  const findingRows = sqlite
    .prepare(
      `
    SELECT id, attack_techniques FROM osint_findings
    WHERE tenant_id = ? AND attack_techniques IS NOT NULL AND attack_techniques != '' AND COALESCE(published_at, created_at) >= ?
  `,
    )
    .all(tenantId, since) as Array<{ id: string; attack_techniques: string }>;
  const techFindings = new Map<string, Set<string>>();
  const techFindingTactics = new Map<string, Set<string>>();
  const techFindingNames = new Map<string, string>();
  for (const r of findingRows) {
    try {
      for (const t of JSON.parse(r.attack_techniques || "[]")) {
        const id = normaliseTechniqueId(typeof t === "string" ? t : t?.id);
        if (!id) continue;
        if (!techFindings.has(id)) techFindings.set(id, new Set());
        techFindings.get(id)!.add(r.id);
        if (typeof t === "object" && t) {
          const slug = tacticSlug(t.tactic);
          if (slug) {
            if (!techFindingTactics.has(id)) techFindingTactics.set(id, new Set());
            techFindingTactics.get(id)!.add(slug);
          }
          if (t.name && !techFindingNames.has(id)) techFindingNames.set(id, String(t.name).trim());
        }
      }
    } catch {
      /* ignore */
    }
  }
  // Techniques on actor profiles.
  const actorRows = sqlite
    .prepare(
      `
    SELECT t.technique_id, t.sub_technique_id, t.technique_name, t.tactic, a.primary_name
    FROM threat_actor_ttps t JOIN threat_actors a ON a.id = t.actor_id AND a.tenant_id = t.tenant_id
    WHERE t.tenant_id = ?
  `,
    )
    .all(tenantId) as Array<{
    technique_id: string;
    sub_technique_id: string | null;
    technique_name: string | null;
    tactic: string | null;
    primary_name: string;
  }>;
  const techActors = new Map<string, Set<string>>();
  // Technique -> tactic slug / display name, so the UI can lay out a matrix
  // instead of a flat list. A technique can sit under several tactics.
  const techTactics = new Map<string, Set<string>>();
  const techNames = new Map<string, string>();
  for (const r of actorRows) {
    const id = normaliseTechniqueId(r.sub_technique_id || r.technique_id);
    if (!id) continue;
    if (!techActors.has(id)) techActors.set(id, new Set());
    techActors.get(id)!.add(r.primary_name);
    const slug = tacticSlug(r.tactic);
    if (slug) {
      if (!techTactics.has(id)) techTactics.set(id, new Set());
      techTactics.get(id)!.add(slug);
    }
    if (r.technique_name && !techNames.has(id)) techNames.set(id, r.technique_name.trim());
  }

  // Hunt coverage: hunt queries -> their source findings -> techniques.
  const hunts = sqlite
    .prepare("SELECT id, title, source_finding_ids FROM hunt_queries WHERE tenant_id = ?")
    .all(tenantId) as Array<{ id: string; title: string; source_finding_ids: string }>;
  const findingToHunts = new Map<string, string[]>();
  for (const h of hunts) {
    try {
      for (const fid of JSON.parse(h.source_finding_ids || "[]"))
        findingToHunts.set(fid, [...(findingToHunts.get(fid) ?? []), h.id]);
    } catch {
      /* ignore */
    }
  }
  const results = latestHuntResultsByQuery(
    tenantId,
    hunts.map((h) => h.id),
  );

  const allTech = new Set<string>([...techFindings.keys(), ...techActors.keys()]);
  const techniques: LayerTechnique[] = [];
  const counts = { hit: 0, hunted: 0, drafted: 0, none: 0 };
  for (const id of allTech) {
    const findingIds = Array.from(techFindings.get(id) ?? []);
    const huntIds = Array.from(new Set(findingIds.flatMap((f) => findingToHunts.get(f) ?? [])));
    let state: keyof typeof COVERAGE_COLOR = "none";
    if (huntIds.length > 0) {
      const outcomes = huntIds.flatMap((h) => results.get(h) ?? []).map((r) => r.outcome);
      state = outcomes.includes("hit") ? "hit" : outcomes.length > 0 ? "hunted" : "drafted";
    }
    counts[state] += 1;
    const actors = Array.from(techActors.get(id) ?? []);
    const tactics = Array.from(new Set([...(techTactics.get(id) ?? []), ...(techFindingTactics.get(id) ?? [])]));
    const name = techNames.get(id) ?? techFindingNames.get(id) ?? null;
    techniques.push({
      techniqueID: id,
      // Navigator keys a cell by technique+tactic; the first is the primary
      // column, and `tactics` below carries the full set for our own matrix.
      tactic: tactics[0],
      score: Math.min(100, findingIds.length * 10 + actors.length * 15),
      color: COVERAGE_COLOR[state],
      comment: [
        `Coverage: ${state}`,
        findingIds.length ? `${findingIds.length} finding(s) in window` : null,
        actors.length ? `Actors: ${actors.slice(0, 6).join(", ")}${actors.length > 6 ? "…" : ""}` : null,
        huntIds.length ? `${huntIds.length} hunt quer${huntIds.length === 1 ? "y" : "ies"}` : null,
      ]
        .filter(Boolean)
        .join("\n"),
      enabled: true,
      metadata: [
        { name: "coverage", value: state },
        { name: "findings", value: String(findingIds.length) },
        { name: "actors", value: String(actors.length) },
        { name: "huntQueries", value: String(huntIds.length) },
        { name: "techniqueName", value: name ?? "" },
        { name: "tactics", value: tactics.join(",") },
      ],
      showSubtechniques: id.includes("."),
    });
  }

  const layer = baseLayer(
    `ThreatLens hunt coverage (${opts?.sinceDays ?? 90}d)`,
    `Techniques observed on ${findingRows.length} findings and ${techActors.size} actor-attributed techniques. ` +
      `Hit ${counts.hit} · hunted ${counts.hunted} · drafted ${counts.drafted} · no hunt ${counts.none}.`,
    techniques,
    [
      { label: "Hunted — hit recorded", color: COVERAGE_COLOR.hit },
      { label: "Hunted — no hit", color: COVERAGE_COLOR.hunted },
      { label: "Hunt drafted, not run", color: COVERAGE_COLOR.drafted },
      { label: "Observed, no hunt", color: COVERAGE_COLOR.none },
    ],
  );
  return { layer, counts, techniqueCount: allTech.size };
}

export function isTechniqueId(v: string): boolean {
  return TECH_RE.test(v);
}
