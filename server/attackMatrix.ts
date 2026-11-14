/**
 * MITRE ATT&CK knowledge base. Syncs the public Enterprise STIX bundle into
 * local tables and joins it with the rule library, so analysts can see — per
 * tactic and technique — what behaviour exists and how many detections cover it.
 */
import { sqlite } from "./storage";
import { fetchFeedPinned } from "./sourceFetch";
import { setSyncState } from "./iocFeeds";

export const ATTACK_BUNDLE_URL =
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

export interface AttackTactic {
  shortname: string;
  name: string;
  extId: string;
  order: number;
}
export interface AttackTechnique {
  id: string;
  name: string;
  isSub: boolean;
  parent: string | null;
  tactics: string[];
  description: string;
  detection: string;
  platforms: string[];
  url: string | null;
}

/** Strip ATT&CK's "(Citation: …)" markers and markdown links so text reads cleanly. */
export function cleanAttackText(s: unknown, max = 1500): string {
  return String(s ?? "")
    .replace(/\(Citation:[^)]*\)/g, "")
    .replace(/<code>|<\/code>/g, "`")
    .replace(/\[([^\]]+)\]\((?:https?:\/\/|\/)[^)]*\)/g, "$1")
    .replace(/\s+\n/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim()
    .slice(0, max);
}

export interface AttackDetection {
  techniqueId: string;
  detId: string;
  name: string;
  url: string | null;
  analytics: Array<{ platform: string; description: string }>;
}

export function parseAttackBundle(bundle: any): {
  tactics: AttackTactic[];
  techniques: AttackTechnique[];
  detections: AttackDetection[];
  version: string | null;
} {
  const objs: any[] = Array.isArray(bundle?.objects) ? bundle.objects : [];
  const live = (o: any) => !o.revoked && !o.x_mitre_deprecated;
  const byRef = new Map<string, AttackTactic>();
  const tacticByShort = new Map<string, AttackTactic>();
  for (const o of objs) {
    if (o.type !== "x-mitre-tactic" || !live(o)) continue;
    const ext = (o.external_references ?? []).find((r: any) => r.source_name === "mitre-attack");
    const t: AttackTactic = {
      shortname: String(o.x_mitre_shortname),
      name: String(o.name),
      extId: String(ext?.external_id ?? ""),
      order: 999,
    };
    byRef.set(o.id, t);
    tacticByShort.set(t.shortname, t);
  }
  // The matrix object lists tactics in their canonical column order.
  const matrix = objs.find((o) => o.type === "x-mitre-matrix");
  (matrix?.tactic_refs ?? []).forEach((ref: string, i: number) => {
    const t = byRef.get(ref);
    if (t) t.order = i;
  });
  const techniques: AttackTechnique[] = [];
  const techByStix = new Map<string, string>();
  for (const o of objs) {
    if (o.type !== "attack-pattern" || !live(o)) continue;
    const ext = (o.external_references ?? []).find(
      (r: any) => r.source_name === "mitre-attack" && /^T\d{4}/.test(r.external_id ?? ""),
    );
    if (!ext) continue;
    const id = String(ext.external_id);
    techByStix.set(o.id, id);
    const isSub = !!o.x_mitre_is_subtechnique || id.includes(".");
    techniques.push({
      id,
      name: String(o.name),
      isSub,
      parent: isSub ? id.split(".")[0] : null,
      tactics: (o.kill_chain_phases ?? [])
        .filter((p: any) => p.kill_chain_name === "mitre-attack")
        .map((p: any) => String(p.phase_name)),
      description: cleanAttackText(o.description, 1500),
      detection: cleanAttackText(o.x_mitre_detection, 1500),
      platforms: Array.isArray(o.x_mitre_platforms) ? o.x_mitre_platforms.map(String) : [],
      url: ext.url ?? null,
    });
  }
  // ATT&CK v18+ publishes detection guidance as strategies + analytics linked by "detects" relationships.
  const analytics = new Map<string, any>();
  const strategies = new Map<string, any>();
  for (const o of objs) {
    if (!live(o)) continue;
    if (o.type === "x-mitre-analytic") analytics.set(o.id, o);
    else if (o.type === "x-mitre-detection-strategy") strategies.set(o.id, o);
  }
  const detections: AttackDetection[] = [];
  const seen = new Set<string>();
  for (const o of objs) {
    if (o.type !== "relationship" || o.relationship_type !== "detects" || !live(o)) continue;
    const strat = strategies.get(o.source_ref);
    const techniqueId = techByStix.get(o.target_ref);
    if (!strat || !techniqueId) continue;
    const ext = (strat.external_references ?? []).find((r: any) => r.source_name === "mitre-attack");
    const detId = String(ext?.external_id ?? strat.id);
    if (seen.has(`${techniqueId}|${detId}`)) continue;
    seen.add(`${techniqueId}|${detId}`);
    const an = ((strat.x_mitre_analytic_refs ?? []) as string[])
      .map((ref) => analytics.get(ref))
      .filter(Boolean)
      .slice(0, 3)
      .map((a) => ({
        platform: Array.isArray(a.x_mitre_platforms) ? a.x_mitre_platforms.join(", ") : "",
        description: cleanAttackText(a.description, 500),
      }))
      .filter((a) => a.description);
    detections.push({
      techniqueId,
      detId,
      name: String(strat.name ?? detId).slice(0, 200),
      url: ext?.url ?? null,
      analytics: an,
    });
  }
  const tactics = Array.from(tacticByShort.values()).sort((a, b) => a.order - b.order || a.name.localeCompare(b.name));
  const collection = objs.find((o) => o.type === "x-mitre-collection");
  const version = (collection?.x_mitre_version ?? null) as string | null;
  return { tactics, techniques, detections, version: version ? String(version) : null };
}

export function storeAttack(data: ReturnType<typeof parseAttackBundle>): void {
  const tx = sqlite.transaction(() => {
    sqlite.exec("DELETE FROM attack_tactics; DELETE FROM attack_techniques; DELETE FROM attack_detections;");
    const t = sqlite.prepare("INSERT INTO attack_tactics (shortname, name, ext_id, ord) VALUES (?, ?, ?, ?)");
    for (const x of data.tactics) t.run(x.shortname, x.name, x.extId, x.order);
    const q = sqlite.prepare(
      "INSERT INTO attack_techniques (id, name, is_sub, parent, tactics, description, detection, platforms, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const x of data.techniques)
      q.run(
        x.id,
        x.name,
        x.isSub ? 1 : 0,
        x.parent,
        JSON.stringify(x.tactics),
        x.description,
        x.detection,
        JSON.stringify(x.platforms),
        x.url,
      );
    const d = sqlite.prepare(
      "INSERT OR REPLACE INTO attack_detections (technique_id, det_id, name, url, analytics) VALUES (?, ?, ?, ?, ?)",
    );
    for (const x of data.detections) d.run(x.techniqueId, x.detId, x.name, x.url, JSON.stringify(x.analytics));
  });
  tx();
}

export async function syncAttack(): Promise<{
  ok: boolean;
  techniques: number;
  version: string | null;
  error: string | null;
}> {
  try {
    const res = await fetchFeedPinned(ATTACK_BUNDLE_URL, { maxBytes: 120_000_000, timeoutMs: 180_000 });
    if (!res || res.status !== 200) throw new Error(`download failed (${res ? "HTTP " + res.status : "no response"})`);
    const data = parseAttackBundle(JSON.parse(res.body.toString("utf8")));
    if (data.techniques.length < 100 || data.tactics.length < 8)
      throw new Error("bundle looked incomplete — keeping the existing data");
    storeAttack(data);
    setSyncState("attack:enterprise", data.techniques.length, null);
    sqlite
      .prepare(
        "INSERT INTO intel_sync_state (key, last_run, item_count, last_error) VALUES ('attack:enterprise:version', ?, 0, ?) ON CONFLICT(key) DO UPDATE SET last_run=excluded.last_run, last_error=excluded.last_error",
      )
      .run(new Date().toISOString(), data.version ?? "");
    return { ok: true, techniques: data.techniques.length, version: data.version, error: null };
  } catch (e: any) {
    const error = String(e?.message || e).slice(0, 300);
    const prev = sqlite.prepare("SELECT item_count FROM intel_sync_state WHERE key = 'attack:enterprise'").get() as any;
    setSyncState("attack:enterprise", prev?.item_count ?? 0, error);
    return { ok: false, techniques: 0, version: null, error };
  }
}

const parse = <T>(s: string, d: T): T => {
  try {
    return JSON.parse(s) as T;
  } catch {
    return d;
  }
};

/** Rule counts per technique id from the rule library (sub-techniques counted on their parent too). */
export function ruleCountsByTechnique(): { exact: Map<string, number>; rollup: Map<string, number> } {
  const exact = new Map<string, number>();
  const rollup = new Map<string, number>();
  for (const r of sqlite.prepare("SELECT techniques FROM rule_library").all() as any[]) {
    const ids = new Set<string>();
    for (const t of parse<string[]>(r.techniques, [])) {
      exact.set(t, (exact.get(t) ?? 0) + 1);
      ids.add(t.split(".")[0]);
    }
    for (const base of ids) rollup.set(base, (rollup.get(base) ?? 0) + 1);
  }
  return { exact, rollup };
}

export function attackMatrix() {
  const tactics = sqlite
    .prepare("SELECT shortname, name, ext_id, ord FROM attack_tactics ORDER BY ord, name")
    .all() as any[];
  const rows = sqlite.prepare("SELECT id, name, is_sub, parent, tactics FROM attack_techniques").all() as any[];
  const { rollup } = ruleCountsByTechnique();
  const subs = new Map<string, number>();
  const subNames = new Map<string, string[]>();
  for (const r of rows) {
    if (!r.is_sub || !r.parent) continue;
    subs.set(r.parent, (subs.get(r.parent) ?? 0) + 1);
    subNames.set(r.parent, [...(subNames.get(r.parent) ?? []), `${r.id} ${r.name}`]);
  }
  const parents = rows.filter((r) => !r.is_sub);
  const out = tactics.map((t) => ({
    shortname: t.shortname as string,
    name: t.name as string,
    extId: t.ext_id as string,
    techniques: parents
      .filter((p) => parse<string[]>(p.tactics, []).includes(t.shortname))
      .map((p) => ({
        id: p.id as string,
        name: p.name as string,
        subCount: subs.get(p.id) ?? 0,
        ruleCount: rollup.get(p.id) ?? 0,
        /** "T1059.001 PowerShell" etc., so the matrix filter can find sub-techniques. */
        subs: subNames.get(p.id) ?? [],
      }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  }));
  const covered = parents.filter((p) => (rollup.get(p.id) ?? 0) > 0).length;
  const state = sqlite
    .prepare("SELECT last_run, last_error FROM intel_sync_state WHERE key = 'attack:enterprise'")
    .get() as any;
  const ver = sqlite
    .prepare("SELECT last_error v FROM intel_sync_state WHERE key = 'attack:enterprise:version'")
    .get() as any;
  return {
    tactics: out,
    totals: { techniques: parents.length, covered, uncovered: parents.length - covered },
    version: ver?.v || null,
    lastSync: state?.last_run ?? null,
    lastError: state?.last_error ?? null,
  };
}

export function attackTechnique(id: string) {
  const norm = id.trim().toUpperCase();
  const r = sqlite.prepare("SELECT * FROM attack_techniques WHERE id = ?").get(norm) as any;
  if (!r) return null;
  const { exact, rollup } = ruleCountsByTechnique();
  const detections = (
    sqlite
      .prepare("SELECT det_id, name, url, analytics FROM attack_detections WHERE technique_id = ? ORDER BY det_id")
      .all(norm) as any[]
  ).map((d) => ({
    id: d.det_id as string,
    name: d.name as string,
    url: d.url as string | null,
    analytics: parse<Array<{ platform: string; description: string }>>(d.analytics, []),
  }));
  const subs = (
    sqlite.prepare("SELECT id, name FROM attack_techniques WHERE parent = ? ORDER BY id").all(norm) as any[]
  ).map((s) => ({
    id: s.id as string,
    name: s.name as string,
    ruleCount: exact.get(s.id) ?? 0,
  }));
  const tactics = parse<string[]>(r.tactics, []).map((sn) => {
    const t = sqlite.prepare("SELECT name FROM attack_tactics WHERE shortname = ?").get(sn) as any;
    return { shortname: sn, name: (t?.name as string) ?? sn };
  });
  return {
    id: r.id as string,
    name: r.name as string,
    isSub: !!r.is_sub,
    parent: r.parent as string | null,
    tactics,
    description: r.description as string,
    detection: r.detection as string,
    platforms: parse<string[]>(r.platforms, []),
    url: r.url as string | null,
    detections,
    subTechniques: subs,
    // Parent techniques count rules for their sub-techniques too, matching the matrix cell.
    ruleCount: r.is_sub ? (exact.get(norm) ?? 0) : (rollup.get(norm) ?? 0),
  };
}
