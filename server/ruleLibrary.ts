/**
 * Detection rule library. Syncs the SigmaHQ community rules (Detection Rule
 * License 1.1 — author attribution is kept verbatim) and lets engineers search
 * them by text, ATT&CK technique, product and severity.
 *
 * Sigma doubles as the IoA catalogue: each rule describes an attacker
 * behaviour and carries ATT&CK tags, so it answers "do we already detect this?"
 */
import yaml from "js-yaml";
import JSZip from "jszip";
import { sqlite } from "./storage";
import { fetchFeedPinned } from "./sourceFetch";
import { setSyncState } from "./iocFeeds";
import { inferTechniques } from "./attackInference";

export const SIGMA_RELEASE_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest";
const SIGMA_ASSET = "sigma_core+.zip";
export const SIGMA_LICENSE = "Detection Rule License (DRL) 1.1";

export interface ParsedRule {
  id: string;
  source: string;
  ruleId: string;
  title: string;
  status: string | null;
  level: string | null;
  description: string | null;
  author: string | null;
  tags: string[];
  techniques: string[];
  cves: string[];
  refs: string[];
  product: string | null;
  category: string | null;
  service: string | null;
  raw: string;
  path: string | null;
  modified: string | null;
  license?: string;
}

/** Normalise an ATT&CK id from a Sigma tag (`attack.t1059.001` -> `T1059.001`). */
export function techniqueFromTag(tag: string): string | null {
  const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(String(tag).trim());
  return m ? m[1].toUpperCase() : null;
}

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

export function parseSigmaRule(text: string, path: string | null = null): ParsedRule | null {
  let doc: any;
  try {
    doc = yaml.load(text, { schema: yaml.JSON_SCHEMA });
  } catch {
    try {
      // Sigma uses unquoted dates; the default schema parses them, JSON does not.
      doc = yaml.load(text);
    } catch {
      return null;
    }
  }
  if (!doc || typeof doc !== "object" || typeof doc.title !== "string" || !doc.detection) return null;
  const ruleId = String(doc.id ?? "").trim();
  if (!ruleId) return null;
  const tags: string[] = Array.isArray(doc.tags) ? doc.tags.map((t: unknown) => String(t)) : [];
  const techniques = Array.from(new Set(tags.map(techniqueFromTag).filter((t): t is string => !!t)));
  const refs: string[] = Array.isArray(doc.references) ? doc.references.map((r: unknown) => String(r)) : [];
  const cves = new Set<string>();
  for (const t of tags) {
    const m = /^cve\.(\d{4}-\d{4,})$/i.exec(t);
    if (m) cves.add(`CVE-${m[1]}`);
  }
  for (const src of [doc.title, doc.description, ...refs]) {
    for (const m of String(src ?? "").matchAll(CVE_RE)) cves.add(m[0].toUpperCase());
  }
  const ls = (doc.logsource && typeof doc.logsource === "object" ? doc.logsource : {}) as Record<string, unknown>;
  const asStr = (v: unknown) => (v == null ? null : String(v instanceof Date ? v.toISOString().slice(0, 10) : v));
  return {
    id: `sigmahq:${ruleId}`,
    source: "sigmahq",
    ruleId,
    title: doc.title.slice(0, 300),
    status: asStr(doc.status),
    level: asStr(doc.level)?.toLowerCase() ?? null,
    description: doc.description ? String(doc.description).slice(0, 2000) : null,
    author: asStr(doc.author)?.slice(0, 300) ?? null,
    tags,
    techniques,
    cves: Array.from(cves),
    refs: refs.slice(0, 20),
    product: asStr(ls.product),
    category: asStr(ls.category),
    service: asStr(ls.service),
    raw: text,
    path,
    modified: asStr(doc.modified ?? doc.date),
  };
}

export function storeRules(rules: ParsedRule[], now = new Date()): number {
  const ts = now.toISOString();
  const up = sqlite.prepare(`
    INSERT INTO rule_library (id, source, rule_id, title, status, level, description, author, tags, techniques, cves, refs, product, category, service, raw, path, modified, license, synced_at)
    VALUES (@id, @source, @rule_id, @title, @status, @level, @description, @author, @tags, @techniques, @cves, @refs, @product, @category, @service, @raw, @path, @modified, @license, @synced_at)
    ON CONFLICT(id) DO UPDATE SET
      title=excluded.title, status=excluded.status, level=excluded.level, description=excluded.description, author=excluded.author,
      tags=excluded.tags, techniques=excluded.techniques, cves=excluded.cves, refs=excluded.refs, product=excluded.product,
      category=excluded.category, service=excluded.service, raw=excluded.raw, path=excluded.path, modified=excluded.modified,
      license=excluded.license, synced_at=excluded.synced_at`);
  const tx = sqlite.transaction(() => {
    for (const r of rules) {
      up.run({
        id: r.id,
        source: r.source,
        rule_id: r.ruleId,
        title: r.title,
        status: r.status,
        level: r.level,
        description: r.description,
        author: r.author,
        tags: JSON.stringify(r.tags),
        techniques: JSON.stringify(r.techniques),
        cves: JSON.stringify(r.cves),
        refs: JSON.stringify(r.refs),
        product: r.product,
        category: r.category,
        service: r.service,
        raw: r.raw,
        path: r.path,
        modified: r.modified,
        license: r.license ?? SIGMA_LICENSE,
        synced_at: ts,
      });
    }
    for (const src of new Set(rules.map((r) => r.source))) {
      sqlite.prepare("DELETE FROM rule_library WHERE source = ? AND synced_at < ?").run(src, ts);
    }
  });
  tx();
  return rules.length;
}

export async function parseSigmaZip(buf: Buffer): Promise<ParsedRule[]> {
  const zip = await JSZip.loadAsync(buf);
  const out: ParsedRule[] = [];
  for (const [name, entry] of Object.entries(zip.files)) {
    if (entry.dir || !/\.ya?ml$/i.test(name)) continue;
    const text = await entry.async("string");
    const rule = parseSigmaRule(text, name);
    if (rule) out.push(rule);
  }
  return out;
}

export interface RuleSyncResult {
  ok: boolean;
  count: number;
  version: string | null;
  error: string | null;
}

export async function syncSigma(): Promise<RuleSyncResult> {
  try {
    const rel = await fetchFeedPinned(SIGMA_RELEASE_API, { maxBytes: 2_000_000, timeoutMs: 30_000 });
    if (!rel || rel.status !== 200)
      throw new Error(`release lookup failed (${rel ? "HTTP " + rel.status : "no response"})`);
    const meta = JSON.parse(rel.body.toString("utf8"));
    const asset = (meta.assets ?? []).find((a: any) => a.name === SIGMA_ASSET);
    if (!asset?.browser_download_url) throw new Error(`release ${meta.tag_name} has no ${SIGMA_ASSET} asset`);
    const zipRes = await fetchFeedPinned(asset.browser_download_url, { maxBytes: 30_000_000, timeoutMs: 90_000 });
    if (!zipRes || zipRes.status !== 200)
      throw new Error(`rule download failed (${zipRes ? "HTTP " + zipRes.status : "no response"})`);
    const rules = await parseSigmaZip(zipRes.body);
    if (rules.length < 100) throw new Error(`only ${rules.length} rules parsed — refusing to replace the library`);
    storeRules(rules);
    setSyncState("rules:sigmahq", rules.length, null);
    sqlite
      .prepare(
        "INSERT INTO intel_sync_state (key, last_run, item_count, last_error) VALUES ('rules:sigmahq:version', ?, 0, ?) ON CONFLICT(key) DO UPDATE SET last_run=excluded.last_run, last_error=excluded.last_error",
      )
      .run(new Date().toISOString(), String(meta.tag_name));
    return { ok: true, count: rules.length, version: String(meta.tag_name), error: null };
  } catch (e: any) {
    const error = String(e?.message || e).slice(0, 300);
    const prev = sqlite.prepare("SELECT item_count FROM intel_sync_state WHERE key = 'rules:sigmahq'").get() as any;
    setSyncState("rules:sigmahq", prev?.item_count ?? 0, error);
    return { ok: false, count: 0, version: null, error };
  }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

export interface RuleSummary {
  id: string;
  source: string;
  ruleId: string;
  title: string;
  status: string | null;
  level: string | null;
  description: string | null;
  author: string | null;
  techniques: string[];
  cves: string[];
  product: string | null;
  category: string | null;
  service: string | null;
  path: string | null;
  modified: string | null;
  license: string | null;
}

function rowToSummary(r: any): RuleSummary {
  const j = (s: string) => {
    try {
      return JSON.parse(s);
    } catch {
      return [];
    }
  };
  return {
    id: r.id,
    source: r.source ?? "sigmahq",
    ruleId: r.rule_id,
    title: r.title,
    status: r.status,
    level: r.level,
    description: r.description,
    author: r.author,
    techniques: j(r.techniques),
    cves: j(r.cves),
    product: r.product,
    category: r.category,
    service: r.service,
    path: r.path,
    modified: r.modified,
    license: r.license,
  };
}

const LEVEL_RANK =
  "CASE level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END";
const likeEsc = (s: string) => s.replace(/[\\%_]/g, "\\$&");

export function searchRules(opts: {
  q?: string;
  technique?: string;
  product?: string;
  level?: string;
  source?: string;
  limit?: number;
  offset?: number;
}) {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.q?.trim()) {
    for (const tok of opts.q.trim().split(/\s+/).slice(0, 6)) {
      const like = `%${likeEsc(tok)}%`;
      where.push(
        "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\' OR cves LIKE ? ESCAPE '\\')",
      );
      params.push(like, like, like, like);
    }
  }
  if (opts.technique?.trim()) {
    const t = opts.technique.trim().toUpperCase();
    where.push("(techniques LIKE ? ESCAPE '\\')");
    params.push(`%"${likeEsc(t)}%`);
  }
  if (opts.product) {
    where.push("product = ?");
    params.push(opts.product);
  }
  if (opts.level) {
    where.push("level = ?");
    params.push(opts.level);
  }
  if (opts.source) {
    where.push("source = ?");
    params.push(opts.source);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const limit = Math.min(200, Math.max(1, opts.limit ?? 50));
  const offset = Math.max(0, opts.offset ?? 0);
  const total = (sqlite.prepare(`SELECT COUNT(*) c FROM rule_library ${clause}`).get(...params) as any).c as number;
  const rows = sqlite
    .prepare(
      `SELECT id, source, rule_id, title, status, level, description, author, techniques, cves, product, category, service, path, modified, license
              FROM rule_library ${clause} ORDER BY ${LEVEL_RANK}, title COLLATE NOCASE LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset) as any[];
  return { total, rules: rows.map(rowToSummary) };
}

export function getRule(id: string): (RuleSummary & { raw: string; refs: string[]; tags: string[] }) | null {
  const r = sqlite.prepare("SELECT * FROM rule_library WHERE id = ?").get(id) as any;
  if (!r) return null;
  const j = (s: string) => {
    try {
      return JSON.parse(s);
    } catch {
      return [];
    }
  };
  return { ...rowToSummary(r), raw: r.raw, refs: j(r.refs), tags: j(r.tags) };
}

export function ruleLibrarySummary() {
  const total = (sqlite.prepare("SELECT COUNT(*) c FROM rule_library").get() as any).c as number;
  const byLevel = sqlite
    .prepare("SELECT COALESCE(level,'unrated') k, COUNT(*) c FROM rule_library GROUP BY k")
    .all() as any[];
  const byProduct = sqlite
    .prepare(
      "SELECT product k, COUNT(*) c FROM rule_library WHERE product IS NOT NULL GROUP BY k ORDER BY c DESC LIMIT 12",
    )
    .all() as any[];
  const bySource = sqlite.prepare("SELECT source k, COUNT(*) c FROM rule_library GROUP BY k").all() as any[];
  const yaraState = sqlite
    .prepare("SELECT last_run, last_error FROM intel_sync_state WHERE key = 'rules:yara'")
    .get() as any;
  const state = sqlite
    .prepare("SELECT last_run, last_error FROM intel_sync_state WHERE key = 'rules:sigmahq'")
    .get() as any;
  const ver = sqlite
    .prepare("SELECT last_error v FROM intel_sync_state WHERE key = 'rules:sigmahq:version'")
    .get() as any;
  return {
    total,
    byLevel: Object.fromEntries(byLevel.map((r) => [r.k, r.c])),
    byProduct: byProduct.map((r) => ({ product: r.k as string, count: r.c as number })),
    bySource: Object.fromEntries(bySource.map((r) => [r.k, r.c])),
    yaraLastSync: yaraState?.last_run ?? null,
    yaraLastError: yaraState?.last_error ?? null,
    lastSync: state?.last_run ?? null,
    lastError: state?.last_error ?? null,
    version: ver?.v ?? null,
    license: SIGMA_LICENSE,
  };
}

// ---------------------------------------------------------------------------
// Coverage: does a detection already exist for this finding?
// ---------------------------------------------------------------------------

export type CoverageVerdict = "covered" | "partial" | "gap" | "unknown";
export interface CoverageResult {
  verdict: CoverageVerdict;
  summary: string;
  techniques: string[];
  /** True when the techniques were inferred from the article text rather than extracted by AI. */
  techniquesInferred: boolean;
  cves: string[];
  cveRules: RuleSummary[];
  techniqueRules: Array<RuleSummary & { matchedTechnique: string }>;
  libraryEmpty: boolean;
}

/** T1059 covers T1059.001 and vice versa. */
function techniqueMatches(a: string, b: string): boolean {
  return a === b || a.startsWith(b + ".") || b.startsWith(a + ".");
}

export function coverageFor(finding: {
  cveIds?: string[];
  attackTechniques?: Array<{ id: string }> | null;
  title?: string | null;
  summary?: string | null;
  aiSummary?: string | null;
  rawSnippet?: string | null;
}): CoverageResult {
  const cves = Array.from(new Set((finding.cveIds ?? []).map((c) => c.toUpperCase())));
  let techniques = Array.from(
    new Set(
      (finding.attackTechniques ?? [])
        .map((t) => String(t.id).toUpperCase())
        .filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)),
    ),
  );
  let techniquesInferred = false;
  if (techniques.length === 0) {
    const text = [finding.title, finding.summary, finding.aiSummary, finding.rawSnippet].filter(Boolean).join("\n");
    techniques = inferTechniques(text).map((t) => t.id);
    techniquesInferred = techniques.length > 0;
  }
  const libraryEmpty = (sqlite.prepare("SELECT COUNT(*) c FROM rule_library").get() as any).c === 0;
  const empty = { techniques, techniquesInferred, cves, cveRules: [], techniqueRules: [], libraryEmpty };
  if (libraryEmpty) return { verdict: "unknown", summary: "The rule library has not been synced yet.", ...empty };
  if (cves.length === 0 && techniques.length === 0) {
    return {
      verdict: "unknown",
      summary:
        "No CVE or recognisable attacker behaviour was found in this finding, so coverage cannot be checked. Run AI analysis to extract ATT&CK techniques.",
      ...empty,
    };
  }
  const cols =
    "id, source, rule_id, title, status, level, description, author, techniques, cves, product, category, service, path, modified, license";
  const cveRules: RuleSummary[] = [];
  for (const c of cves.slice(0, 20)) {
    for (const r of sqlite
      .prepare(`SELECT ${cols} FROM rule_library WHERE cves LIKE ? LIMIT 5`)
      .all(`%"${c}"%`) as any[]) {
      if (!cveRules.some((x) => x.id === r.id)) cveRules.push(rowToSummary(r));
    }
  }
  const techniqueRules: Array<RuleSummary & { matchedTechnique: string }> = [];
  for (const t of techniques.slice(0, 15)) {
    const base = t.split(".")[0];
    const rows = sqlite
      .prepare(`SELECT ${cols} FROM rule_library WHERE techniques LIKE ? ORDER BY ${LEVEL_RANK} LIMIT 40`)
      .all(`%"${base}%`) as any[];
    for (const r of rows) {
      const s = rowToSummary(r);
      const hit = s.techniques.find((x) => techniqueMatches(x, t));
      if (hit && !techniqueRules.some((x) => x.id === s.id)) techniqueRules.push({ ...s, matchedTechnique: t });
    }
  }
  const sorted = techniqueRules.slice(0, 25);
  let verdict: CoverageVerdict;
  let summary: string;
  if (cveRules.length > 0) {
    verdict = "covered";
    summary = `${cveRules.length} existing rule${cveRules.length === 1 ? "" : "s"} reference ${cves.length === 1 ? "this CVE" : "these CVEs"} directly.`;
  } else if (sorted.length > 0) {
    verdict = "partial";
    summary = `No rule targets ${cves.length ? "this CVE" : "this exact activity"}, but ${sorted.length} existing rule${sorted.length === 1 ? "" : "s"} detect the same ATT&CK behaviour (${techniques.join(", ")}). Review them, then generate a specific rule if the gap matters.`;
  } else {
    verdict = "gap";
    summary = "No existing rule covers this CVE or these ATT&CK techniques. Generate a detection for it.";
  }
  return { verdict, summary, techniques, techniquesInferred, cves, cveRules, techniqueRules: sorted, libraryEmpty };
}

// ---------------------------------------------------------------------------
// YARA (ReversingLabs open rules, MIT)
// ---------------------------------------------------------------------------

export const YARA_LICENSE = "MIT (ReversingLabs YARA rules)";
export const YARA_ZIP_URL = "https://api.github.com/repos/reversinglabs/reversinglabs-yara-rules/zipball/develop";

/** One .yara file (may hold several rules) -> one library entry. */
export function parseYaraFile(text: string, path: string): ParsedRule | null {
  const names = Array.from(text.matchAll(/^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)/gm)).map(
    (m) => m[1],
  );
  if (names.length === 0) return null;
  const meta = new Map<string, string>();
  for (const m of text.matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"/gm)) {
    if (!meta.has(m[1])) meta.set(m[1], m[2]);
  }
  const techniques = Array.from(
    new Set(Array.from(text.matchAll(/\bT\d{4}(?:\.\d{3})?\b/g)).map((m) => m[0].toUpperCase())),
  );
  const cves = Array.from(new Set(Array.from(text.matchAll(CVE_RE)).map((m) => m[0].toUpperCase())));
  const parts = path.split("/").filter(Boolean);
  const dirs = parts.slice(0, -1).filter((p) => p !== "yara" && !/^reversinglabs-/i.test(p));
  const category = dirs[dirs.length - 1] ?? null;
  const base = parts[parts.length - 1]?.replace(/\.(yara|yar)$/i, "") ?? names[0];
  return {
    id: `reversinglabs-yara:${base}`,
    source: "reversinglabs-yara",
    ruleId: base,
    title:
      (meta.get("threat_name") || meta.get("description") || names[0]).slice(0, 300) +
      (names.length > 1 ? ` (+${names.length - 1} more)` : ""),
    status: null,
    level: null,
    description: meta.get("description")?.slice(0, 2000) ?? null,
    author: meta.get("author") ?? null,
    tags: names,
    techniques,
    cves,
    refs: meta.get("reference") ? [meta.get("reference")!] : [],
    product: "yara",
    category,
    service: null,
    raw: text,
    path,
    modified: meta.get("date") ?? null,
    license: YARA_LICENSE,
  };
}

export async function syncYara(): Promise<RuleSyncResult> {
  try {
    const res = await fetchFeedPinned(YARA_ZIP_URL, { maxBytes: 30_000_000, timeoutMs: 90_000 });
    if (!res || res.status !== 200) throw new Error(`download failed (${res ? "HTTP " + res.status : "no response"})`);
    const zip = await JSZip.loadAsync(res.body);
    const rules: ParsedRule[] = [];
    for (const [name, entry] of Object.entries(zip.files)) {
      if (entry.dir || !/\.(yara|yar)$/i.test(name)) continue;
      const rule = parseYaraFile(await entry.async("string"), name.split("/").slice(1).join("/"));
      if (rule) rules.push(rule);
    }
    if (rules.length < 50) throw new Error(`only ${rules.length} YARA files parsed — refusing to replace the library`);
    storeRules(rules);
    setSyncState("rules:yara", rules.length, null);
    return { ok: true, count: rules.length, version: "develop", error: null };
  } catch (e: any) {
    const error = String(e?.message || e).slice(0, 300);
    const prev = sqlite.prepare("SELECT item_count FROM intel_sync_state WHERE key = 'rules:yara'").get() as any;
    setSyncState("rules:yara", prev?.item_count ?? 0, error);
    return { ok: false, count: 0, version: null, error };
  }
}
