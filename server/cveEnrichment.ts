/**
 * CVE enrichment — CVSS (NVD), exploit probability (FIRST EPSS) and
 * known-exploited status (CISA KEV) for every CVE referenced by findings.
 *
 * Upstreams and their limits:
 *   • EPSS   https://api.first.org/data/v1/epss?cve=A,B,…   bulk, generous
 *   • KEV    single JSON catalog, refreshed every 6 h in memory
 *   • NVD    https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…
 *            5 requests / 30 s unauthenticated → at most a few per tick
 *
 * All calls go through the pinned outbound fetcher.
 */
import { fetchFeedPinned } from "./sourceFetch";
import { env } from "./env";
import { sqlite } from "./storage";
import type { CveEnrichmentDTO, CveEnrichmentSummary } from "@shared/schema";
import { cvePriority, normaliseCveId } from "./intelScoring";

export { cvePriority, normaliseCveId };

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_TTL_MS = 6 * 60 * 60 * 1000;
const RECHECK_MS = 24 * 60 * 60 * 1000;
const NVD_PER_TICK = Number(env("NVD_PER_TICK") || 4);
const NVD_SPACING_MS = 6500;

// ---------- KEV catalog cache ----------
type KevEntry = { dateAdded: string | null; knownRansomware: boolean; vendor: string; product: string; name: string };
let kevCache: { loadedAt: number; byCve: Map<string, KevEntry> } | null = null;

async function loadKev(force = false): Promise<Map<string, KevEntry> | null> {
  if (!force && kevCache && Date.now() - kevCache.loadedAt < KEV_TTL_MS) return kevCache.byCve;
  const res = await fetchFeedPinned(KEV_URL, { maxBytes: 16_000_000, timeoutMs: 20_000 });
  if (!res || res.status !== 200) return kevCache?.byCve ?? null;
  try {
    const j = JSON.parse(res.body.toString("utf8"));
    const byCve = new Map<string, KevEntry>();
    for (const v of j?.vulnerabilities ?? []) {
      const id = normaliseCveId(v?.cveID);
      if (!id) continue;
      byCve.set(id, {
        dateAdded: v?.dateAdded ?? null,
        knownRansomware: /known/i.test(String(v?.knownRansomwareCampaignUse ?? "")),
        vendor: String(v?.vendorProject ?? ""),
        product: String(v?.product ?? ""),
        name: String(v?.vulnerabilityName ?? ""),
      });
    }
    kevCache = { loadedAt: Date.now(), byCve };
    return byCve;
  } catch {
    return kevCache?.byCve ?? null;
  }
}

// ---------- persistence ----------
function rowToDto(r: any): CveEnrichmentDTO {
  return {
    cveId: r.cve_id,
    cvssScore: r.cvss_score ?? null,
    cvssVector: r.cvss_vector ?? null,
    cvssSeverity: r.cvss_severity ?? null,
    epssScore: r.epss_score ?? null,
    epssPercentile: r.epss_percentile ?? null,
    kev: !!r.kev,
    kevDateAdded: r.kev_date_added ?? null,
    kevKnownRansomware: !!r.kev_known_ransomware,
    publishedAt: r.published_at ?? null,
    description: r.description ?? null,
    nvdCheckedAt: r.nvd_checked_at ?? null,
    epssCheckedAt: r.epss_checked_at ?? null,
    kevCheckedAt: r.kev_checked_at ?? null,
    updatedAt: r.updated_at,
  };
}

export function getCveEnrichment(cveIds: string[]): Map<string, CveEnrichmentDTO> {
  const ids = Array.from(new Set(cveIds.map(normaliseCveId).filter((v): v is string => !!v)));
  const out = new Map<string, CveEnrichmentDTO>();
  for (let i = 0; i < ids.length; i += 400) {
    const slice = ids.slice(i, i + 400);
    const rows = sqlite
      .prepare(`SELECT * FROM cve_enrichment WHERE cve_id IN (${slice.map(() => "?").join(",")})`)
      .all(...slice) as any[];
    for (const r of rows) out.set(r.cve_id, rowToDto(r));
  }
  return out;
}

export function summariseForFinding(
  cveIds: string[],
  cache: Map<string, CveEnrichmentDTO>,
): CveEnrichmentSummary | null {
  let best: CveEnrichmentSummary | null = null;
  for (const raw of cveIds) {
    const id = normaliseCveId(raw);
    if (!id) continue;
    const e = cache.get(id);
    if (!e) continue;
    const priority = cvePriority(e);
    if (!best || priority > best.priority) {
      best = { cveId: id, cvssScore: e.cvssScore, epssScore: e.epssScore, kev: e.kev, priority };
    }
  }
  return best;
}

/** Attach `cveEnrichment` summaries to a list of findings in one query. */
export function attachCveSummaries<T extends { cveIds: string[]; cveEnrichment?: CveEnrichmentSummary | null }>(
  findings: T[],
): T[] {
  const all = findings.flatMap((f) => f.cveIds || []);
  if (all.length === 0) return findings;
  const cache = getCveEnrichment(all);
  for (const f of findings) f.cveEnrichment = summariseForFinding(f.cveIds || [], cache);
  return findings;
}

function upsert(fields: Partial<CveEnrichmentDTO> & { cveId: string }): void {
  const now = new Date().toISOString();
  const existing = sqlite.prepare("SELECT * FROM cve_enrichment WHERE cve_id = ?").get(fields.cveId) as any;
  const merged = { ...(existing ? rowToDto(existing) : {}), ...fields } as Partial<CveEnrichmentDTO> & {
    cveId: string;
  };
  sqlite
    .prepare(
      `
    INSERT INTO cve_enrichment (cve_id, cvss_score, cvss_vector, cvss_severity, epss_score, epss_percentile, kev, kev_date_added, kev_known_ransomware,
      published_at, description, nvd_checked_at, epss_checked_at, kev_checked_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
      cvss_score = excluded.cvss_score, cvss_vector = excluded.cvss_vector, cvss_severity = excluded.cvss_severity,
      epss_score = excluded.epss_score, epss_percentile = excluded.epss_percentile,
      kev = excluded.kev, kev_date_added = excluded.kev_date_added, kev_known_ransomware = excluded.kev_known_ransomware,
      published_at = excluded.published_at, description = excluded.description,
      nvd_checked_at = excluded.nvd_checked_at, epss_checked_at = excluded.epss_checked_at, kev_checked_at = excluded.kev_checked_at,
      updated_at = excluded.updated_at
  `,
    )
    .run(
      merged.cveId,
      merged.cvssScore ?? null,
      merged.cvssVector ?? null,
      merged.cvssSeverity ?? null,
      merged.epssScore ?? null,
      merged.epssPercentile ?? null,
      merged.kev ? 1 : 0,
      merged.kevDateAdded ?? null,
      merged.kevKnownRansomware ? 1 : 0,
      merged.publishedAt ?? null,
      merged.description ?? null,
      merged.nvdCheckedAt ?? null,
      merged.epssCheckedAt ?? null,
      merged.kevCheckedAt ?? null,
      now,
    );
}

// ---------- upstream fetchers ----------
async function enrichEpss(ids: string[]): Promise<number> {
  let done = 0;
  for (let i = 0; i < ids.length; i += 100) {
    const slice = ids.slice(i, i + 100);
    const res = await fetchFeedPinned(`${EPSS_URL}?cve=${encodeURIComponent(slice.join(","))}`, {
      maxBytes: 4_000_000,
      timeoutMs: 20_000,
    });
    if (!res || res.status !== 200) continue;
    let j: any;
    try {
      j = JSON.parse(res.body.toString("utf8"));
    } catch {
      continue;
    }
    const now = new Date().toISOString();
    const seen = new Set<string>();
    for (const row of j?.data ?? []) {
      const id = normaliseCveId(row?.cve);
      if (!id) continue;
      seen.add(id);
      upsert({ cveId: id, epssScore: Number(row.epss), epssPercentile: Number(row.percentile), epssCheckedAt: now });
      done += 1;
    }
    // CVEs EPSS has never scored still count as checked so we don't hammer the API.
    for (const id of slice) if (!seen.has(id)) upsert({ cveId: id, epssCheckedAt: now });
  }
  return done;
}

async function enrichKev(ids: string[], force: boolean): Promise<number> {
  const kev = await loadKev(force);
  if (!kev) return 0;
  const now = new Date().toISOString();
  let flagged = 0;
  for (const id of ids) {
    const entry = kev.get(id);
    upsert({
      cveId: id,
      kev: !!entry,
      kevDateAdded: entry?.dateAdded ?? null,
      kevKnownRansomware: !!entry?.knownRansomware,
      kevCheckedAt: now,
    });
    if (entry) flagged += 1;
  }
  return flagged;
}

function extractCvss(cve: any): { score: number | null; vector: string | null; severity: string | null } {
  const m = cve?.metrics ?? {};
  const pick = (arr: any[] | undefined) =>
    Array.isArray(arr) && arr.length ? (arr.find((x) => x?.type === "Primary") ?? arr[0]) : null;
  const v40 = pick(m.cvssMetricV40);
  const v31 = pick(m.cvssMetricV31);
  const v30 = pick(m.cvssMetricV30);
  const v2 = pick(m.cvssMetricV2);
  const chosen = v40 ?? v31 ?? v30 ?? v2;
  if (!chosen?.cvssData) return { score: null, vector: null, severity: null };
  const d = chosen.cvssData;
  return {
    score: typeof d.baseScore === "number" ? d.baseScore : null,
    vector: typeof d.vectorString === "string" ? d.vectorString : null,
    severity: String(d.baseSeverity ?? chosen.baseSeverity ?? "").toUpperCase() || null,
  };
}

async function enrichNvd(ids: string[]): Promise<number> {
  let done = 0;
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i];
    if (i > 0) await new Promise((r) => setTimeout(r, NVD_SPACING_MS));
    const res = await fetchFeedPinned(`${NVD_URL}?cveId=${encodeURIComponent(id)}`, {
      maxBytes: 4_000_000,
      timeoutMs: 20_000,
    });
    const now = new Date().toISOString();
    if (!res) continue;
    if (res.status === 404) {
      upsert({ cveId: id, nvdCheckedAt: now });
      continue;
    }
    if (res.status !== 200) continue; // rate-limited or upstream trouble: retry next tick
    try {
      const j = JSON.parse(res.body.toString("utf8"));
      const cve = j?.vulnerabilities?.[0]?.cve;
      if (!cve) {
        upsert({ cveId: id, nvdCheckedAt: now });
        continue;
      }
      const cvss = extractCvss(cve);
      const desc = (cve.descriptions ?? []).find((d: any) => d?.lang === "en")?.value ?? null;
      upsert({
        cveId: id,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        cvssSeverity: cvss.severity,
        publishedAt: cve.published ?? null,
        description: desc ? String(desc).slice(0, 2000) : null,
        nvdCheckedAt: now,
      });
      done += 1;
    } catch {
      /* malformed — retry next tick */
    }
  }
  return done;
}

// ---------- orchestration ----------
export interface EnrichmentRunSummary {
  requested: number;
  epss: number;
  kevFlagged: number;
  nvd: number;
  skipped: number;
}

/**
 * Enrich a set of CVEs. Unless `force`, upstreams checked within the last 24 h
 * are skipped. NVD calls are capped per run to respect its public rate limit;
 * remaining CVEs are picked up by later ticks.
 */
export async function enrichCves(
  cveIds: string[],
  opts?: { force?: boolean; nvdLimit?: number },
): Promise<EnrichmentRunSummary> {
  const ids = Array.from(new Set(cveIds.map(normaliseCveId).filter((v): v is string => !!v)));
  if (ids.length === 0) return { requested: 0, epss: 0, kevFlagged: 0, nvd: 0, skipped: 0 };
  const existing = getCveEnrichment(ids);
  const cutoff = Date.now() - RECHECK_MS;
  const stale = (ts: string | null | undefined) => !ts || Date.parse(ts) < cutoff;
  const force = !!opts?.force;

  const needEpss = ids.filter((id) => force || stale(existing.get(id)?.epssCheckedAt));
  const needKev = ids.filter((id) => force || stale(existing.get(id)?.kevCheckedAt));
  const needNvd = ids
    .filter((id) => force || stale(existing.get(id)?.nvdCheckedAt))
    .slice(0, Math.max(0, opts?.nvdLimit ?? NVD_PER_TICK));

  const [epss, kevFlagged, nvd] = await Promise.all([
    needEpss.length ? enrichEpss(needEpss) : Promise.resolve(0),
    needKev.length ? enrichKev(needKev, force) : Promise.resolve(0),
    needNvd.length ? enrichNvd(needNvd) : Promise.resolve(0),
  ]);
  return {
    requested: ids.length,
    epss,
    kevFlagged,
    nvd,
    skipped: ids.length - Math.max(needEpss.length, needKev.length, needNvd.length),
  };
}

/** CVEs referenced by recent findings that still lack any enrichment. */
export function listCvesNeedingEnrichment(tenantId: string, opts?: { sinceDays?: number; limit?: number }): string[] {
  const since = new Date(Date.now() - (opts?.sinceDays ?? 90) * 86400_000).toISOString();
  const rows = sqlite
    .prepare(
      `
    SELECT cve_ids FROM osint_findings
    WHERE tenant_id = ? AND cve_ids IS NOT NULL AND cve_ids != '[]' AND COALESCE(published_at, created_at) >= ?
    ORDER BY COALESCE(published_at, created_at) DESC
    LIMIT 3000
  `,
    )
    .all(tenantId, since) as Array<{ cve_ids: string }>;
  const seen = new Set<string>();
  for (const r of rows) {
    try {
      for (const raw of JSON.parse(r.cve_ids || "[]")) {
        const id = normaliseCveId(String(raw));
        if (id) seen.add(id);
      }
    } catch {
      /* ignore */
    }
  }
  const ids = Array.from(seen);
  if (ids.length === 0) return [];
  const known = getCveEnrichment(ids);
  const cutoff = Date.now() - RECHECK_MS;
  const pending = ids.filter((id) => {
    const e = known.get(id);
    return !e || !e.epssCheckedAt || !e.kevCheckedAt || !e.nvdCheckedAt || Date.parse(e.updatedAt) < cutoff;
  });
  return pending.slice(0, opts?.limit ?? 200);
}

/** Background tick: enrich a bounded slice of pending CVEs for a tenant. */
export async function enrichPendingCves(tenantId: string): Promise<EnrichmentRunSummary> {
  const pending = listCvesNeedingEnrichment(tenantId, { limit: 150 });
  if (pending.length === 0) return { requested: 0, epss: 0, kevFlagged: 0, nvd: 0, skipped: 0 };
  return enrichCves(pending);
}
