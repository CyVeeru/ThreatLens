/**
 * Organization profile — the technology the org actually runs (vendors,
 * products, cloud services, keywords) and the engine that scores every finding
 * against it. This is what turns a generic threat feed into "what affects us".
 *
 * Matching is deliberately explainable: each hit records which asset matched,
 * where (affected-tech list, title, body) and why the finding was prioritised.
 */
import { randomUUID } from "node:crypto";
import { sqlite, storage } from "./storage";
import { attachCveSummaries } from "./cveEnrichment";
import { compileAssets, matchFinding } from "./orgMatcher";
import type { OrgAssetDTO, OrgExposureDTO, OrgPriority, OrgRelevance, OsintFindingDTO } from "@shared/schema";
import type { z } from "zod";
import type { orgAssetCreateSchema, orgAssetPatchSchema } from "@shared/schema";

type AssetCreate = z.infer<typeof orgAssetCreateSchema>;
type AssetPatch = z.infer<typeof orgAssetPatchSchema>;

const now = () => new Date().toISOString();

function rowToAsset(r: any): OrgAssetDTO {
  let aliases: string[] = [];
  try {
    const parsed = JSON.parse(r.aliases || "[]");
    if (Array.isArray(parsed)) aliases = parsed.filter((a) => typeof a === "string");
  } catch {
    /* corrupt alias list — treat as none */
  }
  return {
    id: r.id,
    tenantId: r.tenant_id,
    name: r.name,
    kind: r.kind,
    criticality: r.criticality,
    aliases,
    notes: r.notes ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    createdBy: r.created_by,
  };
}

export function listAssets(tenantId: string): OrgAssetDTO[] {
  return (
    sqlite.prepare("SELECT * FROM org_assets WHERE tenant_id = ? ORDER BY name COLLATE NOCASE").all(tenantId) as any[]
  ).map(rowToAsset);
}

export function getAsset(tenantId: string, id: string): OrgAssetDTO | null {
  const r = sqlite.prepare("SELECT * FROM org_assets WHERE tenant_id = ? AND id = ?").get(tenantId, id);
  return r ? rowToAsset(r) : null;
}

function dedupeAliases(name: string, aliases: string[]): string[] {
  const seen = new Set<string>([name.toLowerCase()]);
  const out: string[] = [];
  for (const a of aliases) {
    const k = a.trim().toLowerCase();
    if (k.length >= 2 && !seen.has(k)) {
      seen.add(k);
      out.push(a.trim());
    }
  }
  return out;
}

export class OrgAssetConflictError extends Error {
  status = 409;
}

export function createAsset(tenantId: string, input: AssetCreate, actor: string): OrgAssetDTO {
  const existing = sqlite
    .prepare("SELECT id FROM org_assets WHERE tenant_id = ? AND name = ? COLLATE NOCASE")
    .get(tenantId, input.name);
  if (existing) throw new OrgAssetConflictError(`"${input.name}" is already in the organization profile`);
  const id = randomUUID();
  const ts = now();
  sqlite
    .prepare(
      `INSERT INTO org_assets (id, tenant_id, name, kind, criticality, aliases, notes, created_at, updated_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      tenantId,
      input.name,
      input.kind,
      input.criticality,
      JSON.stringify(dedupeAliases(input.name, input.aliases ?? [])),
      input.notes ?? null,
      ts,
      ts,
      actor,
    );
  return getAsset(tenantId, id)!;
}

/** Bulk add that skips names already present instead of failing the whole batch. */
export function createAssets(
  tenantId: string,
  inputs: AssetCreate[],
  actor: string,
): { created: OrgAssetDTO[]; skipped: string[] } {
  const created: OrgAssetDTO[] = [];
  const skipped: string[] = [];
  const tx = sqlite.transaction(() => {
    for (const input of inputs) {
      try {
        created.push(createAsset(tenantId, input, actor));
      } catch (e) {
        if (e instanceof OrgAssetConflictError) skipped.push(input.name);
        else throw e;
      }
    }
  });
  tx();
  return { created, skipped };
}

export function updateAsset(tenantId: string, id: string, patch: AssetPatch): OrgAssetDTO | null {
  const cur = getAsset(tenantId, id);
  if (!cur) return null;
  const name = patch.name ?? cur.name;
  if (name.toLowerCase() !== cur.name.toLowerCase()) {
    const clash = sqlite
      .prepare("SELECT id FROM org_assets WHERE tenant_id = ? AND name = ? COLLATE NOCASE AND id <> ?")
      .get(tenantId, name, id);
    if (clash) throw new OrgAssetConflictError(`"${name}" is already in the organization profile`);
  }
  sqlite
    .prepare(
      `UPDATE org_assets SET name = ?, kind = ?, criticality = ?, aliases = ?, notes = ?, updated_at = ?
       WHERE tenant_id = ? AND id = ?`,
    )
    .run(
      name,
      patch.kind ?? cur.kind,
      patch.criticality ?? cur.criticality,
      JSON.stringify(dedupeAliases(name, patch.aliases ?? cur.aliases)),
      patch.notes === undefined ? cur.notes : patch.notes || null,
      now(),
      tenantId,
      id,
    );
  return getAsset(tenantId, id);
}

export function deleteAsset(tenantId: string, id: string): boolean {
  return sqlite.prepare("DELETE FROM org_assets WHERE tenant_id = ? AND id = ?").run(tenantId, id).changes > 0;
}

/** Attach `orgRelevance` to findings in place. No-op (fields stay unset) when the org has no profile. */
export function attachOrgRelevance<T extends OsintFindingDTO>(tenantId: string, findings: T[]): T[] {
  const assets = listAssets(tenantId);
  if (assets.length === 0) return findings;
  const terms = compileAssets(assets);
  // Priority depends on CVE enrichment; make sure it is attached first.
  const needsEnrichment = findings.some((f) => f.cveEnrichment === undefined);
  if (needsEnrichment) attachCveSummaries(findings as any);
  for (const f of findings) f.orgRelevance = matchFinding(f, terms);
  return findings;
}

const PRIORITY_RANK: Record<OrgPriority, number> = { urgent: 3, high: 2, watch: 1 };

export function exposureSummary(tenantId: string, topN = 12): OrgExposureDTO {
  const assets = listAssets(tenantId);
  const all = storage.listOsintFindings(tenantId).filter((f) => f.status !== "false_positive");
  const empty: OrgExposureDTO = {
    totals: { urgent: 0, high: 0, watch: 0, matchedFindings: 0, totalFindings: all.length },
    byAsset: [],
    top: [],
  };
  if (assets.length === 0) return empty;
  attachCveSummaries(all);
  const terms = compileAssets(assets);
  const perAsset = new Map<string, { count: number; urgent: number }>();
  const matched: Array<OsintFindingDTO & { orgRelevance: OrgRelevance }> = [];
  for (const f of all) {
    const rel = matchFinding(f, terms);
    if (!rel) continue;
    f.orgRelevance = rel;
    matched.push(f as any);
    empty.totals[rel.priority] += 1;
    for (const m of rel.matches) {
      const cur = perAsset.get(m.assetId) ?? { count: 0, urgent: 0 };
      cur.count += 1;
      if (rel.priority === "urgent") cur.urgent += 1;
      perAsset.set(m.assetId, cur);
    }
  }
  empty.totals.matchedFindings = matched.length;
  empty.byAsset = assets
    .map((a) => ({
      assetId: a.id,
      name: a.name,
      criticality: a.criticality,
      count: perAsset.get(a.id)?.count ?? 0,
      urgent: perAsset.get(a.id)?.urgent ?? 0,
    }))
    .sort((a, b) => b.urgent - a.urgent || b.count - a.count || a.name.localeCompare(b.name));
  matched.sort(
    (a, b) =>
      PRIORITY_RANK[b.orgRelevance.priority] - PRIORITY_RANK[a.orgRelevance.priority] ||
      b.orgRelevance.score - a.orgRelevance.score ||
      (b.cveEnrichment?.priority ?? 0) - (a.cveEnrichment?.priority ?? 0) ||
      String(b.publishedAt).localeCompare(String(a.publishedAt)),
  );
  empty.top = matched.slice(0, topN).map((f) => ({
    id: f.id,
    title: f.title,
    url: f.url,
    sourceName: f.sourceName,
    severity: f.severity,
    publishedAt: f.publishedAt,
    cveIds: f.cveIds,
    orgRelevance: f.orgRelevance,
    cveEnrichment: f.cveEnrichment ?? null,
  }));
  return empty;
}
