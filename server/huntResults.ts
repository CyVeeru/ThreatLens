/**
 * Hunt result capture — closes the loop from "hunt query generated" to
 * "what did we find in our environment". One row per (hunt query, language,
 * run); the newest result per language is what the UI shows as the state.
 */
import { randomUUID } from "node:crypto";
import { sqlite, storage } from "./storage";
import type { HuntResultDTO, HuntOutcome } from "@shared/schema";

function rowToDto(r: any): HuntResultDTO {
  return {
    id: r.id,
    huntQueryId: r.hunt_query_id,
    language: r.language,
    outcome: r.outcome as HuntOutcome,
    hitCount: r.hit_count ?? null,
    evidence: r.evidence ?? null,
    notes: r.notes ?? null,
    recordedBy: r.recorded_by,
    recordedAt: r.recorded_at,
  };
}

function assertHuntQuery(tenantId: string, huntQueryId: string): void {
  const row = sqlite.prepare("SELECT 1 FROM hunt_queries WHERE tenant_id = ? AND id = ?").get(tenantId, huntQueryId);
  if (!row) {
    const err = new Error("hunt query not found");
    (err as any).status = 404;
    throw err;
  }
}

export function listHuntResults(tenantId: string, huntQueryId: string): HuntResultDTO[] {
  const rows = sqlite
    .prepare("SELECT * FROM hunt_results WHERE tenant_id = ? AND hunt_query_id = ? ORDER BY recorded_at DESC")
    .all(tenantId, huntQueryId) as any[];
  return rows.map(rowToDto);
}

/** Latest result per hunt query id (for list badges). */
export function latestHuntResultsByQuery(tenantId: string, huntQueryIds: string[]): Map<string, HuntResultDTO[]> {
  const out = new Map<string, HuntResultDTO[]>();
  if (huntQueryIds.length === 0) return out;
  const rows = sqlite
    .prepare(
      `SELECT * FROM hunt_results WHERE tenant_id = ? AND hunt_query_id IN (${huntQueryIds.map(() => "?").join(",")}) ORDER BY recorded_at DESC`,
    )
    .all(tenantId, ...huntQueryIds) as any[];
  for (const r of rows) {
    const list = out.get(r.hunt_query_id) ?? [];
    if (!list.some((x) => x.language === r.language)) list.push(rowToDto(r));
    out.set(r.hunt_query_id, list);
  }
  return out;
}

export function addHuntResult(
  tenantId: string,
  huntQueryId: string,
  input: {
    language: string;
    outcome: HuntOutcome;
    hitCount?: number | null;
    evidence?: string | null;
    notes?: string | null;
  },
  recordedBy: string,
): HuntResultDTO {
  assertHuntQuery(tenantId, huntQueryId);
  const id = randomUUID();
  const at = new Date().toISOString();
  sqlite
    .prepare(
      `
    INSERT INTO hunt_results (id, tenant_id, hunt_query_id, language, outcome, hit_count, evidence, notes, recorded_by, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `,
    )
    .run(
      id,
      tenantId,
      huntQueryId,
      input.language,
      input.outcome,
      input.hitCount ?? null,
      input.evidence ?? null,
      input.notes ?? null,
      recordedBy,
      at,
    );
  storage.appendAudit(tenantId, recordedBy, "hunt.result.record", huntQueryId, {
    resultId: id,
    language: input.language,
    outcome: input.outcome,
    hitCount: input.hitCount ?? null,
  });
  return rowToDto(sqlite.prepare("SELECT * FROM hunt_results WHERE id = ?").get(id));
}

export function deleteHuntResult(tenantId: string, huntQueryId: string, resultId: string, actor: string): boolean {
  const res = sqlite
    .prepare("DELETE FROM hunt_results WHERE tenant_id = ? AND hunt_query_id = ? AND id = ?")
    .run(tenantId, huntQueryId, resultId);
  if (res.changes > 0) storage.appendAudit(tenantId, actor, "hunt.result.delete", huntQueryId, { resultId });
  return res.changes > 0;
}

/** Hunt queries whose source findings include the given finding ids. */
export function huntQueriesForFindings(
  tenantId: string,
  findingIds: string[],
): Array<{ id: string; title: string; languages: string[]; results: HuntResultDTO[] }> {
  if (findingIds.length === 0) return [];
  const rows = sqlite
    .prepare(
      "SELECT id, title, source_finding_ids, queries FROM hunt_queries WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 500",
    )
    .all(tenantId) as any[];
  const wanted = new Set(findingIds);
  const matched = rows.filter((r) => {
    try {
      return (JSON.parse(r.source_finding_ids || "[]") as string[]).some((id) => wanted.has(id));
    } catch {
      return false;
    }
  });
  const results = latestHuntResultsByQuery(
    tenantId,
    matched.map((r) => r.id),
  );
  return matched.map((r) => ({
    id: r.id,
    title: r.title,
    languages: Object.keys(
      (() => {
        try {
          return JSON.parse(r.queries || "{}");
        } catch {
          return {};
        }
      })(),
    ),
    results: results.get(r.id) ?? [],
  }));
}
