/**
 * Review queue — ownership, due dates and throughput metrics over
 * osint_findings. Status transitions are recorded by storage.updateOsintFinding;
 * this module owns assignment/SLA fields and the metrics roll-up.
 */
import { sqlite, storage } from "./storage";
import { getCveEnrichment, normaliseCveId } from "./cveEnrichment";
import type { ReviewQueueMetricsDTO } from "@shared/schema";

export function setFindingReview(
  tenantId: string,
  findingId: string,
  patch: { assignee?: string | null; dueAt?: string | null },
  actor: string,
): boolean {
  const sets: string[] = [];
  const params: any[] = [];
  if (patch.assignee !== undefined) {
    sets.push("assignee = ?");
    params.push(patch.assignee ? patch.assignee.trim() : null);
  }
  if (patch.dueAt !== undefined) {
    sets.push("due_at = ?");
    params.push(patch.dueAt ? new Date(patch.dueAt).toISOString() : null);
  }
  if (sets.length === 0) return true;
  params.push(findingId, tenantId);
  const res = sqlite
    .prepare(`UPDATE osint_findings SET ${sets.join(", ")} WHERE id = ? AND tenant_id = ?`)
    .run(...params);
  if (res.changes > 0) {
    storage.appendAudit(tenantId, actor, "osint.finding.review", findingId, {
      ...(patch.assignee !== undefined ? { assignee: patch.assignee } : {}),
      ...(patch.dueAt !== undefined ? { dueAt: patch.dueAt } : {}),
    });
  }
  return res.changes > 0;
}

/** Stamp triaged_at / closed_at when a status transition happens. Called by
 *  storage.updateOsintFinding after the status write. */
export function recordStatusTransition(tenantId: string, findingId: string, prev: string, next: string): void {
  const now = new Date().toISOString();
  if (prev === "new" && next !== "new") {
    sqlite
      .prepare("UPDATE osint_findings SET triaged_at = COALESCE(triaged_at, ?) WHERE id = ? AND tenant_id = ?")
      .run(now, findingId, tenantId);
  }
  if (next === "dismissed" || next === "assessed") {
    sqlite
      .prepare("UPDATE osint_findings SET closed_at = ? WHERE id = ? AND tenant_id = ?")
      .run(now, findingId, tenantId);
  } else if (prev === "dismissed" || prev === "assessed") {
    sqlite
      .prepare("UPDATE osint_findings SET closed_at = NULL WHERE id = ? AND tenant_id = ?")
      .run(findingId, tenantId);
  }
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const s = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

export function reviewQueueMetrics(tenantId: string, windowDays = 30): ReviewQueueMetricsDTO {
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const since = new Date(nowMs - windowDays * 86400_000).toISOString();

  const open = sqlite
    .prepare(
      `
    SELECT id, created_at, assignee, due_at, cve_ids, source_id
    FROM osint_findings
    WHERE tenant_id = ? AND status IN ('new', 'triaged', 'escalated')
  `,
    )
    .all(tenantId) as Array<{
    id: string;
    created_at: string;
    assignee: string | null;
    due_at: string | null;
    cve_ids: string;
    source_id: string;
  }>;

  const byAge = { lt24h: 0, d1to3: 0, d3to7: 0, gt7d: 0 };
  let unassigned = 0;
  let overdue = 0;
  const assigneeAgg = new Map<string, { open: number; overdue: number }>();
  const openCves = new Set<string>();
  for (const f of open) {
    const ageH = (nowMs - Date.parse(f.created_at)) / 3600_000;
    if (ageH < 24) byAge.lt24h += 1;
    else if (ageH < 72) byAge.d1to3 += 1;
    else if (ageH < 168) byAge.d3to7 += 1;
    else byAge.gt7d += 1;
    const isOverdue = !!f.due_at && f.due_at < nowIso;
    if (isOverdue) overdue += 1;
    if (!f.assignee) unassigned += 1;
    else {
      const a = assigneeAgg.get(f.assignee) ?? { open: 0, overdue: 0 };
      a.open += 1;
      if (isOverdue) a.overdue += 1;
      assigneeAgg.set(f.assignee, a);
    }
    try {
      for (const c of JSON.parse(f.cve_ids || "[]")) {
        const id = normaliseCveId(String(c));
        if (id) openCves.add(id);
      }
    } catch {
      /* ignore */
    }
  }

  const triagedRows = sqlite
    .prepare(
      `
    SELECT created_at, triaged_at, status FROM osint_findings
    WHERE tenant_id = ? AND triaged_at IS NOT NULL AND triaged_at >= ?
  `,
    )
    .all(tenantId, since) as Array<{ created_at: string; triaged_at: string; status: string }>;
  const ttt = triagedRows
    .map((r) => (Date.parse(r.triaged_at) - Date.parse(r.created_at)) / 3600_000)
    .filter((h) => Number.isFinite(h) && h >= 0);
  const closedCounts = sqlite
    .prepare(
      `
    SELECT status, COUNT(*) n FROM osint_findings
    WHERE tenant_id = ? AND COALESCE(closed_at, triaged_at) >= ? AND status IN ('dismissed', 'escalated')
    GROUP BY status
  `,
    )
    .all(tenantId, since) as Array<{ status: string; n: number }>;
  const count = (st: string) => closedCounts.find((c) => c.status === st)?.n ?? 0;

  const perSource = sqlite
    .prepare(
      `
    SELECT f.source_id AS sourceId, COALESCE(s.name, f.source_id) AS sourceName,
           COUNT(*) AS total,
           SUM(CASE WHEN f.status = 'dismissed' THEN 1 ELSE 0 END) AS dismissed,
           SUM(CASE WHEN f.status = 'escalated' THEN 1 ELSE 0 END) AS escalated
    FROM osint_findings f LEFT JOIN osint_sources s ON s.id = f.source_id
    WHERE f.tenant_id = ? AND COALESCE(f.published_at, f.created_at) >= ?
    GROUP BY f.source_id
    HAVING total >= 3
    ORDER BY total DESC
    LIMIT 25
  `,
    )
    .all(tenantId, since) as Array<{
    sourceId: string;
    sourceName: string;
    total: number;
    dismissed: number;
    escalated: number;
  }>;

  const enrichment = getCveEnrichment(Array.from(openCves));
  let kevOpen = 0;
  let highEpssOpen = 0;
  for (const f of open) {
    let ids: string[] = [];
    try {
      ids = JSON.parse(f.cve_ids || "[]");
    } catch {
      /* ignore */
    }
    const es = ids.map((c) => enrichment.get(normaliseCveId(String(c)) || "")).filter(Boolean);
    if (es.some((e) => e!.kev)) kevOpen += 1;
    else if (es.some((e) => (e!.epssScore ?? 0) >= 0.5)) highEpssOpen += 1;
  }

  return {
    generatedAt: nowIso,
    windowDays,
    backlog: { total: open.length, unassigned, overdue, byAge },
    throughput: {
      triaged: triagedRows.length,
      dismissed: count("dismissed"),
      escalated: count("escalated"),
      meanTimeToTriageHours: ttt.length ? Math.round((ttt.reduce((a, b) => a + b, 0) / ttt.length) * 10) / 10 : null,
      medianTimeToTriageHours: (() => {
        const m = median(ttt);
        return m == null ? null : Math.round(m * 10) / 10;
      })(),
    },
    bySource: perSource.map((r) => ({
      sourceId: r.sourceId,
      sourceName: r.sourceName,
      total: r.total,
      dismissed: r.dismissed,
      escalated: r.escalated,
      dismissalRate: r.total ? Math.round((r.dismissed / r.total) * 100) / 100 : 0,
    })),
    byAssignee: Array.from(assigneeAgg.entries())
      .map(([assignee, a]) => ({ assignee, ...a }))
      .sort((a, b) => b.open - a.open),
    exploited: { kevOpen, highEpssOpen },
  };
}
