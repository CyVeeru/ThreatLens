/**
 * Cases — group findings, actors, hunt queries and CVEs into one working
 * object with status, assignee, notes and a derived timeline. Backed by the
 * investigations / investigation_links / investigation_notes tables.
 */
import { randomUUID } from "node:crypto";
import { sqlite, storage } from "./storage";
import { latestHuntResultsByQuery } from "./huntResults";
import { normaliseCveId } from "./cveEnrichment";
import { normaliseTechniqueId } from "./attackNavigator";
import type {
  CaseFullDTO,
  CaseLinkResolvedDTO,
  CaseLinkType,
  FindingIoCs,
  HuntResultDTO,
  InvestigationDTO,
  InvestigationNoteDTO,
  InvestigationSeverity,
  InvestigationStatus,
} from "@shared/schema";

const now = () => new Date().toISOString();

function notFound(what: string): never {
  const err = new Error(`${what} not found`);
  (err as any).status = 404;
  throw err;
}

function rowToCase(r: any): InvestigationDTO {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    title: r.title,
    status: r.status as InvestigationStatus,
    severity: r.severity as InvestigationSeverity,
    summary: r.summary ?? null,
    assignee: r.assignee ?? null,
    sourceType: r.source_type ?? null,
    sourceId: r.source_id ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    createdBy: r.created_by,
    linkCount: typeof r.link_count === "number" ? r.link_count : undefined,
    noteCount: typeof r.note_count === "number" ? r.note_count : undefined,
  };
}

function rowToNote(r: any): InvestigationNoteDTO {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    investigationId: r.investigation_id,
    kind: r.kind,
    body: r.body,
    createdAt: r.created_at,
    createdBy: r.created_by,
  };
}

export function listCases(
  tenantId: string,
  filter?: { status?: string; assignee?: string; q?: string },
): InvestigationDTO[] {
  const where = ["i.tenant_id = ?"];
  const args: any[] = [tenantId];
  if (filter?.status) {
    where.push("i.status = ?");
    args.push(filter.status);
  }
  if (filter?.assignee) {
    where.push("i.assignee = ?");
    args.push(filter.assignee);
  }
  if (filter?.q) {
    where.push("(LOWER(i.title) LIKE ? OR LOWER(COALESCE(i.summary,'')) LIKE ?)");
    const n = `%${filter.q.toLowerCase()}%`;
    args.push(n, n);
  }
  const rows = sqlite
    .prepare(
      `
    SELECT i.*,
      (SELECT COUNT(*) FROM investigation_links l WHERE l.investigation_id = i.id) AS link_count,
      (SELECT COUNT(*) FROM investigation_notes n WHERE n.investigation_id = i.id) AS note_count
    FROM investigations i
    WHERE ${where.join(" AND ")}
    ORDER BY CASE i.status WHEN 'closed' THEN 1 ELSE 0 END, i.updated_at DESC
    LIMIT 500
  `,
    )
    .all(...args) as any[];
  return rows.map(rowToCase);
}

export function createCase(
  tenantId: string,
  input: {
    title: string;
    severity?: InvestigationSeverity;
    summary?: string | null;
    assignee?: string | null;
    sourceType?: string | null;
    sourceId?: string | null;
  },
  actor: string,
): InvestigationDTO {
  const id = randomUUID();
  const ts = now();
  sqlite
    .prepare(
      `
    INSERT INTO investigations (id, tenant_id, title, status, severity, summary, assignee, source_type, source_id, created_at, updated_at, created_by)
    VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
  `,
    )
    .run(
      id,
      tenantId,
      input.title.trim(),
      input.severity ?? "medium",
      input.summary ?? null,
      input.assignee ?? null,
      input.sourceType ?? null,
      input.sourceId ?? null,
      ts,
      ts,
      actor,
    );
  storage.appendAudit(tenantId, actor, "case.create", id, { title: input.title, severity: input.severity ?? "medium" });
  return getCase(tenantId, id)!;
}

export function getCase(tenantId: string, id: string): InvestigationDTO | undefined {
  const r = sqlite
    .prepare(
      `
    SELECT i.*,
      (SELECT COUNT(*) FROM investigation_links l WHERE l.investigation_id = i.id) AS link_count,
      (SELECT COUNT(*) FROM investigation_notes n WHERE n.investigation_id = i.id) AS note_count
    FROM investigations i WHERE i.tenant_id = ? AND i.id = ?
  `,
    )
    .get(tenantId, id) as any;
  return r ? rowToCase(r) : undefined;
}

export function updateCase(
  tenantId: string,
  id: string,
  patch: {
    title?: string;
    status?: InvestigationStatus;
    severity?: InvestigationSeverity;
    summary?: string | null;
    assignee?: string | null;
  },
  actor: string,
): InvestigationDTO | undefined {
  const existing = getCase(tenantId, id);
  if (!existing) return undefined;
  const sets: string[] = [];
  const args: any[] = [];
  if (patch.title !== undefined) {
    sets.push("title = ?");
    args.push(patch.title.trim());
  }
  if (patch.status !== undefined) {
    sets.push("status = ?");
    args.push(patch.status);
  }
  if (patch.severity !== undefined) {
    sets.push("severity = ?");
    args.push(patch.severity);
  }
  if (patch.summary !== undefined) {
    sets.push("summary = ?");
    args.push(patch.summary);
  }
  if (patch.assignee !== undefined) {
    sets.push("assignee = ?");
    args.push(patch.assignee ? patch.assignee.trim() : null);
  }
  if (sets.length === 0) return existing;
  sets.push("updated_at = ?");
  args.push(now());
  args.push(tenantId, id);
  sqlite.prepare(`UPDATE investigations SET ${sets.join(", ")} WHERE tenant_id = ? AND id = ?`).run(...args);
  if (patch.status && patch.status !== existing.status) {
    addNote(tenantId, id, { kind: "system", body: `Status changed ${existing.status} → ${patch.status}` }, actor);
  }
  storage.appendAudit(tenantId, actor, "case.update", id, { fields: Object.keys(patch) });
  return getCase(tenantId, id);
}

export function deleteCase(tenantId: string, id: string, actor: string): boolean {
  const existing = getCase(tenantId, id);
  if (!existing) return false;
  sqlite.transaction(() => {
    sqlite.prepare("DELETE FROM investigation_links WHERE tenant_id = ? AND investigation_id = ?").run(tenantId, id);
    sqlite.prepare("DELETE FROM investigation_notes WHERE tenant_id = ? AND investigation_id = ?").run(tenantId, id);
    sqlite.prepare("DELETE FROM investigations WHERE tenant_id = ? AND id = ?").run(tenantId, id);
  })();
  storage.appendAudit(tenantId, actor, "case.delete", id, { title: existing.title });
  return true;
}

// ---------- links ----------
function resolveEntity(
  tenantId: string,
  entityType: CaseLinkType,
  entityId: string,
): { title: string; subtitle: string | null; href: string | null; severity?: string | null } | null {
  switch (entityType) {
    case "osint_finding": {
      const f = sqlite
        .prepare(
          "SELECT id, title, severity, source_id, published_at FROM osint_findings WHERE tenant_id = ? AND id = ?",
        )
        .get(tenantId, entityId) as any;
      if (!f) return null;
      const src = sqlite.prepare("SELECT name FROM osint_sources WHERE id = ?").get(f.source_id) as any;
      return {
        title: f.title,
        subtitle: `${src?.name ?? f.source_id} · ${String(f.published_at || "").slice(0, 10)}`,
        href: `#/osint?finding=${encodeURIComponent(f.id)}`,
        severity: f.severity,
      };
    }
    case "threat_actor": {
      const a = sqlite
        .prepare("SELECT id, profile_id, primary_name, threat_level FROM threat_actors WHERE tenant_id = ? AND id = ?")
        .get(tenantId, entityId) as any;
      if (!a) return null;
      return {
        title: a.primary_name,
        subtitle: `${a.profile_id} · ${a.threat_level}`,
        href: `#/threat-actors?focus=${encodeURIComponent(a.id)}`,
        severity: a.threat_level,
      };
    }
    case "hunt_query": {
      const h = sqlite
        .prepare("SELECT id, title, created_at FROM hunt_queries WHERE tenant_id = ? AND id = ?")
        .get(tenantId, entityId) as any;
      if (!h) return null;
      return {
        title: h.title,
        subtitle: `Hunt query · ${String(h.created_at).slice(0, 10)}`,
        href: `#/osint?tab=hunt-queries&hunt=${encodeURIComponent(h.id)}`,
      };
    }
    case "cve": {
      const id = normaliseCveId(entityId);
      if (!id) return null;
      const e = sqlite
        .prepare("SELECT cvss_score, epss_score, kev FROM cve_enrichment WHERE cve_id = ?")
        .get(id) as any;
      const bits = [
        e?.kev ? "KEV" : null,
        e?.cvss_score != null ? `CVSS ${e.cvss_score}` : null,
        e?.epss_score != null ? `EPSS ${(e.epss_score * 100).toFixed(0)}%` : null,
      ].filter(Boolean);
      return {
        title: id,
        subtitle: bits.length ? bits.join(" · ") : "not yet enriched",
        href: `https://nvd.nist.gov/vuln/detail/${id}`,
      };
    }
  }
}

export function addLink(
  tenantId: string,
  caseId: string,
  input: { entityType: CaseLinkType; entityId: string; label?: string | null },
  actor: string,
): CaseLinkResolvedDTO {
  if (!getCase(tenantId, caseId)) notFound("case");
  const entityId = input.entityType === "cve" ? (normaliseCveId(input.entityId) ?? input.entityId) : input.entityId;
  const resolved = resolveEntity(tenantId, input.entityType, entityId);
  if (!resolved) notFound(`${input.entityType} ${entityId}`);
  const id = randomUUID();
  const ts = now();
  sqlite
    .prepare(
      `
    INSERT INTO investigation_links (id, tenant_id, investigation_id, entity_type, entity_id, label, created_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(investigation_id, entity_type, entity_id) DO UPDATE SET label = COALESCE(excluded.label, investigation_links.label)
  `,
    )
    .run(id, tenantId, caseId, input.entityType, entityId, input.label ?? null, ts, actor);
  sqlite.prepare("UPDATE investigations SET updated_at = ? WHERE id = ?").run(ts, caseId);
  storage.appendAudit(tenantId, actor, "case.link.add", caseId, { entityType: input.entityType, entityId });
  const row = sqlite
    .prepare("SELECT * FROM investigation_links WHERE investigation_id = ? AND entity_type = ? AND entity_id = ?")
    .get(caseId, input.entityType, entityId) as any;
  return { ...rowToLink(row), ...resolved! };
}

export function removeLink(tenantId: string, caseId: string, linkId: string, actor: string): boolean {
  const res = sqlite
    .prepare("DELETE FROM investigation_links WHERE tenant_id = ? AND investigation_id = ? AND id = ?")
    .run(tenantId, caseId, linkId);
  if (res.changes > 0) {
    sqlite.prepare("UPDATE investigations SET updated_at = ? WHERE id = ?").run(now(), caseId);
    storage.appendAudit(tenantId, actor, "case.link.remove", caseId, { linkId });
  }
  return res.changes > 0;
}

function rowToLink(r: any): Omit<CaseLinkResolvedDTO, "title" | "subtitle" | "href" | "severity"> {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    investigationId: r.investigation_id,
    entityType: r.entity_type as CaseLinkType,
    entityId: r.entity_id,
    label: r.label ?? null,
    createdAt: r.created_at,
    createdBy: r.created_by,
  };
}

// ---------- notes ----------
export function addNote(
  tenantId: string,
  caseId: string,
  input: { kind?: "analyst" | "ai" | "system"; body: string },
  actor: string,
): InvestigationNoteDTO {
  if (!getCase(tenantId, caseId)) notFound("case");
  const id = randomUUID();
  const ts = now();
  sqlite
    .prepare(
      `
    INSERT INTO investigation_notes (id, tenant_id, investigation_id, kind, body, created_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `,
    )
    .run(id, tenantId, caseId, input.kind ?? "analyst", input.body, ts, actor);
  sqlite.prepare("UPDATE investigations SET updated_at = ? WHERE id = ?").run(ts, caseId);
  return rowToNote(sqlite.prepare("SELECT * FROM investigation_notes WHERE id = ?").get(id));
}

export function deleteNote(tenantId: string, caseId: string, noteId: string): boolean {
  return (
    sqlite
      .prepare("DELETE FROM investigation_notes WHERE tenant_id = ? AND investigation_id = ? AND id = ?")
      .run(tenantId, caseId, noteId).changes > 0
  );
}

// ---------- full view ----------
export function getCaseFull(tenantId: string, id: string): CaseFullDTO | undefined {
  const head = getCase(tenantId, id);
  if (!head) return undefined;
  const linkRows = sqlite
    .prepare("SELECT * FROM investigation_links WHERE tenant_id = ? AND investigation_id = ? ORDER BY created_at")
    .all(tenantId, id) as any[];
  const links: CaseLinkResolvedDTO[] = linkRows.map((r) => {
    const resolved = resolveEntity(tenantId, r.entity_type, r.entity_id) ?? {
      title: `${r.entity_type} ${r.entity_id} (missing)`,
      subtitle: null,
      href: null,
    };
    return { ...rowToLink(r), ...resolved };
  });
  const notes = (
    sqlite
      .prepare("SELECT * FROM investigation_notes WHERE tenant_id = ? AND investigation_id = ? ORDER BY created_at")
      .all(tenantId, id) as any[]
  ).map(rowToNote);

  const findingIds = links.filter((l) => l.entityType === "osint_finding").map((l) => l.entityId);
  const iocs: FindingIoCs = {};
  const cveIds = new Set<string>(links.filter((l) => l.entityType === "cve").map((l) => l.entityId));
  const techniques = new Set<string>();
  const actorNames = new Set<string>();
  const timeline: CaseFullDTO["timeline"] = [
    { id: `created-${id}`, type: "case", title: "Case opened", at: head.createdAt, detail: `by ${head.createdBy}` },
  ];
  if (findingIds.length) {
    const rows = sqlite
      .prepare(
        `SELECT id, title, published_at, iocs, cve_ids, attack_techniques, threat_actors FROM osint_findings WHERE tenant_id = ? AND id IN (${findingIds.map(() => "?").join(",")})`,
      )
      .all(tenantId, ...findingIds) as any[];
    for (const f of rows) {
      try {
        const bag = JSON.parse(f.iocs || "{}");
        for (const [k, arr] of Object.entries(bag)) {
          if (!Array.isArray(arr)) continue;
          const key = k as keyof FindingIoCs;
          const cur = new Set((iocs[key] as string[] | undefined) ?? []);
          for (const v of arr as string[]) cur.add(v);
          (iocs as any)[key] = Array.from(cur).slice(0, 200);
        }
      } catch {
        /* ignore */
      }
      try {
        for (const c of JSON.parse(f.cve_ids || "[]")) {
          const n = normaliseCveId(String(c));
          if (n) cveIds.add(n);
        }
      } catch {
        /* ignore */
      }
      try {
        for (const t of JSON.parse(f.attack_techniques || "[]")) {
          const n = normaliseTechniqueId(typeof t === "string" ? t : t?.id);
          if (n) techniques.add(n);
        }
      } catch {
        /* ignore */
      }
      try {
        for (const a of JSON.parse(f.threat_actors || "[]"))
          if (typeof a === "string" && a.trim()) actorNames.add(a.trim().toLowerCase());
      } catch {
        /* ignore */
      }
      timeline.push({
        id: `finding-${f.id}`,
        type: "finding",
        title: f.title,
        at: f.published_at,
        detail: "linked finding published",
      });
    }
  }
  for (const l of links) {
    timeline.push({
      id: `link-${l.id}`,
      type: `link:${l.entityType}`,
      title: `Linked ${l.entityType.replace("_", " ")}: ${l.title}`,
      at: l.createdAt,
      detail: `by ${l.createdBy}`,
    });
  }
  for (const n of notes) {
    timeline.push({
      id: `note-${n.id}`,
      type: `note:${n.kind}`,
      title: n.kind === "system" ? n.body : `${n.kind === "ai" ? "AI" : n.createdBy} note`,
      at: n.createdAt,
      detail: n.kind === "system" ? null : n.body.slice(0, 240),
    });
  }
  timeline.sort((a, b) => String(a.at).localeCompare(String(b.at)));

  // Related actors: explicitly linked + those named on linked findings.
  const linkedActorIds = links.filter((l) => l.entityType === "threat_actor").map((l) => l.entityId);
  const actorRows = sqlite
    .prepare("SELECT id, primary_name, profile_id, threat_level, aliases FROM threat_actors WHERE tenant_id = ?")
    .all(tenantId) as any[];
  const relatedActors = actorRows
    .filter((a) => {
      if (linkedActorIds.includes(a.id)) return true;
      if (actorNames.has(String(a.primary_name).toLowerCase())) return true;
      try {
        return (JSON.parse(a.aliases || "[]") as string[]).some((al) => actorNames.has(String(al).toLowerCase()));
      } catch {
        return false;
      }
    })
    .map((a) => ({ id: a.id, name: a.primary_name, profileId: a.profile_id, threatLevel: a.threat_level }));

  // Hunt results for linked hunt queries + hunts derived from linked findings.
  const huntIds = new Set<string>(links.filter((l) => l.entityType === "hunt_query").map((l) => l.entityId));
  if (findingIds.length) {
    const hunts = sqlite
      .prepare("SELECT id, source_finding_ids FROM hunt_queries WHERE tenant_id = ?")
      .all(tenantId) as any[];
    const wanted = new Set(findingIds);
    for (const h of hunts) {
      try {
        if ((JSON.parse(h.source_finding_ids || "[]") as string[]).some((f) => wanted.has(f))) huntIds.add(h.id);
      } catch {
        /* ignore */
      }
    }
  }
  const huntResults: HuntResultDTO[] = Array.from(
    latestHuntResultsByQuery(tenantId, Array.from(huntIds)).values(),
  ).flat();

  return {
    ...head,
    links,
    notes,
    timeline,
    iocs,
    cveIds: Array.from(cveIds).sort(),
    attackTechniques: Array.from(techniques).sort(),
    relatedActors,
    huntResults,
  };
}

/** Cases an entity already belongs to (for "add to case" pickers). */
export function casesForEntity(
  tenantId: string,
  entityType: CaseLinkType,
  entityId: string,
): Array<{ id: string; title: string; status: string }> {
  return sqlite
    .prepare(
      `
    SELECT i.id, i.title, i.status FROM investigation_links l
    JOIN investigations i ON i.id = l.investigation_id
    WHERE l.tenant_id = ? AND l.entity_type = ? AND l.entity_id = ?
    ORDER BY i.updated_at DESC
  `,
    )
    .all(tenantId, entityType, entityId) as Array<{ id: string; title: string; status: string }>;
}
