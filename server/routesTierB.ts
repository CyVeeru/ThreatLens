/**
 * Tier B routes: cases, hunt results, CVE enrichment, review queue, document
 * ingest, ATT&CK Navigator export, report builder. Mounted from routes.ts
 * after the core BatchOne routes; every path is listed in shared/accessPolicy.
 */
import type { Express, Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { fromZodError } from "zod-validation-error";
import {
  caseLinkSchema,
  cveEnrichRequestSchema,
  documentIngestSchema,
  findingReviewPatchSchema,
  huntResultCreateSchema,
  investigationCreateSchema,
  investigationNoteSchema,
  investigationPatchSchema,
  orgAssetBulkSchema,
  orgAssetCreateSchema,
  orgAssetPatchSchema,
  reportBriefRequestSchema,
  type CaseLinkType,
} from "@shared/schema";
import { storage } from "./storage";
import * as cases from "./cases";
import * as hunts from "./huntResults";
import * as org from "./orgProfile";
import { buildIocExport, IOC_PLATFORMS, type IocPlatformId } from "./iocExport";
import { sqlite } from "./storage";
import { attachCveSummaries, enrichCves, getCveEnrichment, listCvesNeedingEnrichment } from "./cveEnrichment";
import { reviewQueueMetrics, setFindingReview } from "./reviewQueue";
import { ingestDocument, listDocuments } from "./documents";
import { buildActorNavigatorLayer, buildCoverageNavigatorLayer, TACTIC_ORDER } from "./attackNavigator";
import { buildStixBundle, buildStixPreview } from "./stixPreview";
import { auditReport, buildReportModel, renderDocx, renderMarkdown, reportFilename } from "./reportBuilder";

type Authed = import("express").Request & {
  user?: { id: string; email: string; role: string };
  effectiveTenantId?: string;
  accessMode?: string;
};
type Middleware = (req: Authed, res: Response, next: NextFunction) => unknown;

function bad(res: Response, err: unknown) {
  return res.status(400).json({ detail: fromZodError(err as any).message });
}
function actorOf(req: Authed): string {
  return req.user?.email || "analyst";
}
function isAdmin(req: Authed): boolean {
  return req.user?.role === "admin";
}

export function registerTierBRoutes(app: Express, requireAuth: Middleware): void {
  const uploadLimiter = rateLimit({
    windowMs: 60_000,
    limit: 12,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { detail: "too many uploads" },
  });
  const reportLimiter = rateLimit({
    windowMs: 60_000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { detail: "too many report requests" },
  });

  // ---------------- Organization profile ----------------
  app.get("/api/v1/org/assets", requireAuth, (req: Authed, res) => {
    res.json({ assets: org.listAssets(req.effectiveTenantId!) });
  });
  app.get("/api/v1/org/exposure", requireAuth, (req: Authed, res) => {
    res.json(org.exposureSummary(req.effectiveTenantId!));
  });
  app.post("/api/v1/org/assets", requireAuth, (req: Authed, res, next) => {
    const parsed = orgAssetCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      res.status(201).json(org.createAsset(req.effectiveTenantId!, parsed.data, actorOf(req)));
    } catch (e: any) {
      if (e?.status === 409) return res.status(409).json({ detail: e.message });
      next(e);
    }
  });
  app.post("/api/v1/org/assets/bulk", requireAuth, (req: Authed, res, next) => {
    const parsed = orgAssetBulkSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      res.status(201).json(org.createAssets(req.effectiveTenantId!, parsed.data.assets, actorOf(req)));
    } catch (e) {
      next(e);
    }
  });
  app.patch("/api/v1/org/assets/:id", requireAuth, (req: Authed, res, next) => {
    const parsed = orgAssetPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      const updated = org.updateAsset(req.effectiveTenantId!, String(req.params.id), parsed.data);
      if (!updated) return res.status(404).json({ detail: "asset not found" });
      res.json(updated);
    } catch (e: any) {
      if (e?.status === 409) return res.status(409).json({ detail: e.message });
      next(e);
    }
  });
  app.delete("/api/v1/org/assets/:id", requireAuth, (req: Authed, res) => {
    if (!org.deleteAsset(req.effectiveTenantId!, String(req.params.id))) {
      return res.status(404).json({ detail: "asset not found" });
    }
    res.status(204).end();
  });

  // ---------------- Cases ----------------
  app.get("/api/v1/cases", requireAuth, (req: Authed, res) => {
    res.json({
      cases: cases.listCases(req.effectiveTenantId!, {
        status: typeof req.query.status === "string" ? req.query.status : undefined,
        assignee: typeof req.query.assignee === "string" ? req.query.assignee : undefined,
        q: typeof req.query.q === "string" ? req.query.q : undefined,
      }),
    });
  });
  app.post("/api/v1/cases", requireAuth, (req: Authed, res) => {
    const parsed = investigationCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    const created = cases.createCase(req.effectiveTenantId!, parsed.data, actorOf(req));
    res.status(201).json(created);
  });
  app.get("/api/v1/cases/for-entity", requireAuth, (req: Authed, res) => {
    const entityType = String(req.query.entityType || "") as CaseLinkType;
    const entityId = String(req.query.entityId || "");
    if (!entityType || !entityId) return res.status(400).json({ detail: "entityType and entityId required" });
    res.json({ cases: cases.casesForEntity(req.effectiveTenantId!, entityType, entityId) });
  });
  app.get("/api/v1/cases/:cid", requireAuth, (req: Authed, res) => {
    const full = cases.getCaseFull(req.effectiveTenantId!, String(req.params.cid));
    if (!full) return res.status(404).json({ detail: "case not found" });
    res.json(full);
  });
  app.patch("/api/v1/cases/:cid", requireAuth, (req: Authed, res) => {
    const parsed = investigationPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    const updated = cases.updateCase(req.effectiveTenantId!, String(req.params.cid), parsed.data, actorOf(req));
    if (!updated) return res.status(404).json({ detail: "case not found" });
    res.json(updated);
  });
  app.delete("/api/v1/cases/:cid", requireAuth, (req: Authed, res) => {
    if (!isAdmin(req)) return res.status(403).json({ detail: "admin role required" });
    const ok = cases.deleteCase(req.effectiveTenantId!, String(req.params.cid), actorOf(req));
    if (!ok) return res.status(404).json({ detail: "case not found" });
    res.status(204).end();
  });
  app.post("/api/v1/cases/:cid/links", requireAuth, (req: Authed, res, next) => {
    const parsed = caseLinkSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      res.status(201).json(cases.addLink(req.effectiveTenantId!, String(req.params.cid), parsed.data, actorOf(req)));
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/cases/:cid/links/:lid", requireAuth, (req: Authed, res) => {
    const ok = cases.removeLink(req.effectiveTenantId!, String(req.params.cid), String(req.params.lid), actorOf(req));
    if (!ok) return res.status(404).json({ detail: "link not found" });
    res.status(204).end();
  });
  app.post("/api/v1/cases/:cid/notes", requireAuth, (req: Authed, res, next) => {
    const parsed = investigationNoteSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      res
        .status(201)
        .json(
          cases.addNote(
            req.effectiveTenantId!,
            String(req.params.cid),
            { kind: parsed.data.kind === "ai" ? "analyst" : parsed.data.kind, body: parsed.data.body },
            actorOf(req),
          ),
        );
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/cases/:cid/notes/:nid", requireAuth, (req: Authed, res) => {
    const ok = cases.deleteNote(req.effectiveTenantId!, String(req.params.cid), String(req.params.nid));
    if (!ok) return res.status(404).json({ detail: "note not found" });
    res.status(204).end();
  });

  // ---------------- Hunt results ----------------
  app.get("/api/v1/osint/hunt-queries/:hid/results", requireAuth, (req: Authed, res) => {
    res.json({ results: hunts.listHuntResults(req.effectiveTenantId!, String(req.params.hid)) });
  });
  app.post("/api/v1/osint/hunt-queries/:hid/results", requireAuth, (req: Authed, res, next) => {
    const parsed = huntResultCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      res
        .status(201)
        .json(hunts.addHuntResult(req.effectiveTenantId!, String(req.params.hid), parsed.data, actorOf(req)));
    } catch (e) {
      next(e);
    }
  });
  app.delete("/api/v1/osint/hunt-queries/:hid/results/:rid", requireAuth, (req: Authed, res) => {
    const ok = hunts.deleteHuntResult(
      req.effectiveTenantId!,
      String(req.params.hid),
      String(req.params.rid),
      actorOf(req),
    );
    if (!ok) return res.status(404).json({ detail: "result not found" });
    res.status(204).end();
  });
  app.get("/api/v1/osint/hunt-results/latest", requireAuth, (req: Authed, res) => {
    const ids = String(req.query.ids || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 200);
    const map = hunts.latestHuntResultsByQuery(req.effectiveTenantId!, ids);
    res.json({ results: Object.fromEntries(map) });
  });

  // ---------------- CVE enrichment ----------------
  app.get("/api/v1/osint/cve", requireAuth, (req: Authed, res) => {
    const ids = String(req.query.ids || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 200);
    const map = getCveEnrichment(ids);
    res.json({ cves: Object.fromEntries(map) });
  });
  app.get("/api/v1/osint/cve/pending", requireAuth, (req: Authed, res) => {
    res.json({ pending: listCvesNeedingEnrichment(req.effectiveTenantId!, { limit: 500 }) });
  });
  app.post("/api/v1/osint/cve/enrich", requireAuth, async (req: Authed, res, next) => {
    const parsed = cveEnrichRequestSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      const summary = await enrichCves(parsed.data.cveIds, { force: parsed.data.force, nvdLimit: 8 });
      storage.appendAudit(req.effectiveTenantId!, actorOf(req), "osint.cve.enrich", null, summary);
      res.json({ ...summary, cves: Object.fromEntries(getCveEnrichment(parsed.data.cveIds)) });
    } catch (e) {
      next(e);
    }
  });

  // ---------------- Review queue ----------------
  app.get("/api/v1/osint/review/metrics", requireAuth, (req: Authed, res) => {
    const days = Math.max(1, Math.min(180, Number(req.query.days || 30) || 30));
    res.json(reviewQueueMetrics(req.effectiveTenantId!, days));
  });
  app.patch("/api/v1/osint/findings/:fid/review", requireAuth, (req: Authed, res) => {
    const parsed = findingReviewPatchSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    const ok = setFindingReview(req.effectiveTenantId!, String(req.params.fid), parsed.data, actorOf(req));
    if (!ok) return res.status(404).json({ detail: "not found" });
    const f = storage.getOsintFinding(req.effectiveTenantId!, String(req.params.fid));
    res.json(f ? attachCveSummaries([f])[0] : { ok: true });
  });
  app.get("/api/v1/osint/review/queue", requireAuth, (req: Authed, res) => {
    const tid = req.effectiveTenantId!;
    const assignee = typeof req.query.assignee === "string" ? req.query.assignee : undefined;
    const open = storage
      .listOsintFindings(tid)
      .filter((f) => ["new", "triaged", "escalated"].includes(f.status) && (!assignee || f.assignee === assignee));
    attachCveSummaries(open);
    org.attachOrgRelevance(tid, open);
    const nowIso = new Date().toISOString();
    const orgBoost = { urgent: 60, high: 35, watch: 15 } as const;
    const sevWeight: Record<string, number> = { critical: 20, high: 12, medium: 5, low: 1, info: 0 };
    const score = (f: (typeof open)[number]) =>
      (f.cveEnrichment?.priority ?? 0) +
      (f.orgRelevance ? orgBoost[f.orgRelevance.priority] : 0) +
      (f.status === "escalated" ? 30 : 0) +
      (f.dueAt && f.dueAt < nowIso ? 25 : 0) +
      (sevWeight[String(f.severity).toLowerCase()] ?? 0);
    open.sort((a, b) => score(b) - score(a));
    res.json({ findings: open.slice(0, 300), total: open.length });
  });

  // ---------------- Documents ----------------
  app.get("/api/v1/osint/documents", requireAuth, (req: Authed, res) => {
    res.json({ documents: listDocuments(req.effectiveTenantId!) });
  });
  app.post("/api/v1/osint/documents", uploadLimiter, requireAuth, async (req: Authed, res, next) => {
    const parsed = documentIngestSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      const out = await ingestDocument(req.effectiveTenantId!, parsed.data, actorOf(req));
      // Kick enrichment for the CVEs we just found; bounded, non-blocking.
      if (out.cveIds.length)
        enrichCves(out.cveIds, { nvdLimit: 4 }).catch(() => {
          /* background */
        });
      res.status(201).json(out);
    } catch (e: any) {
      if (e?.status === 409 && e?.findingId) return res.status(409).json({ detail: e.message, findingId: e.findingId });
      next(e);
    }
  });

  // ---------------- ATT&CK Navigator ----------------
  app.get("/api/v1/threat-actors/:aid/navigator-layer.json", requireAuth, (req: Authed, res) => {
    const full = storage.getFullThreatActor(req.effectiveTenantId!, String(req.params.aid));
    if (!full) return res.status(404).json({ detail: "threat actor not found" });
    const layer = buildActorNavigatorLayer(full);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${full.profileId}_${full.primaryName.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 50)}_attack-layer.json"`,
    );
    res.json(layer);
  });
  app.get("/api/v1/osint/attack-coverage/navigator-layer.json", requireAuth, (req: Authed, res) => {
    const days = Math.max(1, Math.min(365, Number(req.query.days || 90) || 90));
    const { layer } = buildCoverageNavigatorLayer(req.effectiveTenantId!, { sinceDays: days });
    res.setHeader("Content-Disposition", `attachment; filename="threatlens_hunt-coverage_${days}d.json"`);
    res.json(layer);
  });
  // STIX 2.1 bundle download for the same selection the preview describes.
  app.get("/api/v1/exchange/stix/export", requireAuth, (req: Authed, res) => {
    const ids = String(req.query.findingIds || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 500);
    if (ids.length === 0) return res.status(400).json({ detail: "findingIds required" });
    const tenantId = req.effectiveTenantId!;
    const findings = ids
      .map((id) => storage.getOsintFinding(tenantId, id))
      .filter((f): f is NonNullable<typeof f> => !!f);
    if (findings.length === 0) return res.status(404).json({ detail: "no matching findings in this workspace" });
    const bundle = buildStixBundle(findings);
    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="threatlens-stix-${stamp}.json"`);
    res.send(JSON.stringify(bundle, null, 2));
  });

  // IoC export in the import format of a chosen EDR / SIEM platform.
  app.get("/api/v1/detections/iocs/export", requireAuth, (req: Authed, res) => {
    const platform = String(req.query.platform || "") as IocPlatformId;
    if (!IOC_PLATFORMS.some((p) => p.id === platform)) {
      return res.status(400).json({ detail: `platform must be one of: ${IOC_PLATFORMS.map((p) => p.id).join(", ")}` });
    }
    const ids = String(req.query.findingIds || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 500);
    const intelName = typeof req.query.intelName === "string" ? req.query.intelName.trim() : "";
    const intelSource = typeof req.query.intelSource === "string" ? req.query.intelSource.trim() : "";
    let findings: Array<{ title: string; severity?: string | null; iocs?: any }> = [];
    if (ids.length === 0 && (intelName || intelSource)) {
      // Export from the named-IoC library (e.g. every "Cobaltstrike C2" address).
      const where: string[] = [];
      const params: string[] = [];
      if (intelName) {
        where.push("name = ? COLLATE NOCASE");
        params.push(intelName);
      }
      if (intelSource) {
        where.push("source = ?");
        params.push(intelSource);
      }
      const rows = sqlite
        .prepare(`SELECT ioc_type, value, name FROM ioc_intel WHERE ${where.join(" AND ")} LIMIT 5000`)
        .all(...params) as any[];
      const iocs: Record<string, string[]> = {};
      for (const r of rows) (iocs[r.ioc_type] ??= []).push(r.value);
      if (rows.length === 0) return res.status(404).json({ detail: "no matching indicators in the library" });
      findings = [{ title: intelName || `Indicators from ${intelSource}`, severity: "high", iocs }];
    } else {
      if (ids.length === 0) return res.status(400).json({ detail: "findingIds (or intelName / intelSource) required" });
      const tenantId = req.effectiveTenantId!;
      findings = ids.map((id) => storage.getOsintFinding(tenantId, id)).filter((f): f is NonNullable<typeof f> => !!f);
      if (findings.length === 0) return res.status(404).json({ detail: "no matching findings in this workspace" });
    }
    const days = Number(req.query.expireDays);
    const out = buildIocExport(platform, findings, {
      expireDays: Number.isFinite(days) && days > 0 && days <= 3650 ? days : 90,
    });
    if (out.total === 0) {
      return res.status(422).json({
        detail: "the selected findings contain no exportable indicators for this platform",
        unsupported: out.unsupported,
      });
    }
    res.setHeader("Content-Type", out.contentType);
    res.setHeader("Content-Disposition", `attachment; filename="${out.filename}"`);
    res.setHeader("X-Ioc-Total", String(out.total));
    res.setHeader("X-Ioc-Counts", JSON.stringify(out.counts));
    res.setHeader("X-Ioc-Unsupported", JSON.stringify(out.unsupported));
    res.send(out.body);
  });

  // STIX 2.1 export preview. The Intel Inbox calls this when an analyst opens
  // the preview dialog over a selection, so it must stay cheap: it counts what
  // the bundle would contain without building or persisting one.
  app.get("/api/v1/exchange/stix/preview", requireAuth, (req: Authed, res) => {
    const ids = String(req.query.findingIds || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 500);
    const tenantId = req.effectiveTenantId!;
    const findings = ids
      .map((id) => storage.getOsintFinding(tenantId, id))
      .filter((f): f is NonNullable<typeof f> => !!f);
    const preview = buildStixPreview(findings);
    if (findings.length < ids.length) {
      preview.warnings.unshift(
        `${ids.length - findings.length} selected finding(s) could not be resolved in this workspace.`,
      );
    }
    res.json(preview);
  });

  app.get("/api/v1/osint/attack-coverage", requireAuth, (req: Authed, res) => {
    const days = Math.max(1, Math.min(365, Number(req.query.days || 90) || 90));
    const { layer, counts, techniqueCount } = buildCoverageNavigatorLayer(req.effectiveTenantId!, { sinceDays: days });
    res.json({
      counts,
      techniqueCount,
      tacticOrder: TACTIC_ORDER,
      techniques: layer.techniques.map((t) => ({
        id: t.techniqueID,
        name: t.metadata.find((m) => m.name === "techniqueName")?.value || null,
        tactics: (t.metadata.find((m) => m.name === "tactics")?.value || "").split(",").filter(Boolean),
        coverage: t.metadata.find((m) => m.name === "coverage")?.value,
        findings: Number(t.metadata.find((m) => m.name === "findings")?.value ?? 0),
        actors: Number(t.metadata.find((m) => m.name === "actors")?.value ?? 0),
        huntQueries: Number(t.metadata.find((m) => m.name === "huntQueries")?.value ?? 0),
      })),
    });
  });

  // ---------------- Reports ----------------
  app.post("/api/v1/reports/brief", reportLimiter, requireAuth, async (req: Authed, res, next) => {
    const parsed = reportBriefRequestSchema.safeParse(req.body || {});
    if (!parsed.success) return bad(res, parsed.error);
    try {
      const model = buildReportModel(req.effectiveTenantId!, parsed.data);
      auditReport(req.effectiveTenantId!, actorOf(req), parsed.data.kind, parsed.data.format, {
        caseId: parsed.data.caseId ?? null,
        days: parsed.data.days ?? null,
      });
      const filename = reportFilename(model, parsed.data.format);
      if (parsed.data.format === "md") {
        res.setHeader("Content-Type", "text/markdown; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        return res.send(renderMarkdown(model));
      }
      const buf = await renderDocx(model);
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", String(buf.byteLength));
      res.end(buf);
    } catch (e) {
      next(e);
    }
  });
}
