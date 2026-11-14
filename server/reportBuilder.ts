/**
 * Report builder — deterministic briefs assembled from workspace data, with
 * AI-authored text clearly labelled and optional. Three kinds:
 *
 *   executive_brief   — last N days: exploited/high-priority findings, active
 *                       actors, hunt coverage, queue health. For leadership.
 *   weekly_landscape  — last 7 days by default: volume by source/category,
 *                       new CVEs (KEV/EPSS), actors seen, hunts run.
 *   case_report       — one case: summary, timeline, linked evidence, IOCs,
 *                       techniques, hunt results, notes.
 *
 * Every section marks provenance: [verified] analyst-recorded data, [ai] model
 * output (only when includeAi), [feed] ingested source data.
 */
import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  Table,
  TableRow,
  TableCell,
  WidthType,
  ShadingType,
  AlignmentType,
} from "docx";
import { sqlite, storage } from "./storage";
import { getCaseFull } from "./cases";
import { getCveEnrichment, normaliseCveId, cvePriority } from "./cveEnrichment";
import { reviewQueueMetrics } from "./reviewQueue";
import { buildCoverageNavigatorLayer } from "./attackNavigator";
import { latestHuntResultsByQuery } from "./huntResults";
import type { ReportBriefKind } from "@shared/schema";

// ---------- model ----------
type Block =
  | { t: "h1"; text: string }
  | { t: "h2"; text: string }
  | { t: "p"; text: string; muted?: boolean }
  | { t: "bullets"; items: string[] }
  | { t: "table"; header: string[]; rows: string[][] }
  | { t: "tag"; text: string };

interface ReportModel {
  title: string;
  subtitle: string;
  generatedAt: string;
  blocks: Block[];
}

const fmtDate = (iso: string | null | undefined) => (iso ? String(iso).slice(0, 10) : "—");
const pct = (n: number | null | undefined) => (typeof n === "number" ? `${Math.round(n * 100)}%` : "—");

// ---------- data assembly ----------
function recentFindings(tenantId: string, days: number) {
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  return sqlite
    .prepare(
      `
    SELECT f.id, f.title, f.severity, f.status, f.published_at, f.cve_ids, f.threat_actors, f.attack_techniques,
           f.ai_summary, f.ai_recommendation, f.intel_category, f.analyst_edited_at, s.name AS source_name, s.category AS source_category
    FROM osint_findings f LEFT JOIN osint_sources s ON s.id = f.source_id
    WHERE f.tenant_id = ? AND COALESCE(f.published_at, f.created_at) >= ?
    ORDER BY COALESCE(f.published_at, f.created_at) DESC
    LIMIT 2000
  `,
    )
    .all(tenantId, since) as any[];
}
const parseArr = (s: string | null): string[] => {
  try {
    const v = JSON.parse(s || "[]");
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
};

function rankFindings(rows: any[]) {
  const allCves = rows.flatMap((r) => parseArr(r.cve_ids));
  const enrichment = getCveEnrichment(allCves);
  const sevRank: Record<string, number> = { critical: 40, high: 30, medium: 15, low: 5, info: 0 };
  return rows
    .map((r) => {
      const cves = parseArr(r.cve_ids)
        .map((c) => normaliseCveId(c))
        .filter((c): c is string => !!c);
      const best =
        cves
          .map((c) => enrichment.get(c))
          .filter(Boolean)
          .sort((a, b) => cvePriority(b!) - cvePriority(a!))[0] ?? null;
      const score =
        (sevRank[String(r.severity).toLowerCase()] ?? 10) +
        (best ? cvePriority(best) : 0) +
        (r.status === "escalated" ? 20 : 0);
      return { ...r, cves, best, score };
    })
    .sort((a, b) => b.score - a.score);
}

function buildExecutiveBrief(tenantId: string, days: number, includeAi: boolean): ReportModel {
  const rows = rankFindings(recentFindings(tenantId, days));
  const metrics = reviewQueueMetrics(tenantId, days);
  const coverage = buildCoverageNavigatorLayer(tenantId, { sinceDays: days });
  const kev = rows.filter((r) => r.best?.kev);
  const highEpss = rows.filter((r) => !r.best?.kev && (r.best?.epssScore ?? 0) >= 0.5);
  const escalated = rows.filter((r) => r.status === "escalated");
  const actorCounts = new Map<string, number>();
  for (const r of rows) for (const a of parseArr(r.threat_actors)) actorCounts.set(a, (actorCounts.get(a) ?? 0) + 1);
  const topActors = Array.from(actorCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  const blocks: Block[] = [];
  blocks.push({ t: "h1", text: "Situation summary" });
  blocks.push({
    t: "bullets",
    items: [
      `${rows.length} intelligence items ingested in the last ${days} days across ${new Set(rows.map((r) => r.source_name)).size} sources. [feed]`,
      `${kev.length} item(s) reference CVEs on CISA's Known Exploited Vulnerabilities list; ${highEpss.length} more reference CVEs with ≥50% 30-day exploitation probability (EPSS). [verified: NVD/EPSS/KEV]`,
      `${escalated.length} finding(s) escalated by analysts; ${metrics.backlog.total} open in the review queue (${metrics.backlog.overdue} overdue, ${metrics.backlog.unassigned} unassigned). [verified]`,
      `Hunt coverage: ${coverage.counts.hit} technique(s) hunted with hits, ${coverage.counts.hunted} hunted without hits, ${coverage.counts.drafted} drafted only, ${coverage.counts.none} observed with no hunt. [verified]`,
    ],
  });
  blocks.push({ t: "h1", text: "Priority items" });
  blocks.push({
    t: "p",
    text: "Ranked by exploitation evidence (KEV, EPSS, CVSS), severity and analyst escalation.",
    muted: true,
  });
  blocks.push({
    t: "table",
    header: ["Finding", "Source", "Published", "CVE", "Exploitation", "Status"],
    rows: rows
      .slice(0, 15)
      .map((r) => [
        r.title,
        r.source_name ?? "—",
        fmtDate(r.published_at),
        r.best?.cveId ?? r.cves[0] ?? "—",
        r.best
          ? [
              r.best.kev ? "KEV" : null,
              r.best.epssScore != null ? `EPSS ${pct(r.best.epssScore)}` : null,
              r.best.cvssScore != null ? `CVSS ${r.best.cvssScore}` : null,
            ]
              .filter(Boolean)
              .join(" · ")
          : "—",
        r.status,
      ]),
  });
  if (includeAi) {
    const withAi = rows.filter((r) => r.ai_recommendation).slice(0, 8);
    if (withAi.length) {
      blocks.push({ t: "h2", text: "AI-suggested actions [ai — unverified]" });
      blocks.push({
        t: "bullets",
        items: withAi.map((r) => `${r.title}: ${String(r.ai_recommendation).slice(0, 240)}`),
      });
    }
  }
  blocks.push({ t: "h1", text: "Threat actors seen" });
  blocks.push(
    topActors.length
      ? { t: "table", header: ["Actor", "Mentions"], rows: topActors.map(([a, n]) => [a, String(n)]) }
      : { t: "p", text: "No actor attribution in the window.", muted: true },
  );
  blocks.push({ t: "h1", text: "Review queue health" });
  blocks.push({
    t: "table",
    header: ["Metric", "Value"],
    rows: [
      ["Open findings", String(metrics.backlog.total)],
      ["Overdue", String(metrics.backlog.overdue)],
      ["Unassigned", String(metrics.backlog.unassigned)],
      ["Older than 7 days", String(metrics.backlog.byAge.gt7d)],
      ["Triaged in window", String(metrics.throughput.triaged)],
      [
        "Mean time to triage",
        metrics.throughput.meanTimeToTriageHours != null ? `${metrics.throughput.meanTimeToTriageHours} h` : "—",
      ],
      ["Dismissed / escalated", `${metrics.throughput.dismissed} / ${metrics.throughput.escalated}`],
    ],
  });
  return {
    title: "Executive threat brief",
    subtitle: `Last ${days} days · generated ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`,
    generatedAt: new Date().toISOString(),
    blocks,
  };
}

function buildWeeklyLandscape(tenantId: string, days: number, includeAi: boolean): ReportModel {
  const rows = rankFindings(recentFindings(tenantId, days));
  const bySource = new Map<string, number>();
  const byCategory = new Map<string, number>();
  const byIntel = new Map<string, number>();
  for (const r of rows) {
    bySource.set(r.source_name ?? "unknown", (bySource.get(r.source_name ?? "unknown") ?? 0) + 1);
    byCategory.set(r.source_category ?? "unknown", (byCategory.get(r.source_category ?? "unknown") ?? 0) + 1);
    byIntel.set(r.intel_category ?? "unclassified", (byIntel.get(r.intel_category ?? "unclassified") ?? 0) + 1);
  }
  const cveSet = new Map<string, any>();
  for (const r of rows) for (const c of r.cves) if (!cveSet.has(c)) cveSet.set(c, r);
  const enrichment = getCveEnrichment(Array.from(cveSet.keys()));
  const cveRows = Array.from(cveSet.keys())
    .map((c) => ({ c, e: enrichment.get(c) ?? null }))
    .sort((a, b) => (b.e ? cvePriority(b.e) : 0) - (a.e ? cvePriority(a.e) : 0))
    .slice(0, 25);
  const techCounts = new Map<string, number>();
  for (const r of rows) {
    try {
      for (const t of JSON.parse(r.attack_techniques || "[]")) {
        const id = typeof t === "string" ? t : t?.id;
        if (id) techCounts.set(id, (techCounts.get(id) ?? 0) + 1);
      }
    } catch {
      /* ignore */
    }
  }
  const hunts = sqlite
    .prepare(
      "SELECT id, title, created_at FROM hunt_queries WHERE tenant_id = ? AND created_at >= ? ORDER BY created_at DESC",
    )
    .all(tenantId, new Date(Date.now() - days * 86400_000).toISOString()) as any[];
  const results = latestHuntResultsByQuery(
    tenantId,
    hunts.map((h) => h.id),
  );
  const blocks: Block[] = [];
  blocks.push({ t: "h1", text: "Volume" });
  blocks.push({
    t: "bullets",
    items: [
      `${rows.length} items from ${bySource.size} sources. [feed]`,
      `By category: ${Array.from(byCategory.entries())
        .map(([k, v]) => `${k} ${v}`)
        .join(", ")}.`,
      `AI classification: ${Array.from(byIntel.entries())
        .map(([k, v]) => `${k} ${v}`)
        .join(", ")}. [ai]`,
    ],
  });
  blocks.push({
    t: "table",
    header: ["Source", "Items"],
    rows: Array.from(bySource.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([s, n]) => [s, String(n)]),
  });
  blocks.push({ t: "h1", text: "Vulnerabilities" });
  blocks.push(
    cveRows.length
      ? {
          t: "table",
          header: ["CVE", "KEV", "EPSS", "CVSS", "First seen in"],
          rows: cveRows.map(({ c, e }) => [
            c,
            e?.kev ? "yes" : "—",
            pct(e?.epssScore),
            e?.cvssScore != null ? String(e.cvssScore) : "—",
            cveSet.get(c)?.source_name ?? "—",
          ]),
        }
      : { t: "p", text: "No CVEs referenced in the window.", muted: true },
  );
  blocks.push({ t: "h1", text: "Techniques observed [ai-extracted]" });
  blocks.push(
    techCounts.size
      ? {
          t: "table",
          header: ["Technique", "Findings"],
          rows: Array.from(techCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([t, n]) => [t, String(n)]),
        }
      : { t: "p", text: "No ATT&CK techniques extracted yet — run AI analysis on recent findings.", muted: true },
  );
  blocks.push({ t: "h1", text: "Hunts" });
  blocks.push(
    hunts.length
      ? {
          t: "table",
          header: ["Hunt", "Created", "Latest result"],
          rows: hunts.map((h) => [
            h.title,
            fmtDate(h.created_at),
            (results.get(h.id) ?? [])
              .map((r) => `${r.language}: ${r.outcome}${r.hitCount ? ` (${r.hitCount})` : ""}`)
              .join("; ") || "not run",
          ]),
        }
      : { t: "p", text: "No hunt queries generated in the window.", muted: true },
  );
  if (includeAi) {
    const summaries = rows.filter((r) => r.ai_summary && (r.best?.kev || r.severity === "critical")).slice(0, 6);
    if (summaries.length) {
      blocks.push({ t: "h1", text: "Notable items — AI summaries [ai — unverified]" });
      blocks.push({ t: "bullets", items: summaries.map((r) => `${r.title}: ${String(r.ai_summary).slice(0, 300)}`) });
    }
  }
  return {
    title: "Threat landscape",
    subtitle: `Last ${days} days · generated ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`,
    generatedAt: new Date().toISOString(),
    blocks,
  };
}

function buildCaseReport(tenantId: string, caseId: string, includeAi: boolean): ReportModel {
  const c = getCaseFull(tenantId, caseId);
  if (!c) {
    const e = new Error("case not found");
    (e as any).status = 404;
    throw e;
  }
  const blocks: Block[] = [];
  blocks.push({
    t: "table",
    header: ["Field", "Value"],
    rows: [
      ["Case", c.title],
      ["Status", c.status],
      ["Severity", c.severity],
      ["Assignee", c.assignee ?? "—"],
      ["Opened", fmtDate(c.createdAt)],
      ["Last updated", fmtDate(c.updatedAt)],
      ["Opened by", c.createdBy],
    ],
  });
  blocks.push({ t: "h1", text: "Summary [verified]" });
  blocks.push({ t: "p", text: c.summary || "No summary recorded." });
  blocks.push({ t: "h1", text: "Linked evidence" });
  blocks.push(
    c.links.length
      ? {
          t: "table",
          header: ["Type", "Item", "Context", "Added"],
          rows: c.links.map((l) => [l.entityType.replace("_", " "), l.title, l.subtitle ?? "—", fmtDate(l.createdAt)]),
        }
      : { t: "p", text: "Nothing linked yet.", muted: true },
  );
  blocks.push({ t: "h1", text: "Indicators of compromise [feed/analyst]" });
  const iocRows = Object.entries(c.iocs).flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => [k, x]) : []));
  blocks.push(
    iocRows.length
      ? { t: "table", header: ["Type", "Value"], rows: iocRows.slice(0, 300) }
      : { t: "p", text: "No indicators on linked findings.", muted: true },
  );
  blocks.push({ t: "h1", text: "Vulnerabilities" });
  if (c.cveIds.length) {
    const enr = getCveEnrichment(c.cveIds);
    blocks.push({
      t: "table",
      header: ["CVE", "KEV", "EPSS", "CVSS"],
      rows: c.cveIds.map((id) => {
        const e = enr.get(id);
        return [id, e?.kev ? "yes" : "—", pct(e?.epssScore), e?.cvssScore != null ? String(e.cvssScore) : "—"];
      }),
    });
  } else blocks.push({ t: "p", text: "No CVEs.", muted: true });
  blocks.push({ t: "h1", text: "ATT&CK techniques [ai-extracted]" });
  blocks.push(
    c.attackTechniques.length
      ? { t: "p", text: c.attackTechniques.join(", ") }
      : { t: "p", text: "None extracted.", muted: true },
  );
  blocks.push({ t: "h1", text: "Related actors" });
  blocks.push(
    c.relatedActors.length
      ? { t: "bullets", items: c.relatedActors.map((a) => `${a.profileId} ${a.name} — ${a.threatLevel}`) }
      : { t: "p", text: "None.", muted: true },
  );
  blocks.push({ t: "h1", text: "Hunt results [verified]" });
  blocks.push(
    c.huntResults.length
      ? {
          t: "table",
          header: ["Language", "Outcome", "Hits", "Recorded", "Evidence"],
          rows: c.huntResults.map((r) => [
            r.language,
            r.outcome,
            r.hitCount != null ? String(r.hitCount) : "—",
            fmtDate(r.recordedAt),
            r.evidence ?? "—",
          ]),
        }
      : { t: "p", text: "No hunts recorded for this case.", muted: true },
  );
  blocks.push({ t: "h1", text: "Timeline" });
  blocks.push({
    t: "table",
    header: ["When", "Event", "Detail"],
    rows: c.timeline.map((t) => [String(t.at).replace("T", " ").slice(0, 16), t.title, t.detail ?? "—"]),
  });
  const notes = c.notes.filter((n) => n.kind !== "system" && (includeAi || n.kind !== "ai"));
  blocks.push({ t: "h1", text: "Notes" });
  blocks.push(
    notes.length
      ? {
          t: "bullets",
          items: notes.map(
            (n) => `[${n.kind === "ai" ? "ai" : "verified"}] ${fmtDate(n.createdAt)} ${n.createdBy}: ${n.body}`,
          ),
        }
      : { t: "p", text: "No notes.", muted: true },
  );
  return {
    title: `Case report — ${c.title}`,
    subtitle: `Status ${c.status} · severity ${c.severity}`,
    generatedAt: new Date().toISOString(),
    blocks,
  };
}

export function buildReportModel(
  tenantId: string,
  req: { kind: ReportBriefKind; days?: number; caseId?: string; includeAi?: boolean },
): ReportModel {
  const includeAi = req.includeAi !== false;
  switch (req.kind) {
    case "executive_brief":
      return buildExecutiveBrief(tenantId, req.days ?? 14, includeAi);
    case "weekly_landscape":
      return buildWeeklyLandscape(tenantId, req.days ?? 7, includeAi);
    case "case_report": {
      if (!req.caseId) {
        const e = new Error("caseId is required for case_report");
        (e as any).status = 400;
        throw e;
      }
      return buildCaseReport(tenantId, req.caseId, includeAi);
    }
  }
}

// ---------- renderers ----------
export function renderMarkdown(m: ReportModel): string {
  const out: string[] = [
    `# ${m.title}`,
    ``,
    `_${m.subtitle}_`,
    ``,
    `Provenance tags: **[verified]** analyst-recorded · **[feed]** ingested source data · **[ai]** model output, not independently verified.`,
    ``,
  ];
  for (const b of m.blocks) {
    switch (b.t) {
      case "h1":
        out.push(`## ${b.text}`, "");
        break;
      case "h2":
        out.push(`### ${b.text}`, "");
        break;
      case "p":
        out.push(b.muted ? `_${b.text}_` : b.text, "");
        break;
      case "tag":
        out.push(`> ${b.text}`, "");
        break;
      case "bullets":
        out.push(...b.items.map((i) => `- ${i}`), "");
        break;
      case "table":
        out.push(`| ${b.header.join(" | ")} |`, `| ${b.header.map(() => "---").join(" | ")} |`);
        for (const r of b.rows)
          out.push(
            `| ${r
              .map((c) =>
                String(c ?? "")
                  .replace(/\|/g, "\\|")
                  .replace(/\n/g, " "),
              )
              .join(" | ")} |`,
          );
        out.push("");
        break;
    }
  }
  return out.join("\n");
}

const C_HEAD = "1F2A44";
const C_MUTED = "5B6478";
export async function renderDocx(m: ReportModel): Promise<Buffer> {
  const children: Array<Paragraph | Table> = [];
  children.push(
    new Paragraph({
      heading: HeadingLevel.TITLE,
      children: [new TextRun({ text: m.title, bold: true, size: 40, color: C_HEAD })],
    }),
  );
  children.push(
    new Paragraph({
      children: [new TextRun({ text: m.subtitle, italics: true, size: 20, color: C_MUTED })],
      spacing: { after: 200 },
    }),
  );
  children.push(
    new Paragraph({
      children: [
        new TextRun({
          text: "Provenance: [verified] analyst-recorded · [feed] ingested source data · [ai] model output, not independently verified.",
          size: 18,
          color: C_MUTED,
        }),
      ],
      spacing: { after: 240 },
    }),
  );
  for (const b of m.blocks) {
    switch (b.t) {
      case "h1":
        children.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_1,
            spacing: { before: 320, after: 120 },
            children: [new TextRun({ text: b.text, bold: true, size: 28, color: C_HEAD })],
          }),
        );
        break;
      case "h2":
        children.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 200, after: 80 },
            children: [new TextRun({ text: b.text, bold: true, size: 24, color: C_HEAD })],
          }),
        );
        break;
      case "p":
        children.push(
          new Paragraph({
            spacing: { after: 120 },
            children: [
              new TextRun({ text: b.text, size: 21, italics: !!b.muted, color: b.muted ? C_MUTED : undefined }),
            ],
          }),
        );
        break;
      case "tag":
        children.push(
          new Paragraph({
            spacing: { after: 120 },
            children: [new TextRun({ text: b.text, size: 19, color: C_MUTED })],
          }),
        );
        break;
      case "bullets":
        for (const i of b.items)
          children.push(
            new Paragraph({
              bullet: { level: 0 },
              spacing: { after: 60 },
              children: [new TextRun({ text: i, size: 21 })],
            }),
          );
        break;
      case "table": {
        const mk = (text: string, head = false) =>
          new TableCell({
            width: { size: Math.floor(100 / b.header.length), type: WidthType.PERCENTAGE },
            shading: head ? { type: ShadingType.CLEAR, fill: "F1F5F9", color: "auto" } : undefined,
            children: [
              new Paragraph({ alignment: AlignmentType.LEFT, children: [new TextRun({ text, bold: head, size: 18 })] }),
            ],
          });
        children.push(
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            rows: [
              new TableRow({ tableHeader: true, children: b.header.map((h) => mk(h, true)) }),
              ...b.rows.map((r) => new TableRow({ children: r.map((c) => mk(String(c ?? ""))) })),
            ],
          }),
        );
        children.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
        break;
      }
    }
  }
  const doc = new Document({ creator: "ThreatLens", title: m.title, sections: [{ children }] });
  return Buffer.from(await Packer.toBuffer(doc));
}

export function reportFilename(m: ReportModel, format: "docx" | "md"): string {
  const base = m.title.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60);
  return `${base}_${m.generatedAt.slice(0, 10)}.${format}`;
}

// keep storage import used (audit hook for report generation)
export function auditReport(
  tenantId: string,
  actor: string,
  kind: ReportBriefKind,
  format: string,
  detail: Record<string, unknown>,
) {
  storage.appendAudit(tenantId, actor, "report.generate", null, { kind, format, ...detail });
}
