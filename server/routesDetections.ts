/**
 * Detection Library routes: named IoC intel, the Sigma rule library, and the
 * "is this finding already covered?" check. Every path is listed in
 * shared/accessPolicy.
 */
import type { Express, Response, NextFunction } from "express";
import { storage } from "./storage";
import { sqlite } from "./storage";
import { IOC_FEEDS, getSyncState, syncAllIocFeeds } from "./iocFeeds";
import { coverageFor, getRule, ruleLibrarySummary, searchRules, syncSigma, syncYara } from "./ruleLibrary";
import { attackMatrix, attackTechnique, syncAttack } from "./attackMatrix";
import { convertSigma, CONVERT_PLATFORMS, type ConvertPlatform } from "./sigmaConvert";

type Authed = import("express").Request & {
  user?: { id: string; email: string; role: string };
  effectiveTenantId?: string;
};
type Middleware = (req: Authed, res: Response, next: NextFunction) => unknown;

const likeEsc = (s: string) => s.replace(/[\\%_]/g, "\\$&");
const intParam = (v: unknown, d: number) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.floor(n) : d;
};

let syncing = false;
let lastSync: {
  startedAt: string;
  finishedAt: string | null;
  iocs?: unknown;
  rules?: unknown;
  attack?: unknown;
} | null = null;

/** Run a full intel refresh once at a time. Used by the route and the scheduler. */
export async function runIntelSync(target: "iocs" | "rules" | "attack" | "all" = "all") {
  if (syncing) return { busy: true as const };
  syncing = true;
  const startedAt = new Date().toISOString();
  lastSync = { startedAt, finishedAt: null };
  try {
    const iocs = target === "all" || target === "iocs" ? await syncAllIocFeeds() : undefined;
    const rules =
      target === "all" || target === "rules" ? { sigma: await syncSigma(), yara: await syncYara() } : undefined;
    const attack = target === "all" || target === "attack" ? await syncAttack() : undefined;
    lastSync = { startedAt, finishedAt: new Date().toISOString(), iocs, rules, attack };
    return { busy: false as const, iocs, rules, attack };
  } finally {
    syncing = false;
  }
}

/** Scheduler hook: refresh IoC feeds hourly and rules weekly, only when due. */
export async function syncIntelIfDue(now = Date.now()): Promise<void> {
  const age = (key: string) => {
    const t = Date.parse(getSyncState(key).lastRun ?? "");
    return Number.isFinite(t) ? now - t : Infinity;
  };
  const iocDue = IOC_FEEDS.some((f) => age(`ioc:${f.id}`) > 60 * 60_000);
  const weekly = 7 * 24 * 60 * 60_000;
  const rulesDue = age("rules:sigmahq") > weekly || age("rules:yara") > weekly;
  const attackDue = age("attack:enterprise") > weekly;
  if (iocDue) await runIntelSync("iocs");
  if (rulesDue) await runIntelSync("rules");
  if (attackDue) await runIntelSync("attack");
}

export function registerDetectionRoutes(app: Express, requireAuth: Middleware, requireManage: Middleware): void {
  // ---- IoC intel ----
  app.get("/api/v1/detections/iocs", requireAuth, (req: Authed, res) => {
    const where: string[] = [];
    const params: unknown[] = [];
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    if (q) {
      where.push("(value LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')");
      const like = `%${likeEsc(q)}%`;
      params.push(like, like);
    }
    if (typeof req.query.type === "string" && req.query.type) {
      where.push("ioc_type = ?");
      params.push(req.query.type);
    }
    if (typeof req.query.name === "string" && req.query.name) {
      where.push("name = ? COLLATE NOCASE");
      params.push(req.query.name);
    }
    if (typeof req.query.source === "string" && req.query.source) {
      where.push("source = ?");
      params.push(req.query.source);
    }
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const limit = Math.min(200, Math.max(1, intParam(req.query.limit, 50)));
    const offset = Math.max(0, intParam(req.query.offset, 0));
    const total = (sqlite.prepare(`SELECT COUNT(*) c FROM ioc_intel ${clause}`).get(...params) as any).c;
    const rows = sqlite
      .prepare(
        `SELECT ioc_type, value, name, source, port, status, first_seen, last_seen, confidence FROM ioc_intel ${clause} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?`,
      )
      .all(...params, limit, offset) as any[];
    res.json({
      total,
      iocs: rows.map((r) => ({
        type: r.ioc_type,
        value: r.value,
        name: r.name,
        source: r.source,
        port: r.port,
        status: r.status,
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
        confidence: r.confidence,
      })),
    });
  });

  app.get("/api/v1/detections/iocs/summary", requireAuth, (_req: Authed, res) => {
    const total = (sqlite.prepare("SELECT COUNT(*) c FROM ioc_intel").get() as any).c;
    const names = sqlite
      .prepare("SELECT name, COUNT(*) c FROM ioc_intel GROUP BY name COLLATE NOCASE ORDER BY c DESC LIMIT 15")
      .all() as any[];
    const types = sqlite.prepare("SELECT ioc_type t, COUNT(*) c FROM ioc_intel GROUP BY t").all() as any[];
    res.json({
      total,
      names: names.map((n) => ({ name: n.name as string, count: n.c as number })),
      types: Object.fromEntries(types.map((t) => [t.t, t.c])),
      feeds: IOC_FEEDS.map((f) => {
        const s = getSyncState(`ioc:${f.id}`);
        return {
          id: f.id,
          label: f.label,
          homepage: f.homepage,
          count: (sqlite.prepare("SELECT COUNT(*) c FROM ioc_intel WHERE source = ?").get(f.id) as any).c,
          lastRun: s.lastRun,
          lastError: s.lastError,
        };
      }),
    });
  });

  // ---- Rule library ----
  app.get("/api/v1/detections/rules/summary", requireAuth, (_req: Authed, res) => {
    res.json(ruleLibrarySummary());
  });
  app.get("/api/v1/detections/rules", requireAuth, (req: Authed, res) => {
    const s = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
    res.json(
      searchRules({
        q: s(req.query.q),
        technique: s(req.query.technique),
        product: s(req.query.product),
        level: s(req.query.level),
        source: s(req.query.source),
        limit: intParam(req.query.limit, 50),
        offset: intParam(req.query.offset, 0),
      }),
    );
  });
  app.get("/api/v1/detections/rules/:id", requireAuth, (req: Authed, res) => {
    const rule = getRule(decodeURIComponent(String(req.params.id)));
    if (!rule) return res.status(404).json({ detail: "rule not found" });
    res.json(rule);
  });

  // ---- Sigma -> EDR / SIEM conversion ----
  app.get("/api/v1/detections/rules/:id/convert", requireAuth, (req: Authed, res) => {
    const platform = String(req.query.platform || "") as ConvertPlatform;
    if (!CONVERT_PLATFORMS.some((p) => p.id === platform)) {
      return res
        .status(400)
        .json({ detail: `platform must be one of: ${CONVERT_PLATFORMS.map((p) => p.id).join(", ")}` });
    }
    const rule = getRule(decodeURIComponent(String(req.params.id)));
    if (!rule) return res.status(404).json({ detail: "rule not found" });
    if (rule.source !== "sigmahq") {
      return res.json({
        platform,
        supported: false,
        notes: [],
        error: "only Sigma rules can be converted; YARA rules are used as-is with YARA-capable scanners",
      });
    }
    res.json(convertSigma(rule.raw, platform));
  });

  // ---- MITRE ATT&CK ----
  app.get("/api/v1/detections/attack/matrix", requireAuth, (_req: Authed, res) => {
    res.json(attackMatrix());
  });
  app.get("/api/v1/detections/attack/techniques/:id", requireAuth, (req: Authed, res) => {
    const t = attackTechnique(String(req.params.id));
    if (!t) return res.status(404).json({ detail: "technique not found — sync ATT&CK first" });
    res.json(t);
  });

  // ---- Coverage ----
  app.get("/api/v1/detections/coverage", requireAuth, (req: Authed, res) => {
    const findingId = String(req.query.findingId || "");
    if (!findingId) return res.status(400).json({ detail: "findingId required" });
    const f = storage.getOsintFinding(req.effectiveTenantId!, findingId);
    if (!f) return res.status(404).json({ detail: "finding not found" });
    res.json(coverageFor(f));
  });

  // ---- Sync ----
  app.get("/api/v1/detections/sync/status", requireAuth, (_req: Authed, res) => {
    res.json({ busy: syncing, last: lastSync });
  });
  app.post("/api/v1/detections/sync", requireAuth, requireManage, (req: Authed, res) => {
    const t = String(req.body?.target || "all");
    const target = t === "iocs" || t === "rules" || t === "attack" ? t : "all";
    if (syncing) return res.status(409).json({ detail: "a sync is already running" });
    runIntelSync(target).catch((e) => console.error("[detections] sync failed:", e));
    res.status(202).json({ status: "started", target });
  });
}
