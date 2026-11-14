/**
 * Actor activity derived from ingested intel.
 *
 * A TAP dossier is a written document: it is accurate as of the day an analyst
 * (or the enrichment job) last wrote it, and it says nothing about whether the
 * actor is active *now*. The findings table already answers that — every
 * finding carries the actor names parsed out of it — but nothing surfaced it,
 * so the Threat Actors showed month-old dossiers with no indication that
 * some of those actors were in today's intel and others had gone quiet.
 *
 * This module joins the two: for each dossier it reports when the actor was
 * last named in intel, how often, and how that compares to the dossier's own
 * age. No AI, no network — it is a query over data already ingested, so it is
 * correct the moment a scan completes.
 */
import type { Database } from "better-sqlite3";

export interface ActorActivity {
  /** Most recent publish date of a finding naming this actor. */
  lastSeenInIntel: string | null;
  /** Whole days since that finding, or null when never seen. */
  daysSinceLastSeen: number | null;
  /** Findings naming this actor, all time. */
  intelMentions: number;
  /** Findings naming this actor within the activity window. */
  recentMentions: number;
  /** Which of the actor's names actually matched — keeps the join auditable. */
  matchedNames: string[];
  /** Whole days since the dossier itself was last written. */
  dossierAgeDays: number | null;
  /**
   * How the dossier stands against the intel:
   *   active  — named in intel within the window
   *   quiet   — has intel, but none inside the window
   *   unseen  — no finding has ever named this actor
   */
  signal: "active" | "quiet" | "unseen";
  /** True when intel is newer than the dossier — the dossier has catching up to do. */
  intelNewerThanDossier: boolean;
}

const DAY_MS = 86_400_000;

function daysBetween(fromIso: string | null | undefined, nowMs: number): number | null {
  if (!fromIso) return null;
  const t = Date.parse(fromIso);
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.floor((nowMs - t) / DAY_MS));
}

/** Lowercased, punctuation-light key so "Cl0p" and "cl0p " collapse together. */
function key(name: unknown): string {
  return String(name ?? "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

function parseJsonArray(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw !== "string" || !raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}

/** Every name a dossier is known by: primary, aliases, and vendor synonyms. */
function actorNameKeys(row: { primary_name: string; aliases: unknown; vendor_names: unknown }): string[] {
  const names = [row.primary_name, ...parseJsonArray(row.aliases)];
  const vendor = row.vendor_names;
  if (typeof vendor === "string" && vendor) {
    try {
      const parsed = JSON.parse(vendor);
      if (parsed && typeof parsed === "object") {
        for (const list of Object.values(parsed)) {
          if (Array.isArray(list)) names.push(...list.map(String));
        }
      }
    } catch {
      /* a malformed vendor map just means fewer aliases to match on */
    }
  }
  // Single-character or numeric "names" would match half the corpus.
  return [...new Set(names.map(key).filter((n) => n.length >= 3))];
}

/**
 * Compute activity for every dossier in one pass over the findings table.
 *
 * Deliberately not per-actor: with 100 dossiers and thousands of findings a
 * query-per-actor turns the Observatory into an N+1, and this endpoint is
 * polled.
 */
export function computeActorActivity(
  sqlite: Database,
  tenantId: string,
  opts: { windowDays?: number; nowMs?: number } = {},
): Map<string, ActorActivity> {
  const windowDays = Math.max(1, Math.min(365, opts.windowDays ?? 30));
  const nowMs = opts.nowMs ?? Date.now();
  const windowStart = new Date(nowMs - windowDays * DAY_MS).toISOString();

  // ---- fold the findings into one entry per mentioned name ----------------
  type Mention = { last: string; total: number; recent: number };
  const byName = new Map<string, Mention>();

  const findings = sqlite
    .prepare(
      `SELECT threat_actors, published_at
         FROM osint_findings
        WHERE tenant_id = ?
          AND threat_actors IS NOT NULL
          AND threat_actors != ''
          AND threat_actors != '[]'`,
    )
    .all(tenantId) as Array<{ threat_actors: string; published_at: string | null }>;

  for (const row of findings) {
    const published = row.published_at || "";
    const isRecent = published >= windowStart;
    for (const raw of parseJsonArray(row.threat_actors)) {
      const k = key(raw);
      if (k.length < 3) continue;
      const prev = byName.get(k);
      if (!prev) {
        byName.set(k, { last: published, total: 1, recent: isRecent ? 1 : 0 });
      } else {
        if (published > prev.last) prev.last = published;
        prev.total += 1;
        if (isRecent) prev.recent += 1;
      }
    }
  }

  // ---- attribute those mentions to dossiers -------------------------------
  const actors = sqlite
    .prepare(`SELECT id, primary_name, aliases, vendor_names, updated_at FROM threat_actors WHERE tenant_id = ?`)
    .all(tenantId) as Array<{
    id: string;
    primary_name: string;
    aliases: unknown;
    vendor_names: unknown;
    updated_at: string | null;
  }>;

  const out = new Map<string, ActorActivity>();
  for (const actor of actors) {
    let lastSeen: string | null = null;
    let total = 0;
    let recent = 0;
    const matched: string[] = [];

    for (const name of actorNameKeys(actor)) {
      const hit = byName.get(name);
      if (!hit) continue;
      matched.push(name);
      total += hit.total;
      recent += hit.recent;
      if (!lastSeen || hit.last > lastSeen) lastSeen = hit.last;
    }

    const daysSinceLastSeen = daysBetween(lastSeen, nowMs);
    const dossierAgeDays = daysBetween(actor.updated_at, nowMs);

    out.set(actor.id, {
      lastSeenInIntel: lastSeen,
      daysSinceLastSeen,
      intelMentions: total,
      recentMentions: recent,
      matchedNames: matched,
      dossierAgeDays,
      signal: total === 0 ? "unseen" : recent > 0 ? "active" : "quiet",
      intelNewerThanDossier: !!(lastSeen && actor.updated_at && lastSeen > actor.updated_at),
    });
  }

  return out;
}

/** Roll the per-actor view up into the counts the Observatory header shows. */
export function summariseActorActivity(activity: Map<string, ActorActivity>): {
  total: number;
  active: number;
  quiet: number;
  unseen: number;
  staleDossiers: number;
  lastIntelAt: string | null;
} {
  let active = 0;
  let quiet = 0;
  let unseen = 0;
  let staleDossiers = 0;
  let lastIntelAt: string | null = null;

  for (const a of activity.values()) {
    if (a.signal === "active") active += 1;
    else if (a.signal === "quiet") quiet += 1;
    else unseen += 1;
    if (a.intelNewerThanDossier) staleDossiers += 1;
    if (a.lastSeenInIntel && (!lastIntelAt || a.lastSeenInIntel > lastIntelAt)) lastIntelAt = a.lastSeenInIntel;
  }

  return { total: activity.size, active, quiet, unseen, staleDossiers, lastIntelAt };
}
