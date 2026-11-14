/**
 * Named IoC feeds: open sources that publish indicators together with the
 * malware / framework they belong to. Parsers are pure (tested with fixtures);
 * sync() does the network fetch and the upsert.
 *
 * Each feed is isolated — one failing source never blocks the others, and the
 * last error per feed is stored for the UI.
 */
import { sqlite } from "./storage";
import { fetchFeedPinned } from "./sourceFetch";
import { isSecurityPublisherHost } from "./iocPublisherBlocklist";

export type IntelIocType = "ipv4" | "domain" | "url" | "sha256" | "sha1" | "md5";
export interface IntelIoc {
  type: IntelIocType;
  value: string;
  /** Malware family, C2 framework or campaign the indicator belongs to. */
  name: string;
  port?: number | null;
  status?: string | null;
  firstSeen?: string | null;
  lastSeen?: string | null;
  confidence: number;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
function validPublicIpv4(ip: string): boolean {
  if (!IPV4.test(ip)) return false;
  const p = ip.split(".").map(Number);
  if (p.some((n) => n > 255)) return false;
  const [a, b] = p;
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

const toIso = (s?: string | null): string | null => {
  if (!s) return null;
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : s.replace(" ", "T") + "Z");
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};

/** abuse.ch Feodo Tracker — botnet C2 servers with the malware family. */
export function parseFeodo(json: string): IntelIoc[] {
  let rows: any[];
  try {
    const parsed = JSON.parse(json);
    rows = Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
  const out: IntelIoc[] = [];
  for (const r of rows) {
    const ip = String(r?.ip_address ?? "").trim();
    if (!validPublicIpv4(ip)) continue;
    out.push({
      type: "ipv4",
      value: ip,
      name: String(r.malware || "Botnet C2").slice(0, 80),
      port: Number.isInteger(r.port) ? r.port : null,
      status: r.status ? String(r.status) : null,
      firstSeen: toIso(r.first_seen),
      lastSeen: toIso(r.last_online),
      confidence: r.status === "online" ? 90 : 70,
    });
  }
  return out;
}

/** C2IntelFeeds — `#ip,ioc` CSV; the second column names the framework. */
export function parseC2Intel(csv: string): IntelIoc[] {
  const out: IntelIoc[] = [];
  for (const raw of csv.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const comma = line.indexOf(",");
    const ip = (comma < 0 ? line : line.slice(0, comma)).trim();
    if (!validPublicIpv4(ip)) continue;
    const label =
      comma < 0
        ? ""
        : line
            .slice(comma + 1)
            .replace(/^"|"$/g, "")
            .trim();
    const name =
      label
        .replace(/^possible\s+/i, "")
        .replace(/\s+c2\s+ip$/i, " C2")
        .trim() || "C2 server";
    out.push({ type: "ipv4", value: ip, name: name.slice(0, 80), confidence: 60 });
  }
  return out;
}

/** OpenPhish community feed — one phishing URL per line. */
export function parseOpenPhish(text: string): IntelIoc[] {
  const out: IntelIoc[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const url = raw.trim();
    if (!/^https?:\/\/[^\s]+$/i.test(url) || url.length > 2000) continue;
    out.push({ type: "url", value: url, name: "Phishing", confidence: 75 });
  }
  return out;
}

const DOMAIN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const HASHES: Array<[IntelIocType, RegExp]> = [
  ["sha256", /^[a-f0-9]{64}$/i],
  ["sha1", /^[a-f0-9]{40}$/i],
  ["md5", /^[a-f0-9]{32}$/i],
];

/** One MISP event (a named report/campaign) -> actionable indicators only (to_ids). */
export function parseMispEvent(ev: any): IntelIoc[] {
  if (!ev || typeof ev !== "object") return [];
  const name =
    String(ev.info ?? "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 90) || "MISP event";
  const date = toIso(typeof ev.date === "string" ? ev.date : null);
  const attrs: any[] = [...(Array.isArray(ev.Attribute) ? ev.Attribute : [])];
  for (const o of Array.isArray(ev.Object) ? ev.Object : [])
    if (Array.isArray(o?.Attribute)) attrs.push(...o.Attribute);
  const out: IntelIoc[] = [];
  const push = (type: IntelIocType, value: string) => {
    if (out.length < 400) out.push({ type, value, name, firstSeen: date, lastSeen: date, confidence: 55 });
  };
  for (const a of attrs) {
    if (!a || a.to_ids === false) continue;
    const kind = String(a.type ?? "");
    const parts = String(a.value ?? "")
      .trim()
      .split("|");
    const val = (kind.includes("|") ? parts[parts.length - 1] : parts[0]).trim();
    if (!val) continue;
    const base = kind.includes("|") ? kind.split("|").pop()! : kind;
    if (base === "ip-dst" || base === "ip-src") {
      if (validPublicIpv4(val)) push("ipv4", val);
    } else if (base === "domain" || base === "hostname") {
      const d = val.toLowerCase().replace(/\.$/, "");
      if (DOMAIN.test(d) && !isSecurityPublisherHost(d)) push("domain", d);
    } else if (base === "url") {
      if (/^https?:\/\/[^\s]+$/i.test(val) && val.length < 2000) {
        try {
          if (!isSecurityPublisherHost(new URL(val).hostname)) push("url", val);
        } catch {
          /* skip malformed */
        }
      }
    } else if (base === "sha256" || base === "sha1" || base === "md5") {
      const h = HASHES.find(([t, re]) => t === base && re.test(val));
      if (h) push(h[0], val.toLowerCase());
    }
  }
  return out;
}

/** Automated daily dumps (e.g. "Maltrail IOC for 2026-07-29") are untargeted bulk lists, not named campaigns. */
export function isBulkDumpEvent(info: unknown): boolean {
  const t = String(info ?? "");
  // A title that is just a label plus a date ("… for 2026-05-21") is a generated dump.
  return (
    /^\s*maltrail\b/i.test(t) ||
    /\b(?:for|of|on)\s+\d{4}-\d{2}-\d{2}\s*$/i.test(t) ||
    /\b(?:ids|ioc|iocs|alerts?|indicators?|blocklist)\b.*\b\d{4}-\d{2}-\d{2}\b/i.test(t) ||
    /\b(?:daily|weekly)\s+(?:ioc|blocklist|feed)\b/i.test(t)
  );
}

export async function fetchCirclOsint(): Promise<IntelIoc[]> {
  const base = "https://www.circl.lu/doc/misp/feed-osint/";
  const m = await fetchFeedPinned(base + "manifest.json", { maxBytes: 8_000_000, timeoutMs: 60_000 });
  if (!m || m.status !== 200) throw new Error("manifest fetch failed");
  const manifest = JSON.parse(m.body.toString("utf8")) as Record<string, { date?: string; info?: string }>;
  const latest = Object.entries(manifest)
    .filter(([, v]) => !isBulkDumpEvent(v?.info))
    .sort((a, b) => String(b[1]?.date ?? "").localeCompare(String(a[1]?.date ?? "")))
    .slice(0, 16)
    .map(([uuid]) => uuid);
  const out: IntelIoc[] = [];
  let events = 0;
  for (let i = 0; i < latest.length; i += 4) {
    await Promise.all(
      latest.slice(i, i + 4).map(async (uuid) => {
        const r = await fetchFeedPinned(`${base}${uuid}.json`, { maxBytes: 6_000_000, timeoutMs: 40_000 });
        if (!r || r.status !== 200) return;
        try {
          out.push(...parseMispEvent(JSON.parse(r.body.toString("utf8")).Event));
          events += 1;
        } catch {
          /* skip unreadable event */
        }
      }),
    );
  }
  if (events === 0) throw new Error("no events could be fetched");
  return out;
}

export interface IocFeedDef {
  id: string;
  label: string;
  url: string;
  homepage: string;
  parse: (body: string) => IntelIoc[];
  /** Feeds that need several requests supply their own fetch instead of url/parse. */
  run?: () => Promise<IntelIoc[]>;
}

export const IOC_FEEDS: IocFeedDef[] = [
  {
    id: "feodo",
    label: "abuse.ch Feodo Tracker",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    homepage: "https://feodotracker.abuse.ch/",
    parse: parseFeodo,
  },
  {
    id: "c2intel",
    label: "C2IntelFeeds (30 day C2 IPs)",
    url: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
    homepage: "https://github.com/drb-ra/C2IntelFeeds",
    parse: parseC2Intel,
  },
  {
    id: "openphish",
    label: "OpenPhish community feed",
    url: "https://openphish.com/feed.txt",
    homepage: "https://openphish.com/",
    parse: parseOpenPhish,
  },
  {
    id: "circl-osint",
    label: "CIRCL OSINT feed (named campaigns: hashes, domains, IPs)",
    url: "https://www.circl.lu/doc/misp/feed-osint/",
    homepage: "https://www.circl.lu/doc/misp/feed-osint/",
    parse: () => [],
    run: fetchCirclOsint,
  },
];

export interface SyncResult {
  feed: string;
  ok: boolean;
  fetched: number;
  error: string | null;
}

export function setSyncState(key: string, count: number, error: string | null): void {
  sqlite
    .prepare(
      `INSERT INTO intel_sync_state (key, last_run, item_count, last_error) VALUES (?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET last_run = excluded.last_run, item_count = excluded.item_count, last_error = excluded.last_error`,
    )
    .run(key, new Date().toISOString(), count, error);
}

export function getSyncState(key: string): { lastRun: string | null; itemCount: number; lastError: string | null } {
  const r = sqlite
    .prepare("SELECT last_run, item_count, last_error FROM intel_sync_state WHERE key = ?")
    .get(key) as any;
  return { lastRun: r?.last_run ?? null, itemCount: r?.item_count ?? 0, lastError: r?.last_error ?? null };
}

/** Insert or refresh indicators for one feed, then drop rows the feed no longer lists. */
export function storeFeed(feedId: string, items: IntelIoc[], now = new Date()): number {
  const ts = now.toISOString();
  const up = sqlite.prepare(`
    INSERT INTO ioc_intel (ioc_type, value, name, source, port, status, first_seen, last_seen, confidence, fetched_at)
    VALUES (@type, @value, @name, @source, @port, @status, @first_seen, @last_seen, @confidence, @fetched_at)
    ON CONFLICT(ioc_type, value, source) DO UPDATE SET
      name = excluded.name, port = excluded.port, status = excluded.status,
      first_seen = COALESCE(ioc_intel.first_seen, excluded.first_seen),
      last_seen = COALESCE(excluded.last_seen, ioc_intel.last_seen),
      confidence = excluded.confidence, fetched_at = excluded.fetched_at`);
  const tx = sqlite.transaction(() => {
    for (const i of items) {
      up.run({
        type: i.type,
        value: i.value,
        name: i.name,
        source: feedId,
        port: i.port ?? null,
        status: i.status ?? null,
        first_seen: i.firstSeen ?? ts,
        last_seen: i.lastSeen ?? ts,
        confidence: i.confidence,
        fetched_at: ts,
      });
    }
    // Only prune when the feed returned something, so an empty/blocked response
    // can never wipe good data.
    if (items.length > 0) sqlite.prepare("DELETE FROM ioc_intel WHERE source = ? AND fetched_at < ?").run(feedId, ts);
  });
  tx();
  return items.length;
}

export async function syncIocFeed(feed: IocFeedDef): Promise<SyncResult> {
  try {
    let items: IntelIoc[];
    if (feed.run) {
      items = await feed.run();
    } else {
      const res = await fetchFeedPinned(feed.url, { maxBytes: 16_000_000, timeoutMs: 30_000 });
      if (!res || res.status !== 200) throw new Error(`fetch failed (${res ? "HTTP " + res.status : "no response"})`);
      items = feed.parse(res.body.toString("utf8"));
    }
    if (items.length === 0) throw new Error("feed returned no usable indicators");
    storeFeed(feed.id, items);
    setSyncState(`ioc:${feed.id}`, items.length, null);
    return { feed: feed.id, ok: true, fetched: items.length, error: null };
  } catch (e: any) {
    const error = String(e?.message || e).slice(0, 300);
    const prev = getSyncState(`ioc:${feed.id}`);
    setSyncState(`ioc:${feed.id}`, prev.itemCount, error);
    return { feed: feed.id, ok: false, fetched: 0, error };
  }
}

export async function syncAllIocFeeds(): Promise<SyncResult[]> {
  return Promise.all(IOC_FEEDS.map(syncIocFeed));
}
