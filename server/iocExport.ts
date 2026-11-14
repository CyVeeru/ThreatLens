/**
 * IoC export for SOC tooling. Turns the indicators extracted from findings into
 * the import formats each EDR / SIEM understands, so an engineer can load them
 * without hand-converting. Pure (no DB, no network) so it is unit tested.
 *
 * Field layouts follow each vendor's documented IOC import. Vendors change
 * these; the UI labels every export "review before import".
 */
import { IOC_EXPORT_PLATFORMS, type FindingIoCs, type IocExportPlatformId } from "@shared/schema";
import { isSecurityPublisherHost } from "./iocPublisherBlocklist";

export const IOC_PLATFORMS = IOC_EXPORT_PLATFORMS;
export type IocPlatformId = IocExportPlatformId;

export type IocType = "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email";
export interface IocRecord {
  type: IocType;
  value: string;
  /** Short label of the finding(s) this came from. */
  context: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
}
export interface IocFindingInput {
  title: string;
  severity?: string | null;
  iocs?: FindingIoCs | null;
}

export interface IocExportResult {
  filename: string;
  contentType: string;
  body: string;
  /** Indicators written, by type. */
  counts: Record<string, number>;
  total: number;
  /** Indicators dropped because the platform has no matching type. */
  unsupported: Record<string, number>;
}

const SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"] as const;

function normSeverity(s?: string | null): IocRecord["severity"] {
  const v = String(s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "informational";
}

/** Undo the defanging analysts use in reports: hxxp://, [.], (dot), [:] */
export function refang(raw: string): string {
  return raw
    .trim()
    .replace(/^hxxp/i, "http")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]|\[at\]/gi, "@")
    .replace(/\s+/g, "");
}

function isPrivateOrReservedV4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return (
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

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

const HASH_RE: Record<"md5" | "sha1" | "sha256", RegExp> = {
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
};
const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;

/** Merge indicators from many findings: refang, validate, drop private IPs and
 *  security-publisher hosts, dedupe by (type,value), keep the highest severity. */
export function collectIocs(findings: IocFindingInput[]): IocRecord[] {
  const out = new Map<string, IocRecord>();
  const add = (type: IocType, rawValue: string, f: IocFindingInput) => {
    const value = refang(rawValue);
    if (!value) return;
    let v = value;
    if (type === "ipv4") {
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || isPrivateOrReservedV4(v)) return;
    } else if (type === "ipv6") {
      if (!/^[0-9a-f:]+$/i.test(v) || !v.includes(":") || /^(::1|fe80|fc|fd)/i.test(v)) return;
      v = v.toLowerCase();
    } else if (type === "domain") {
      v = v.toLowerCase().replace(/\.$/, "");
      if (!DOMAIN_RE.test(v) || isSecurityPublisherHost(v)) return;
    } else if (type === "url") {
      if (!/^https?:\/\//i.test(v)) return;
      const h = hostOf(v);
      if (!h || isSecurityPublisherHost(h)) return;
    } else if (type === "email") {
      v = v.toLowerCase();
      if (!EMAIL_RE.test(v)) return;
    } else {
      v = v.toLowerCase();
      if (!HASH_RE[type].test(v)) return;
    }
    const key = `${type}|${v}`;
    const sev = normSeverity(f.severity);
    const prev = out.get(key);
    if (!prev) {
      out.set(key, { type, value: v, context: f.title.slice(0, 120), severity: sev });
    } else if (SEVERITY_ORDER.indexOf(sev) > SEVERITY_ORDER.indexOf(prev.severity)) {
      prev.severity = sev;
    }
  };
  for (const f of findings) {
    const i = f.iocs;
    if (!i) continue;
    for (const t of ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"] as const) {
      for (const val of i[t] ?? []) add(t, String(val), f);
    }
  }
  return Array.from(out.values());
}

const csvCell = (s: string) => (/[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
const csv = (rows: string[][]) => rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
const sevUpper = (s: IocRecord["severity"]) => (s === "informational" ? "INFO" : s.toUpperCase());
const sevTitle = (s: IocRecord["severity"]) => s.charAt(0).toUpperCase() + s.slice(1);

function tally(records: IocRecord[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const r of records) c[r.type] = (c[r.type] ?? 0) + 1;
  return c;
}

/** Split records into those a platform accepts and those it cannot represent. */
function partition(records: IocRecord[], supported: ReadonlySet<IocType>) {
  const ok = records.filter((r) => supported.has(r.type));
  const unsupported = tally(records.filter((r) => !supported.has(r.type)));
  return { ok, unsupported };
}

export function buildIocExport(
  platform: IocPlatformId,
  findings: IocFindingInput[],
  opts: { now?: Date; expireDays?: number } = {},
): IocExportResult {
  const now = opts.now ?? new Date();
  const expireDays = opts.expireDays ?? 90;
  const expiry = new Date(now.getTime() + expireDays * 86_400_000).toISOString();
  const stamp = now.toISOString().slice(0, 10);
  const all = collectIocs(findings);
  const meta = IOC_PLATFORMS.find((p) => p.id === platform)!;
  const filename = `threatlens-iocs-${platform}-${stamp}.${meta.ext}`;
  const finish = (
    ok: IocRecord[],
    unsupported: Record<string, number>,
    body: string,
    contentType: string,
  ): IocExportResult => ({
    filename,
    contentType,
    body,
    counts: tally(ok),
    total: ok.length,
    unsupported,
  });
  const desc = (r: IocRecord) => `ThreatLens: ${r.context}`.slice(0, 200);

  switch (platform) {
    case "crowdstrike": {
      // Falcon IOC Management API shape (POST /iocs/entities/indicators/v1).
      const typeMap: Partial<Record<IocType, string>> = {
        ipv4: "ipv4",
        ipv6: "ipv6",
        domain: "domain",
        md5: "md5",
        sha256: "sha256",
      };
      const { ok, unsupported } = partition(all, new Set(Object.keys(typeMap) as IocType[]));
      const indicators = ok.map((r) => ({
        type: typeMap[r.type],
        value: r.value,
        action: r.severity === "critical" || r.severity === "high" ? "prevent" : "detect",
        severity: r.severity,
        platforms: ["windows", "mac", "linux"],
        applied_globally: true,
        description: desc(r),
        source: "ThreatLens",
        expiration: expiry,
        tags: ["threatlens"],
      }));
      return finish(
        ok,
        unsupported,
        JSON.stringify({ comment: "Imported from ThreatLens", indicators }, null, 2),
        "application/json; charset=utf-8",
      );
    }
    case "defender": {
      const typeMap: Partial<Record<IocType, string>> = {
        ipv4: "IpAddress",
        ipv6: "IpAddress",
        domain: "DomainName",
        url: "Url",
        md5: "FileMd5",
        sha1: "FileSha1",
        sha256: "FileSha256",
      };
      const { ok, unsupported } = partition(all, new Set(Object.keys(typeMap) as IocType[]));
      const header = [
        "IndicatorType",
        "IndicatorValue",
        "ExpirationTime",
        "Action",
        "Severity",
        "Title",
        "Description",
        "RecommendedActions",
        "RbacGroups",
        "Category",
        "MitreTechniques",
        "GenerateAlert",
      ];
      const rows = ok.map((r) => [
        typeMap[r.type]!,
        r.value,
        expiry,
        r.severity === "critical" || r.severity === "high" ? "AlertAndBlock" : "Alert",
        r.severity === "informational" ? "Informational" : sevTitle(r.severity),
        `ThreatLens ${r.type} indicator`,
        desc(r),
        "Investigate affected devices and block if confirmed malicious.",
        "",
        "",
        "",
        "TRUE",
      ]);
      return finish(ok, unsupported, csv([header, ...rows]), "text/csv; charset=utf-8");
    }
    case "sentinelone": {
      const typeMap: Partial<Record<IocType, string>> = {
        ipv4: "IPV4",
        ipv6: "IPV6",
        domain: "DNS",
        url: "URL",
        md5: "MD5",
        sha1: "SHA1",
        sha256: "SHA256",
      };
      const { ok, unsupported } = partition(all, new Set(Object.keys(typeMap) as IocType[]));
      const data = ok.map((r) => ({
        type: typeMap[r.type],
        value: r.value,
        name: `ThreatLens ${r.type}`,
        description: desc(r),
        method: "EQUALS",
        source: "ThreatLens",
        validUntil: expiry,
        creationTime: now.toISOString(),
        externalId: `threatlens:${r.type}:${r.value}`.slice(0, 200),
      }));
      return finish(ok, unsupported, JSON.stringify({ data }, null, 2), "application/json; charset=utf-8");
    }
    case "cortex_xdr": {
      // Cortex XDR IOC CSV: hashes, IPs, domains. Other types are not importable.
      const typeMap: Partial<Record<IocType, string>> = {
        ipv4: "IP",
        ipv6: "IP",
        domain: "DOMAIN_NAME",
        md5: "HASH",
        sha256: "HASH",
      };
      const { ok, unsupported } = partition(all, new Set(Object.keys(typeMap) as IocType[]));
      const header = [
        "indicator",
        "type",
        "severity",
        "expiration_date",
        "comment",
        "reputation",
        "reliability",
        "class",
        "vendor.name",
        "vendor.reliability",
        "vendor.reputation",
      ];
      const expMs = String(Date.parse(expiry));
      const rows = ok.map((r) => [
        r.value,
        typeMap[r.type]!,
        sevUpper(r.severity),
        expMs,
        desc(r),
        "BAD",
        "A",
        "Malware",
        "ThreatLens",
        "A",
        "BAD",
      ]);
      return finish(ok, unsupported, csv([header, ...rows]), "text/csv; charset=utf-8");
    }
    case "elastic": {
      const { ok, unsupported } = partition(
        all,
        new Set<IocType>(["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]),
      );
      const lines = ok.map((r) => {
        const ind: Record<string, unknown> = {
          type:
            r.type === "ipv4" || r.type === "ipv6"
              ? "ipv4-addr"
              : r.type === "domain"
                ? "domain-name"
                : r.type === "url"
                  ? "url"
                  : r.type === "email"
                    ? "email-addr"
                    : "file",
          description: desc(r),
          provider: "ThreatLens",
          confidence: r.severity === "critical" || r.severity === "high" ? "High" : "Medium",
        };
        if (r.type === "ipv4" || r.type === "ipv6") {
          ind.type = r.type === "ipv6" ? "ipv6-addr" : "ipv4-addr";
          ind.ip = r.value;
        } else if (r.type === "domain") ind.url = { domain: r.value };
        else if (r.type === "url") ind.url = { full: r.value, original: r.value };
        else if (r.type === "email") ind.email = { address: r.value };
        else ind.file = { hash: { [r.type]: r.value } };
        return JSON.stringify({
          "@timestamp": now.toISOString(),
          event: { category: "threat", kind: "enrichment", type: "indicator" },
          threat: { indicator: ind, feed: { name: "ThreatLens" } },
        });
      });
      return finish(
        ok,
        unsupported,
        lines.join("\n") + (lines.length ? "\n" : ""),
        "application/x-ndjson; charset=utf-8",
      );
    }
    case "splunk": {
      const header = ["type", "value", "severity", "source", "first_seen", "context"];
      const rows = all.map((r) => [r.type, r.value, r.severity, "ThreatLens", now.toISOString(), r.context]);
      return finish(all, {}, csv([header, ...rows]), "text/csv; charset=utf-8");
    }
    case "generic": {
      const groups = new Map<string, string[]>();
      for (const r of all) groups.set(r.type, [...(groups.get(r.type) ?? []), r.value]);
      const body = Array.from(groups.entries())
        .map(([t, vals]) => `# ${t} (${vals.length})\n${vals.join("\n")}`)
        .join("\n\n");
      return finish(all, {}, body ? body + "\n" : "", "text/plain; charset=utf-8");
    }
  }
}
