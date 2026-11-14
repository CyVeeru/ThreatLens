import { describe, expect, it } from "vitest";
import { buildIocExport, collectIocs, refang } from "../server/iocExport";

const NOW = new Date("2026-11-14T00:00:00.000Z");
const finding = (iocs: any, severity = "high", title = "Campaign X") => ({ title, severity, iocs });

const sample = [
  finding({
    ipv4: ["203.0.113.7", "10.0.0.5", "203.0.113.7"],
    domain: ["evil[.]example", "www.cisa.gov"],
    url: ["hxxps://evil[.]example/payload.bin"],
    sha256: ["A".repeat(64)],
    md5: ["not-a-hash"],
    email: ["bad@evil.example"],
  }),
  finding({ ipv4: ["203.0.113.7"], sha1: ["b".repeat(40)] }, "critical", "Second report"),
];

describe("IoC collection", () => {
  it("refangs common defanging", () => {
    expect(refang("hxxps://evil[.]example/a")).toBe("https://evil.example/a");
    expect(refang("a[@]b(dot)com")).toBe("a@b.com");
  });

  it("dedupes, validates, drops private IPs and publisher hosts, keeps highest severity", () => {
    const r = collectIocs(sample);
    const ips = r.filter((x) => x.type === "ipv4");
    expect(ips).toHaveLength(1);
    expect(ips[0].severity).toBe("critical");
    expect(r.find((x) => x.value === "10.0.0.5")).toBeUndefined();
    expect(r.find((x) => x.value === "www.cisa.gov")).toBeUndefined();
    expect(r.find((x) => x.value === "not-a-hash")).toBeUndefined();
    expect(r.find((x) => x.type === "domain")?.value).toBe("evil.example");
    expect(r.find((x) => x.type === "url")?.value).toBe("https://evil.example/payload.bin");
    expect(r.find((x) => x.type === "sha256")?.value).toBe("a".repeat(64));
  });
});

describe("per-platform export", () => {
  it("CrowdStrike: JSON indicators, prevent for high+, no URL support", () => {
    const out = buildIocExport("crowdstrike", sample, { now: NOW });
    const body = JSON.parse(out.body);
    expect(body.indicators.every((i: any) => ["ipv4", "domain", "sha256", "md5", "ipv6"].includes(i.type))).toBe(true);
    expect(body.indicators.find((i: any) => i.value === "203.0.113.7").action).toBe("prevent");
    expect(out.unsupported.url).toBe(1);
    expect(out.filename).toBe("threatlens-iocs-crowdstrike-2026-11-14.json");
  });

  it("Defender: CSV with the documented header and indicator types", () => {
    const out = buildIocExport("defender", sample, { now: NOW });
    const lines = out.body.trim().split("\r\n");
    expect(lines[0]).toBe(
      "IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert",
    );
    expect(out.body).toContain("IpAddress,203.0.113.7");
    expect(out.body).toContain("FileSha1,");
    expect(out.body).toContain("Url,https://evil.example/payload.bin");
    expect(out.unsupported.email).toBe(1);
  });

  it("SentinelOne: type names and EQUALS method", () => {
    const body = JSON.parse(buildIocExport("sentinelone", sample, { now: NOW }).body);
    expect(body.data.map((d: any) => d.type).sort()).toContain("DNS");
    expect(body.data.every((d: any) => d.method === "EQUALS")).toBe(true);
  });

  it("Cortex XDR: CSV, hashes/IPs/domains only", () => {
    const out = buildIocExport("cortex_xdr", sample, { now: NOW });
    expect(out.body.split("\r\n")[0].startsWith("indicator,type,severity")).toBe(true);
    expect(out.body).toContain("203.0.113.7,IP,CRITICAL");
    expect(out.unsupported.url).toBe(1);
    expect(out.unsupported.sha1).toBe(1);
  });

  it("Elastic: one valid JSON document per line", () => {
    const out = buildIocExport("elastic", sample, { now: NOW });
    const docs = out.body
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(docs).toHaveLength(out.total);
    expect(docs.every((d) => d.event.kind === "enrichment" && d.threat.indicator)).toBe(true);
  });

  it("Splunk and generic include everything; CSV cells are escaped", () => {
    const sp = buildIocExport("splunk", [finding({ domain: ["a.example"] }, "low", 'Has "quotes", and commas')], {
      now: NOW,
    });
    expect(sp.body).toContain('"Has ""quotes"", and commas"');
    const g = buildIocExport("generic", sample, { now: NOW });
    expect(g.total).toBe(
      g.counts.ipv4 + g.counts.domain + g.counts.url + g.counts.sha256 + g.counts.sha1 + g.counts.email,
    );
    expect(g.body).toContain("# ipv4 (1)");
  });

  it("returns an empty export for findings without indicators", () => {
    expect(buildIocExport("defender", [finding({})], { now: NOW }).total).toBe(0);
  });
});
