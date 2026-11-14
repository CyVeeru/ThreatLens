import { beforeAll, describe, expect, it, vi } from "vitest";

// A real SQLite (in memory) with the production schema, instead of the workspace DB.
vi.mock("../server/storage", async () => {
  const { default: Database } = await import("better-sqlite3");
  const { ensureTierBSchema } = await import("../server/tierBSchema");
  const sqlite = new Database(":memory:");
  // Minimal base table: the Tier B migration extends it with review columns.
  sqlite.exec("CREATE TABLE osint_findings (id TEXT PRIMARY KEY, tenant_id TEXT, status TEXT)");
  ensureTierBSchema(sqlite);
  return { sqlite, storage: {} };
});
vi.mock("../server/sourceFetch", () => ({ fetchFeedPinned: vi.fn() }));

import { sqlite } from "../server/storage";
import { coverageFor, parseSigmaRule, searchRules, storeRules } from "../server/ruleLibrary";
import { IOC_FEEDS, isBulkDumpEvent, parseMispEvent, storeFeed } from "../server/iocFeeds";
import { parseYaraFile } from "../server/ruleLibrary";
import { attackMatrix, attackTechnique, cleanAttackText, parseAttackBundle, storeAttack } from "../server/attackMatrix";

const rule = (id: string, title: string, tags: string[], extra = "") =>
  `title: ${title}
id: ${id}
status: test
description: ${title}. ${extra}
author: Test Author
date: 2025-01-01
tags:
${tags.map((t) => `    - ${t}`).join("\n")}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\x.exe'
    condition: selection
level: high
`;

describe("rule library + coverage", () => {
  beforeAll(() => {
    const parsed = [
      rule("11111111-1111-1111-1111-111111111111", "Log4Shell exploitation", [
        "attack.initial-access",
        "attack.t1190",
        "cve.2021-44228",
      ]),
      rule("22222222-2222-2222-2222-222222222222", "Certutil download", ["attack.t1105"]),
      rule("33333333-3333-3333-3333-333333333333", "PowerShell encoded command", ["attack.t1059.001"]),
    ].map((t) => parseSigmaRule(t)!);
    expect(parsed.every(Boolean)).toBe(true);
    storeRules(parsed);
  });

  it("is unknown when the library is empty or the finding has no CVE/technique", () => {
    expect(coverageFor({ cveIds: [], attackTechniques: null }).verdict).toBe("unknown");
    expect(coverageFor({ cveIds: [], title: "Nothing relevant here" }).verdict).toBe("unknown");
  });

  it("covered: a rule references the CVE directly", () => {
    const r = coverageFor({ cveIds: ["cve-2021-44228"], attackTechniques: [] });
    expect(r.verdict).toBe("covered");
    expect(r.cveRules.map((x) => x.title)).toEqual(["Log4Shell exploitation"]);
  });

  it("partial: only the ATT&CK behaviour is covered, parent and sub-technique both match", () => {
    const a = coverageFor({ cveIds: ["CVE-2030-0001"], attackTechniques: [{ id: "T1105" }] });
    expect(a.verdict).toBe("partial");
    expect(a.techniqueRules[0].title).toBe("Certutil download");
    const b = coverageFor({ cveIds: [], attackTechniques: [{ id: "T1059" }] });
    expect(b.techniqueRules.map((x) => x.title)).toContain("PowerShell encoded command");
    const c = coverageFor({ cveIds: [], attackTechniques: [{ id: "T1059.001" }] });
    expect(c.verdict).toBe("partial");
  });

  it("gap: nothing matches", () => {
    const r = coverageFor({ cveIds: ["CVE-2030-0002"], attackTechniques: [{ id: "T1566" }] });
    expect(r.verdict).toBe("gap");
    expect(r.cveRules).toHaveLength(0);
    expect(r.techniqueRules).toHaveLength(0);
  });

  it("search filters by text, technique and level, and escapes wildcards", () => {
    expect(searchRules({ q: "certutil" }).total).toBe(1);
    expect(searchRules({ technique: "T1059" }).total).toBe(1);
    expect(searchRules({ level: "critical" }).total).toBe(0);
    expect(searchRules({ q: "%" }).total).toBe(0);
    expect(searchRules({}).total).toBe(3);
  });
});

describe("IoC storage", () => {
  it("upserts, keeps first_seen, and prunes rows a feed no longer lists", () => {
    const feed = IOC_FEEDS[0].id;
    const items = [
      {
        type: "ipv4" as const,
        value: "203.0.114.1",
        name: "QakBot",
        confidence: 90,
        firstSeen: "2025-01-01T00:00:00.000Z",
      },
      { type: "ipv4" as const, value: "203.0.114.2", name: "Emotet", confidence: 70 },
    ];
    storeFeed(feed, items, new Date("2026-01-01T00:00:00Z"));
    storeFeed(feed, [items[0]], new Date("2026-01-02T00:00:00Z"));
    const rows = sqlite.prepare("SELECT value, first_seen FROM ioc_intel WHERE source = ?").all(feed) as any[];
    expect(rows.map((r) => r.value)).toEqual(["203.0.114.1"]);
    expect(rows[0].first_seen).toBe("2025-01-01T00:00:00.000Z");
    // An empty fetch must never wipe good data.
    storeFeed(feed, [], new Date("2026-01-03T00:00:00Z"));
    expect((sqlite.prepare("SELECT COUNT(*) c FROM ioc_intel").get() as any).c).toBe(1);
  });
});

describe("technique inference fallback", () => {
  it("infers techniques from text when none were extracted, and flags them as inferred", () => {
    const r = coverageFor({
      cveIds: [],
      title: "Attackers use certutil -urlcache downloads a payload via PowerShell",
      attackTechniques: [],
    });
    expect(r.techniquesInferred).toBe(true);
    expect(r.techniques).toEqual(expect.arrayContaining(["T1105", "T1059.001"]));
    expect(r.verdict).toBe("partial");
  });
  it("prefers real AI-extracted techniques over inference", () => {
    const r = coverageFor({ cveIds: [], title: "uses powershell", attackTechniques: [{ id: "T1105" }] });
    expect(r.techniquesInferred).toBe(false);
    expect(r.techniques).toEqual(["T1105"]);
  });
});

describe("MISP events (CIRCL OSINT)", () => {
  it("keeps only actionable, valid indicators, named after the event", () => {
    const r = parseMispEvent({
      info: "Kali365 PhaaS kit abused in the wild",
      date: "2026-04-24",
      Attribute: [
        { type: "domain", value: "evil.example", to_ids: true },
        { type: "ip-dst", value: "203.0.114.9", to_ids: true },
        { type: "ip-dst", value: "10.0.0.1", to_ids: true },
        { type: "sha256", value: "A".repeat(64), to_ids: true },
        { type: "filename|sha1", value: "x.exe|" + "b".repeat(40), to_ids: true },
        { type: "url", value: "https://www.cisa.gov/x", to_ids: true },
        { type: "domain", value: "context-only.example", to_ids: false },
        { type: "comment", value: "text", to_ids: false },
      ],
      Object: [{ Attribute: [{ type: "md5", value: "c".repeat(32), to_ids: true }] }],
    });
    expect(r.map((x) => `${x.type}:${x.value}`).sort()).toEqual([
      `domain:evil.example`,
      `ipv4:203.0.114.9`,
      `md5:${"c".repeat(32)}`,
      `sha1:${"b".repeat(40)}`,
      `sha256:${"a".repeat(64)}`,
    ]);
    expect(r.every((x) => x.name === "Kali365 PhaaS kit abused in the wild")).toBe(true);
  });
});

describe("YARA parsing", () => {
  const yara = `rule Win32_Backdoor_Foo : tag1 {
  meta:
    description = "Detects Foo backdoor (CVE-2023-1234)"
    author = "ReversingLabs"
    date = "2026-01-02"
    reference = "https://example.com/foo"
    mitre_att = "T1055"
  strings:
    $a = "evil"
  condition:
    $a
}
rule Second { condition: true }
`;
  it("extracts name, meta, techniques, CVEs and category from the path", () => {
    const r = parseYaraFile(yara, "yara/backdoor/Win32.Backdoor.Foo.yara")!;
    expect(r.id).toBe("reversinglabs-yara:Win32.Backdoor.Foo");
    expect(r.title).toContain("(+1 more)");
    expect(r).toMatchObject({
      source: "reversinglabs-yara",
      product: "yara",
      category: "backdoor",
      author: "ReversingLabs",
    });
    expect(r.techniques).toEqual(["T1055"]);
    expect(r.cves).toEqual(["CVE-2023-1234"]);
    expect(parseYaraFile("just text", "x.yara")).toBeNull();
  });
});

describe("ATT&CK matrix", () => {
  const bundle = {
    objects: [
      {
        type: "x-mitre-tactic",
        id: "tac-1",
        name: "Execution",
        x_mitre_shortname: "execution",
        external_references: [{ source_name: "mitre-attack", external_id: "TA0002" }],
      },
      {
        type: "x-mitre-tactic",
        id: "tac-0",
        name: "Initial Access",
        x_mitre_shortname: "initial-access",
        external_references: [{ source_name: "mitre-attack", external_id: "TA0001" }],
      },
      { type: "x-mitre-matrix", tactic_refs: ["tac-0", "tac-1"], x_mitre_version: "2.0" },
      { type: "x-mitre-collection", x_mitre_version: "18.1" },
      {
        type: "attack-pattern",
        name: "Command and Scripting Interpreter",
        description: "Adversaries abuse [interpreters](https://x.example) (Citation: Foo).",
        x_mitre_detection: "Monitor command execution.",
        x_mitre_platforms: ["Windows"],
        external_references: [
          { source_name: "mitre-attack", external_id: "T1059", url: "https://attack.mitre.org/techniques/T1059" },
        ],
        kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }],
      },
      {
        type: "attack-pattern",
        id: "ap-ps",
        name: "PowerShell",
        x_mitre_is_subtechnique: true,
        external_references: [{ source_name: "mitre-attack", external_id: "T1059.001" }],
        kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "execution" }],
      },
      {
        type: "attack-pattern",
        name: "Phishing",
        external_references: [{ source_name: "mitre-attack", external_id: "T1566" }],
        kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "initial-access" }],
      },
      {
        type: "x-mitre-analytic",
        id: "an-1",
        description: "Monitor process creation for (Citation: X) powershell.exe with encoded arguments.",
        x_mitre_platforms: ["Windows"],
      },
      {
        type: "x-mitre-detection-strategy",
        id: "ds-1",
        name: "Behavioral detection of PowerShell abuse",
        x_mitre_analytic_refs: ["an-1"],
        external_references: [
          {
            source_name: "mitre-attack",
            external_id: "DET0001",
            url: "https://attack.mitre.org/detectionstrategies/DET0001",
          },
        ],
      },
      { type: "relationship", relationship_type: "detects", source_ref: "ds-1", target_ref: "ap-ps" },
      {
        type: "attack-pattern",
        name: "Old thing",
        revoked: true,
        external_references: [{ source_name: "mitre-attack", external_id: "T9999" }],
        kill_chain_phases: [],
      },
    ],
  };

  it("parses tactics in matrix order, drops revoked items and cleans text", () => {
    const p = parseAttackBundle(bundle);
    expect(p.tactics.map((t) => t.shortname)).toEqual(["initial-access", "execution"]);
    expect(p.techniques.map((t) => t.id).sort()).toEqual(["T1059", "T1059.001", "T1566"]);
    expect(p.techniques.find((t) => t.id === "T1059.001")).toMatchObject({ isSub: true, parent: "T1059" });
    expect(p.version).toBe("18.1");
    expect(cleanAttackText("See [x](https://a.b) (Citation: Z) now")).toBe("See x now");
  });

  it("joins technique rows with rule counts from the library", () => {
    storeAttack(parseAttackBundle(bundle));
    const m = attackMatrix();
    expect(m.tactics.map((t) => t.shortname)).toEqual(["initial-access", "execution"]);
    const exec = m.tactics.find((t) => t.shortname === "execution")!;
    expect(exec.techniques).toHaveLength(1); // sub-techniques are nested, not columns
    expect(exec.techniques[0]).toMatchObject({ id: "T1059", subCount: 1, ruleCount: 1 }); // PowerShell rule rolls up
    expect(exec.techniques[0].subs).toEqual(["T1059.001 PowerShell"]); // lets the UI filter find sub-techniques
    expect(m.totals).toMatchObject({ techniques: 2, covered: 1, uncovered: 1 });
    const sub = attackTechnique("T1059.001")!;
    expect(sub.detections).toEqual([
      {
        id: "DET0001",
        name: "Behavioral detection of PowerShell abuse",
        url: "https://attack.mitre.org/detectionstrategies/DET0001",
        analytics: [
          { platform: "Windows", description: "Monitor process creation for powershell.exe with encoded arguments." },
        ],
      },
    ]);
    const t = attackTechnique("t1059")!;
    expect(t.ruleCount).toBe(1);
    expect(t.subTechniques).toEqual([{ id: "T1059.001", name: "PowerShell", ruleCount: 1 }]);
    expect(t.tactics[0].name).toBe("Execution");
    expect(attackTechnique("T0000")).toBeNull();
  });
});

describe("CIRCL bulk-dump filter", () => {
  it("skips automated daily IOC dumps but keeps named campaigns", () => {
    expect(isBulkDumpEvent("Maltrail IOC for 2026-07-29")).toBe(true);
    expect(isBulkDumpEvent("Daily IOCs for 2026-08-01")).toBe(true);
    expect(isBulkDumpEvent("KRVTZ-NET IDS alerts for 2026-05-21")).toBe(true);
    expect(isBulkDumpEvent("NEW KALI365 PHAAS KIT BEING ABUSED IN THE WILD")).toBe(false);
    expect(isBulkDumpEvent("MoustachedBouncer: Espionage against foreign diplomats")).toBe(false);
    expect(isBulkDumpEvent("Phishing Campaign Targeting Hotel Customers in Luxembourg")).toBe(false);
  });
});
