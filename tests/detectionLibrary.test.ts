import { describe, expect, it, vi } from "vitest";

// The parsers are pure; keep the workspace database out of the test process.
vi.mock("../server/storage", () => ({ sqlite: {}, storage: {} }));
vi.mock("../server/sourceFetch", () => ({ fetchFeedPinned: vi.fn() }));

import { parseC2Intel, parseFeodo, parseOpenPhish } from "../server/iocFeeds";
import { parseSigmaRule, parseSigmaZip, techniqueFromTag } from "../server/ruleLibrary";
import JSZip from "jszip";

describe("IoC feed parsers", () => {
  it("Feodo: keeps public IPs with malware family, port and status", () => {
    const json = JSON.stringify([
      {
        ip_address: "50.16.16.211",
        port: 443,
        status: "online",
        malware: "QakBot",
        first_seen: "2024-01-02 03:04:05",
        last_online: "2026-03-07",
      },
      { ip_address: "10.1.1.1", port: 80, status: "online", malware: "Emotet" },
      { ip_address: "not-an-ip", malware: "x" },
    ]);
    const r = parseFeodo(json);
    expect(r).toHaveLength(1);
    expect(r[0]).toMatchObject({
      type: "ipv4",
      value: "50.16.16.211",
      name: "QakBot",
      port: 443,
      status: "online",
      confidence: 90,
    });
    expect(r[0].firstSeen).toBe("2024-01-02T03:04:05.000Z");
    expect(parseFeodo("not json")).toEqual([]);
  });

  it("C2IntelFeeds: derives a readable name and skips headers and private IPs", () => {
    const csv = "#ip,ioc\n1.117.74.144,Possible Cobaltstrike C2 IP\n192.168.0.4,Possible Cobaltstrike C2 IP\n8.8.4.4\n";
    const r = parseC2Intel(csv);
    expect(r.map((x) => x.value)).toEqual(["1.117.74.144", "8.8.4.4"]);
    expect(r[0].name).toBe("Cobaltstrike C2");
    expect(r[1].name).toBe("C2 server");
  });

  it("OpenPhish: only http(s) URLs", () => {
    const r = parseOpenPhish("https://bad.example/login\nftp://x\n\njavascript:alert(1)\nhttp://other.example/a?b=1");
    expect(r.map((x) => x.value)).toEqual(["https://bad.example/login", "http://other.example/a?b=1"]);
    expect(r.every((x) => x.name === "Phishing" && x.type === "url")).toBe(true);
  });
});

const RULE = `title: Suspicious Download Via Certutil.EXE
id: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
status: test
description: Detects certutil downloading files, as abused in CVE-2021-44228 follow-on activity.
references:
    - https://example.com/CVE-2022-0001
author: Florian Roth (Nextron Systems)
date: 2023-02-15
modified: 2025-12-01
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.t1059.001
    - cve.2021-44228
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
    condition: selection
level: High
`;

describe("Sigma rule parsing", () => {
  it("extracts metadata, ATT&CK techniques, CVEs and logsource", () => {
    const r = parseSigmaRule(RULE, "rules/windows/process_creation/x.yml")!;
    expect(r.id).toBe("sigmahq:19b08b1c-861d-4e75-a1ef-ea0c1baf202b");
    expect(r.level).toBe("high");
    expect(r.techniques).toEqual(["T1105", "T1059.001"]);
    expect(r.cves.sort()).toEqual(["CVE-2021-44228", "CVE-2022-0001"]);
    expect(r).toMatchObject({ product: "windows", category: "process_creation", service: null });
    expect(r.author).toContain("Florian Roth");
    expect(r.raw).toBe(RULE);
  });

  it("rejects non-rules and malformed YAML", () => {
    expect(parseSigmaRule("title: only a title")).toBeNull();
    expect(parseSigmaRule("title: x\ndetection: {a: 1}")).toBeNull(); // no id
    expect(parseSigmaRule(":\n  - [unclosed")).toBeNull();
  });

  it("normalises technique tags", () => {
    expect(techniqueFromTag("attack.t1059.001")).toBe("T1059.001");
    expect(techniqueFromTag("attack.execution")).toBeNull();
    expect(techniqueFromTag("cve.2021-44228")).toBeNull();
  });

  it("reads rules out of a zip, ignoring non-rule files", async () => {
    const zip = new JSZip();
    zip.file("rules/windows/a.yml", RULE);
    zip.file("README.md", "# hi");
    zip.file("rules/broken.yml", "title: nope");
    const rules = await parseSigmaZip(await zip.generateAsync({ type: "nodebuffer" }));
    expect(rules).toHaveLength(1);
    expect(rules[0].path).toBe("rules/windows/a.yml");
  });
});
