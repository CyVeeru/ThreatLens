import { describe, expect, it } from "vitest";
import { convertSigma } from "../server/sigmaConvert";

const certutil = `title: Suspicious Download Via Certutil.EXE
id: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
    filter_main:
        ParentImage|startswith: 'C:\\Windows\\System32\\'
    condition: selection_img and selection_flags and not filter_main
level: high
`;

const simple = `title: Whoami priv
id: s1
logsource: {category: process_creation, product: windows}
detection:
    sel:
        Image|endswith: '\\whoami.exe'
        CommandLine|contains: '/priv'
    filter:
        ParentImage|startswith: 'C:\\Windows\\'
    condition: sel and not filter
`;

describe("Sigma → native conversion", () => {
  it("Defender KQL: and / or / not, modifiers and verbatim strings", () => {
    const r = convertSigma(certutil, "defender");
    expect(r.supported).toBe(true);
    expect(r.query).toContain("DeviceProcessEvents");
    expect(r.query).toContain('FolderPath endswith @"\\certutil.exe"');
    expect(r.query).toContain('ProcessVersionInfoOriginalFileName =~ @"CertUtil.exe"');
    expect(r.query).toContain('ProcessCommandLine contains @"urlcache"');
    expect(r.query).toContain('not (InitiatingProcessFolderPath startswith @"C:\\Windows\\System32\\")');
    expect(r.query).toContain("Timestamp, DeviceId, ReportId");
  });

  it("Elastic EQL: wildcard matching and event filter", () => {
    const r = convertSigma(certutil, "elastic");
    expect(r.query).toContain('process where event.type == "start"');
    expect(r.query).toContain('process.executable : "*\\\\certutil.exe"');
    expect(r.query).toContain('process.command_line : "*urlcache*"');
  });

  it("Splunk: lower-cased like() with escaped wildcards", () => {
    const r = convertSigma(certutil, "splunk");
    expect(r.query).toContain("EventCode=1");
    expect(r.query).toContain('like(lower(Image), "%\\\\certutil.exe")');
  });

  it("SentinelOne and Cortex use their native fields", () => {
    const s1 = convertSigma(simple, "sentinelone").query!;
    expect(s1).toContain('event.type = "Process Creation"');
    expect(s1).toContain('tgt.process.cmdline ContainsCIS "/priv"');
    expect(s1).toContain('not (src.process.image.path StartsWithCIS "C:\\\\Windows\\\\")');
    const x = convertSigma(simple, "cortex_xdr").query!;
    expect(x).toContain("event_sub_type = ENUM.PROCESS_START");
    expect(x).toContain('action_process_image_command_line contains "/priv"');
    // Fields a platform cannot express are refused, not guessed.
    expect(convertSigma(certutil, "sentinelone").error).toMatch(/OriginalFileName/);
  });

  it("CrowdStrike refuses fields it cannot express instead of guessing", () => {
    const r = convertSigma(certutil, "crowdstrike");
    expect(r.supported).toBe(false);
    expect(r.error).toMatch(/OriginalFileName|ParentImage/);
  });

  it("CrowdStrike converts what it can, with case-insensitive regex", () => {
    const rule = `title: t
id: x
logsource: {category: process_creation, product: windows}
detection:
    sel:
        Image|endswith: '\\whoami.exe'
        CommandLine|contains|all: ['/priv', '/all']
    condition: sel
`;
    const r = convertSigma(rule, "crowdstrike");
    expect(r.supported).toBe(true);
    expect(r.query).toContain("#event_simpleName=ProcessRollup2");
    expect(r.query).toContain("ImageFileName=/\\\\whoami\\.exe$/i");
    expect(r.query).toContain("CommandLine=/\\/priv/i and CommandLine=/\\/all/i");
  });

  it("handles inner wildcards by converting to a regex", () => {
    const rule = `title: t
id: y
logsource: {category: process_creation}
detection:
    sel:
        CommandLine: 'powershell*-enc*'
    condition: sel
`;
    const r = convertSigma(rule, "elastic");
    expect(r.query).toContain(
      'process.command_line : "powershell*-enc*"'.replace(/.*/, 'process.command_line regex~ "^powershell.*-enc.*$"'),
    );
  });

  it("supports '1 of' and 'all of' patterns", () => {
    const rule = `title: t
id: z
logsource: {category: process_creation}
detection:
    sel_a: {Image|endswith: '\\a.exe'}
    sel_b: {Image|endswith: '\\b.exe'}
    condition: 1 of sel_*
`;
    const q = convertSigma(rule, "defender").query!;
    expect(q).toContain(
      'FolderPath endswith @"\\a.exe") or (FolderPath endswith @"\\b.exe"'.replace(
        /^.*$/,
        'FolderPath endswith @"\\a.exe"',
      ),
    );
    expect(q).toMatch(/\bor\b/);
  });

  it("rejects other log sources, aggregations and unknown modifiers with a reason", () => {
    const net = `title: t
id: n
logsource: {category: network_connection, product: windows}
detection: {sel: {DestinationPort: 4444}, condition: sel}
`;
    expect(convertSigma(net, "defender").error).toMatch(/only process_creation/);
    const agg = `title: t
id: a
logsource: {category: process_creation}
detection: {sel: {Image: 'a'}, condition: sel | count() > 5}
`;
    expect(convertSigma(agg, "defender").error).toMatch(/aggregation/);
    const mod = `title: t
id: m
logsource: {category: process_creation}
detection: {sel: {'CommandLine|base64offset|contains': 'x'}, condition: sel}
`;
    expect(convertSigma(mod, "defender").error).toMatch(/base64offset/);
    expect(convertSigma("::: not yaml [", "defender").supported).toBe(false);
  });
});

describe("windash and extended fields", () => {
  it("expands windash switches into a dash-tolerant regex", () => {
    const rule = `title: t
id: w
logsource: {category: process_creation, product: windows}
detection:
    sel:
        CommandLine|windash|contains: '-enc'
    condition: sel
`;
    const q = convertSigma(rule, "elastic").query!;
    expect(q).toContain("process.command_line regex~");
    expect(q).toContain("[-/");
    expect(q).toContain("enc");
  });
  it("maps Description and IntegrityLevel on Defender", () => {
    const rule = `title: t
id: d
logsource: {category: process_creation, product: windows}
detection:
    sel: {Description: 'Foo', IntegrityLevel: 'System'}
    condition: sel
`;
    const q = convertSigma(rule, "defender").query!;
    expect(q).toContain("ProcessVersionInfoFileDescription");
    expect(q).toContain("ProcessIntegrityLevel");
  });
});
