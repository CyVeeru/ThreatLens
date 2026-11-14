import { describe, expect, it } from "vitest";
import { annotateRule, lintRule } from "../server/ruleLint";

const NAMES: Record<string, string> = {
  T1190: "Exploit Public-Facing Application",
  "T1588.002": "Tool",
  "T1059.004": "Unix Shell",
  T1059: "Command and Scripting Interpreter",
};
const lookup = (id: string) => NAMES[id] ?? null;

describe("generated rule linting", () => {
  it("flags an ATT&CK id whose label does not match", () => {
    const w = lintRule("ioa", "Detect Gitea RCE (T1588.002 — Exploit Public-Facing Application)", lookup);
    expect(w).toHaveLength(1);
    expect(w[0]).toContain('T1588.002 is "Tool"');
  });

  it("accepts correct and partially-worded labels", () => {
    expect(lintRule("ioa", "T1190 — Exploit Public-Facing Application", lookup)).toEqual([]);
    expect(lintRule("ioa", "T1059.004 Unix Shell", lookup)).toEqual([]);
    expect(lintRule("ioa", "ATT&CK: T1059: Command and Scripting Interpreter: Unix Shell", lookup)).toEqual([]);
    expect(lintRule("ioa", "T1190", lookup)).toEqual([]); // no label to contradict
    // A tactic name after the id is the requested format, not a mislabel.
    expect(lintRule("ioa", "ATT&CK: T1190 — Initial Access", lookup)).toEqual([]);
    expect(lintRule("ioa", "T1190 (Recon)", lookup)).toEqual([]);
  });

  it("flags ids that do not exist", () => {
    expect(lintRule("sigma", "tags: T9999", lookup)[0]).toContain("not a valid ATT&CK technique");
  });

  it("flags CrowdStrike IOA rules that match everything", () => {
    const broad = `Rule type: Network Connection
Image Filename regex (PCRE): .*
Command Line regex (PCRE): (.*)
Parent image regex: .*
Destination Port regex (PCRE): ^(80|443)$`;
    expect(lintRule("crowdstrike_ioa", broad, null)[0]).toMatch(/Too broad: 3 of 4/);
    const ok = `Image Filename regex (PCRE): (certutil|bitsadmin)[.]exe$
Command Line regex (PCRE): (urlcache|transfer)`;
    expect(lintRule("crowdstrike_ioa", ok, null)).toEqual([]);
  });

  it("catches product syntax slips", () => {
    const NL = String.fromCharCode(10);
    const s1 =
      'event.type == "process_creation" and src.process.image.name == "ssh" and tgt.file.name matches "x"' +
      NL +
      "// Rule: x";
    const w = lintRule("sentinelone_star", s1, null).join(" | ");
    expect(w).toContain('not "=="');
    expect(w).toContain('"process_creation"');
    expect(w).toContain("matches");
    expect(
      lintRule("sentinelone_star", 'event.type = "Process Creation" and tgt.process.cmdline ContainsCIS "x"', null),
    ).toEqual([]);
    expect(lintRule("elastic_rule", 'process where process.args ~= "x"', null)[0]).toContain("~=");
    expect(lintRule("elastic_rule", 'process where process.args : "x"', null)).toEqual([]);
    expect(lintRule("defender_rule", ["DeviceProcessEvents", "| project FileName"].join(NL), null)[0]).toContain(
      "Timestamp, DeviceId, ReportId",
    );
    expect(
      lintRule("defender_rule", ["DeviceProcessEvents", "| project Timestamp, DeviceId, ReportId"].join(NL), null),
    ).toEqual([]);
    // Comment lines are not code.
    expect(lintRule("elastic_rule", ["process where true", "// uses ~= in a comment"].join(NL), null)).toEqual([]);
  });

  it("appends REVIEW notes with the right comment style and leaves clean rules alone", () => {
    expect(annotateRule("sigma", "title: x\nT9999", lookup)).toContain("# REVIEW:");
    expect(annotateRule("elastic_rule", "process where true\n// T9999", lookup)).toContain("// REVIEW:");
    expect(annotateRule("ioa", "T1190 — Exploit Public-Facing Application", lookup)).toBe(
      "T1190 — Exploit Public-Facing Application",
    );
    expect(annotateRule("ioa", "no techniques here", null)).toBe("no techniques here");
  });
});
