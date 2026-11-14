import { describe, expect, it } from "vitest";
import { compileAssets, matchFinding } from "../server/orgMatcher";
import type { OrgAssetDTO, OsintFindingDTO } from "../shared/schema";

const asset = (over: Partial<OrgAssetDTO>): OrgAssetDTO => ({
  id: over.name ?? "a",
  tenantId: "t",
  name: "Cisco",
  kind: "vendor",
  criticality: "high",
  aliases: [],
  notes: null,
  createdAt: "",
  updatedAt: "",
  createdBy: "test",
  ...over,
});

const finding = (over: Partial<OsintFindingDTO>): OsintFindingDTO =>
  ({
    id: "f1",
    title: "Generic advisory",
    summary: "",
    affectedTech: [],
    cveIds: [],
    severity: "medium",
    ...over,
  }) as OsintFindingDTO;

describe("org profile matching", () => {
  it("returns null with no assets or no match", () => {
    expect(matchFinding(finding({ title: "Cisco flaw" }), compileAssets([]))).toBeNull();
    expect(matchFinding(finding({ title: "Unrelated Fortinet bug" }), compileAssets([asset({})]))).toBeNull();
  });

  it("matches on word boundaries only", () => {
    const terms = compileAssets([asset({ name: "Cisco" })]);
    expect(matchFinding(finding({ title: "Ciscoish thing" }), terms)).toBeNull();
    expect(matchFinding(finding({ title: "Cisco IOS XE RCE" }), terms)?.matched).toBe(true);
  });

  it("treats spaces, hyphens and underscores as interchangeable and honours aliases", () => {
    const terms = compileAssets([asset({ name: "Palo Alto Networks", aliases: ["PAN-OS"] })]);
    expect(matchFinding(finding({ title: "palo-alto networks zero day" }), terms)).not.toBeNull();
    expect(matchFinding(finding({ affectedTech: ["PAN-OS"] }), terms)?.matches[0].field).toBe("tech");
  });

  it("does not match short terms in free text, but does in the tech list", () => {
    const terms = compileAssets([asset({ name: "AWS", kind: "cloud" })]);
    expect(matchFinding(finding({ summary: "Attack via AWS tokens" }), terms)).toBeNull();
    expect(matchFinding(finding({ affectedTech: ["AWS"] }), terms)).not.toBeNull();
  });

  it("scores by criticality and field", () => {
    const hi = matchFinding(finding({ affectedTech: ["Cisco"] }), compileAssets([asset({ criticality: "critical" })]))!;
    const lo = matchFinding(
      finding({ summary: "Cisco appliances affected" }),
      compileAssets([asset({ criticality: "low" })]),
    )!;
    expect(hi.score).toBeGreaterThan(lo.score);
    expect(hi.score).toBe(100);
  });

  it("escalates to urgent for KEV or high EPSS, and explains why", () => {
    const f = finding({
      affectedTech: ["Cisco"],
      cveEnrichment: { cveId: "CVE-2026-0001", cvssScore: 9.8, epssScore: 0.9, kev: true, priority: 99 },
    });
    const rel = matchFinding(f, compileAssets([asset({})]))!;
    expect(rel.priority).toBe("urgent");
    expect(rel.reasons.join(" ")).toMatch(/KEV/);
  });

  it("stays at watch for a low-severity match without exploit signals", () => {
    const rel = matchFinding(
      finding({ summary: "Cisco minor info disclosure", severity: "low" }),
      compileAssets([asset({ criticality: "low" })]),
    )!;
    expect(rel.priority).toBe("watch");
  });
});
