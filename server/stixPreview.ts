/**
 * STIX 2.1 preview for a selection of OSINT findings.
 *
 * The Intelligence Feed lets an analyst select findings and preview what a STIX
 * export would contain before producing one. This module builds the bundle
 * in memory and reports its shape — object counts by type, plus any warnings
 * worth seeing before export (findings with no extractable indicators, IOCs
 * that fail their pattern rules).
 *
 * Bundle layout, one report per finding:
 *
 *   report          <- the finding itself
 *   indicator       <- each extracted IOC, as a STIX pattern
 *   attack-pattern  <- each referenced ATT&CK technique
 *   vulnerability   <- each referenced CVE
 *   relationship    <- report -> each object it refers to
 */
import { createHash } from "node:crypto";
import type { OsintFindingDTO, StixPreviewDTO } from "@shared/schema";

/** IOC kinds we can express as a STIX pattern, and how. */
const IOC_PATTERNS: Record<string, { path: string; validate: RegExp }> = {
  ipv4: { path: "ipv4-addr:value", validate: /^\d{1,3}(?:\.\d{1,3}){3}$/ },
  ipv6: { path: "ipv6-addr:value", validate: /^[0-9a-f:]+$/i },
  domain: { path: "domain-name:value", validate: /^(?=.{1,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$/i },
  url: { path: "url:value", validate: /^https?:\/\/\S+$/i },
  md5: { path: "file:hashes.'MD5'", validate: /^[a-f0-9]{32}$/i },
  sha1: { path: "file:hashes.'SHA-1'", validate: /^[a-f0-9]{40}$/i },
  sha256: { path: "file:hashes.'SHA-256'", validate: /^[a-f0-9]{64}$/i },
  email: { path: "email-addr:value", validate: /^[^@\s]+@[^@\s]+\.[^@\s]+$/ },
  btc: { path: "x-crypto-wallet:address", validate: /^[13bc1][a-zA-HJ-NP-Z0-9]{25,62}$/ },
};

const TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/i;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

/**
 * Count what a STIX 2.1 bundle for these findings would contain.
 *
 * Pure and side-effect free: it deliberately does not persist or emit the
 * bundle, so the preview is safe to call on every selection change.
 */
export function buildStixPreview(findings: OsintFindingDTO[]): StixPreviewDTO {
  const objectCounts: Record<string, number> = {};
  const warnings: string[] = [];
  const errors: string[] = [];

  // Deduplicate across findings: the same IP or technique in five reports is
  // one SDO with five relationships, not five SDOs.
  const indicators = new Set<string>();
  const attackPatterns = new Set<string>();
  const vulnerabilities = new Set<string>();
  let relationshipCount = 0;
  let reportCount = 0;

  const bump = (type: string, by = 1) => {
    objectCounts[type] = (objectCounts[type] ?? 0) + by;
  };

  for (const f of findings) {
    reportCount += 1;
    bump("report");

    let referenced = 0;

    // ---- indicators from extracted IOCs
    const iocs = (f.iocs ?? {}) as Record<string, string[] | undefined>;
    for (const [kind, values] of Object.entries(iocs)) {
      const spec = IOC_PATTERNS[kind];
      if (!spec) {
        if (Array.isArray(values) && values.length > 0) {
          warnings.push(
            `${f.id}: ${values.length} "${kind}" indicator(s) have no STIX pattern mapping and will be dropped.`,
          );
        }
        continue;
      }
      for (const raw of values ?? []) {
        const value = String(raw).trim();
        if (!value) continue;
        if (!spec.validate.test(value)) {
          warnings.push(
            `${f.id}: ${kind} value ${JSON.stringify(value.slice(0, 60))} is not a valid ${kind} and will be dropped.`,
          );
          continue;
        }
        indicators.add(`${spec.path}|${value.toLowerCase()}`);
        referenced += 1;
      }
    }

    // ---- attack-patterns from ATT&CK techniques
    for (const t of f.attackTechniques ?? []) {
      const id = String((t && t.id) || "")
        .trim()
        .toUpperCase();
      if (!id) continue;
      if (!TECHNIQUE_ID.test(id)) {
        warnings.push(`${f.id}: ${JSON.stringify(id)} is not a MITRE ATT&CK technique id and will be dropped.`);
        continue;
      }
      attackPatterns.add(id);
      referenced += 1;
    }

    // ---- vulnerabilities from CVE ids
    for (const raw of f.cveIds ?? []) {
      const id = String(raw).trim().toUpperCase();
      if (!id) continue;
      if (!CVE_ID.test(id)) {
        warnings.push(`${f.id}: ${JSON.stringify(id)} is not a well-formed CVE id and will be dropped.`);
        continue;
      }
      vulnerabilities.add(id);
      referenced += 1;
    }

    relationshipCount += referenced;
    if (referenced === 0) {
      warnings.push(`${f.id}: no indicators, techniques or CVEs — exports as a report with no linked objects.`);
    }
  }

  bump("indicator", indicators.size);
  bump("attack-pattern", attackPatterns.size);
  bump("vulnerability", vulnerabilities.size);
  bump("relationship", relationshipCount);

  if (findings.length === 0) errors.push("No findings selected.");

  const objectCount = Object.values(objectCounts).reduce((a, b) => a + b, 0);

  return {
    valid: errors.length === 0 && objectCount > 0,
    objectCount,
    // Report zero-count types too, so the preview table has stable rows.
    objectCounts: {
      report: objectCounts.report ?? 0,
      indicator: objectCounts.indicator ?? 0,
      "attack-pattern": objectCounts["attack-pattern"] ?? 0,
      vulnerability: objectCounts.vulnerability ?? 0,
      relationship: objectCounts.relationship ?? 0,
    },
    indicatorCount: indicators.size,
    reportCount,
    attackPatternCount: attackPatterns.size,
    relationshipCount,
    findingCount: findings.length,
    // Long selections can produce a warning per finding; keep the payload sane.
    warnings: warnings.slice(0, 50),
    errors,
  };
}

/* ------------------------------------------------------------------ *
 * Bundle emission
 * ------------------------------------------------------------------ */

/**
 * STIX 2.1 ids must be `<type>--<uuid>`. Deriving the uuid from the object's
 * own identifying value (the way STIX derives SCO ids) keeps a re-export of
 * the same intel byte-identical, so downstream diffs stay meaningful.
 */
function deterministicId(type: string, value: string): string {
  const h = createHash("sha1").update(`threatlens:${type}:${value}`).digest("hex");
  const uuid = [
    h.slice(0, 8),
    h.slice(8, 12),
    // version 5 marker, then the RFC 4122 variant bits.
    `5${h.slice(13, 16)}`,
    ((parseInt(h.slice(16, 18), 16) & 0x3f) | 0x80).toString(16).padStart(2, "0") + h.slice(18, 20),
    h.slice(20, 32),
  ].join("-");
  return `${type}--${uuid}`;
}

const iso = (v: string | null | undefined): string => {
  const d = v ? new Date(v) : new Date();
  return (Number.isNaN(d.getTime()) ? new Date() : d).toISOString().replace(/\.\d{3}Z$/, ".000Z");
};

/** Build the STIX 2.1 bundle the preview describes. */
export function buildStixBundle(findings: OsintFindingDTO[]): {
  type: "bundle";
  id: string;
  objects: Array<Record<string, unknown>>;
} {
  const objects: Array<Record<string, unknown>> = [];
  const byKey = new Map<string, string>(); // dedupe key -> stix id
  const created = iso(null);

  const ensure = (key: string, make: () => Record<string, unknown>): string => {
    const existing = byKey.get(key);
    if (existing) return existing;
    const obj = make();
    byKey.set(key, obj.id as string);
    objects.push(obj);
    return obj.id as string;
  };

  for (const f of findings) {
    const reportRefs: string[] = [];

    const iocs = (f.iocs ?? {}) as Record<string, string[] | undefined>;
    for (const [kind, values] of Object.entries(iocs)) {
      const spec = IOC_PATTERNS[kind];
      if (!spec) continue;
      for (const raw of values ?? []) {
        const value = String(raw).trim();
        if (!value || !spec.validate.test(value)) continue;
        const pattern = `[${spec.path} = '${value.replace(/'/g, "\\'")}']`;
        reportRefs.push(
          ensure(`indicator|${pattern}`, () => ({
            type: "indicator",
            spec_version: "2.1",
            id: deterministicId("indicator", pattern),
            created,
            modified: created,
            name: `${kind} ${value}`,
            pattern,
            pattern_type: "stix",
            valid_from: iso(f.publishedAt),
          })),
        );
      }
    }

    for (const t of f.attackTechniques ?? []) {
      const id = String((t && t.id) || "")
        .trim()
        .toUpperCase();
      if (!id || !TECHNIQUE_ID.test(id)) continue;
      reportRefs.push(
        ensure(`attack-pattern|${id}`, () => ({
          type: "attack-pattern",
          spec_version: "2.1",
          id: deterministicId("attack-pattern", id),
          created,
          modified: created,
          name: (t && t.name) || id,
          external_references: [{ source_name: "mitre-attack", external_id: id }],
        })),
      );
    }

    for (const raw of f.cveIds ?? []) {
      const id = String(raw).trim().toUpperCase();
      if (!id || !CVE_ID.test(id)) continue;
      reportRefs.push(
        ensure(`vulnerability|${id}`, () => ({
          type: "vulnerability",
          spec_version: "2.1",
          id: deterministicId("vulnerability", id),
          created,
          modified: created,
          name: id,
          external_references: [{ source_name: "cve", external_id: id }],
        })),
      );
    }

    const reportId = deterministicId("report", f.id);
    objects.push({
      type: "report",
      spec_version: "2.1",
      id: reportId,
      created,
      modified: created,
      name: f.title,
      description: f.summary ?? undefined,
      published: iso(f.publishedAt),
      report_types: ["threat-report"],
      // STIX requires object_refs to be non-empty; a finding with nothing
      // extracted refers to itself rather than emitting an invalid object.
      object_refs: reportRefs.length > 0 ? [...new Set(reportRefs)] : [reportId],
      external_references: f.url ? [{ source_name: f.sourceName, url: f.url }] : undefined,
      labels: [f.severity, f.sourceCategory].filter(Boolean),
    });

    for (const ref of new Set(reportRefs)) {
      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: deterministicId("relationship", `${reportId}|refers-to|${ref}`),
        created,
        modified: created,
        relationship_type: "refers-to",
        source_ref: reportId,
        target_ref: ref,
      });
    }
  }

  return {
    type: "bundle",
    id: deterministicId(
      "bundle",
      findings
        .map((f) => f.id)
        .sort()
        .join(","),
    ),
    objects,
  };
}
