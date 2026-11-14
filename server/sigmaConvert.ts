/**
 * Deterministic Sigma → EDR/SIEM query converter (no AI, no network).
 *
 * Scope is deliberate: process-creation rules (the bulk of endpoint content),
 * with the standard Sigma modifiers contains / startswith / endswith / all / re
 * and wildcards, and conditions built from and / or / not / "1 of" / "all of".
 * Anything outside that (other log sources, aggregations, unsupported fields)
 * returns a clear reason instead of a guess. Always validate in your console.
 */
import yaml from "js-yaml";
import { RULE_CONVERT_PLATFORMS } from "@shared/schema";

export const CONVERT_PLATFORMS = RULE_CONVERT_PLATFORMS;
export type ConvertPlatform = (typeof RULE_CONVERT_PLATFORMS)[number]["id"];

type Op = "eq" | "contains" | "starts" | "ends" | "re";
interface Match {
  kind: "match";
  field: string;
  op: Op;
  value: string;
}
type Node = Match | { kind: "and" | "or"; kids: Node[] } | { kind: "not"; kid: Node };

export interface ConvertResult {
  platform: ConvertPlatform;
  supported: boolean;
  query?: string;
  notes: string[];
  error?: string;
}

class Unsupported extends Error {}

const regexEscape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Turn a Sigma value (with * and ? wildcards) into one or more Match ops. */
function toMatch(field: string, modifier: Op, raw: unknown): Match {
  if (raw === null || raw === undefined)
    throw new Unsupported(`null value for ${field} (field-absent checks are not convertible)`);
  const v = String(raw);
  if (modifier === "re") return { kind: "match", field, op: "re", value: v };
  // Sigma: "\*" and "\?" are literal; everything else with * or ? is a wildcard.
  const hasWild = /(^|[^\\])[*?]/.test(v);
  if (!hasWild) return { kind: "match", field, op: modifier, value: v.replace(/\\([*?])/g, "$1") };
  if (modifier === "eq") {
    const core = v.replace(/^\*/, "").replace(/\*$/, "");
    const lead = v.startsWith("*");
    const trail = v.endsWith("*") && v.length > 1;
    if (!/(^|[^\\])[*?]/.test(core)) {
      const lit = core.replace(/\\([*?])/g, "$1");
      if (lead && trail) return { kind: "match", field, op: "contains", value: lit };
      if (lead) return { kind: "match", field, op: "ends", value: lit };
      if (trail) return { kind: "match", field, op: "starts", value: lit };
    }
  }
  const body = v
    .split(/(?<!\\)([*?])/)
    .map((part) => (part === "*" ? ".*" : part === "?" ? "." : regexEscape(part.replace(/\\([*?])/g, "$1"))))
    .join("");
  const anchored =
    modifier === "eq" ? `^${body}$` : modifier === "starts" ? `^${body}` : modifier === "ends" ? `${body}$` : body;
  return { kind: "match", field, op: "re", value: anchored };
}

/** Sigma "windash": a switch may be written with -, /, or a typographic dash. */
function windash(m: Match): Match {
  if (m.op === "re") return m;
  const e = regexEscape(m.value).replace(/-/g, "[-/\u2013\u2014\u2015]");
  const value = m.op === "eq" ? `^${e}$` : m.op === "starts" ? `^${e}` : m.op === "ends" ? `${e}$` : e;
  return { kind: "match", field: m.field, op: "re", value };
}

function fieldNode(key: string, value: unknown): Node {
  const [field, ...mods] = key.split("|");
  const known = new Set(["contains", "startswith", "endswith", "all", "re", "windash"]);
  const bad = mods.find((m) => !known.has(m));
  if (bad) throw new Unsupported(`modifier "${bad}" on ${field}`);
  const op: Op = mods.includes("re")
    ? "re"
    : mods.includes("contains")
      ? "contains"
      : mods.includes("startswith")
        ? "starts"
        : mods.includes("endswith")
          ? "ends"
          : "eq";
  const values = Array.isArray(value) ? value : [value];
  const dash = mods.includes("windash");
  const ms = values.map((v) => (dash && op !== "re" ? windash(toMatch(field, op, v)) : toMatch(field, op, v)));
  if (ms.length === 1) return ms[0];
  return { kind: mods.includes("all") ? "and" : "or", kids: ms };
}

function selectionNode(sel: unknown): Node {
  if (Array.isArray(sel)) {
    if (sel.every((x) => x && typeof x === "object" && !Array.isArray(x))) {
      const kids = sel.map((m) => selectionNode(m));
      return kids.length === 1 ? kids[0] : { kind: "or", kids };
    }
    throw new Unsupported("keyword (full-text) selections need a free-text field and cannot be converted");
  }
  if (sel && typeof sel === "object") {
    const kids = Object.entries(sel as Record<string, unknown>).map(([k, v]) => fieldNode(k, v));
    if (kids.length === 0) throw new Unsupported("empty selection");
    return kids.length === 1 ? kids[0] : { kind: "and", kids };
  }
  throw new Unsupported("unrecognised selection shape");
}

function conditionNode(cond: string, sels: Map<string, Node>): Node {
  if (/\|/.test(cond)) throw new Unsupported("aggregations / count conditions are not convertible");
  const toks = cond.match(/\(|\)|[^\s()]+/g) ?? [];
  let i = 0;
  const peek = () => toks[i];
  const take = () => toks[i++];
  const expand = (pat: string): Node[] => {
    const names =
      pat === "them"
        ? Array.from(sels.keys())
        : Array.from(sels.keys()).filter((n) => new RegExp(`^${pat.split("*").map(regexEscape).join(".*")}$`).test(n));
    if (names.length === 0) throw new Unsupported(`condition pattern "${pat}" matches no selection`);
    return names.map((n) => sels.get(n)!);
  };
  const primary = (): Node => {
    const t = take();
    if (t === undefined) throw new Unsupported("incomplete condition");
    if (t === "(") {
      const n = orExpr();
      if (take() !== ")") throw new Unsupported("unbalanced parentheses in condition");
      return n;
    }
    if (t === "not") return { kind: "not", kid: primary() };
    if ((t === "1" || t === "all") && peek() === "of") {
      take();
      const kids = expand(take() ?? "them");
      return kids.length === 1 ? kids[0] : { kind: t === "all" ? "and" : "or", kids };
    }
    const n = sels.get(t);
    if (!n) throw new Unsupported(`condition references unknown selection "${t}"`);
    return n;
  };
  const andExpr = (): Node => {
    const kids = [primary()];
    while (peek() === "and") {
      take();
      kids.push(primary());
    }
    return kids.length === 1 ? kids[0] : { kind: "and", kids };
  };
  const orExpr = (): Node => {
    const kids = [andExpr()];
    while (peek() === "or") {
      take();
      kids.push(andExpr());
    }
    return kids.length === 1 ? kids[0] : { kind: "or", kids };
  };
  const n = orExpr();
  if (i < toks.length) throw new Unsupported(`unexpected "${toks[i]}" in condition`);
  return n;
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

interface Renderer {
  fields: Record<string, string>;
  leaf(native: string, m: Match): string;
  wrap(expr: string): string;
  notes: string[];
}

const dq = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
const kqlVerbatim = (s: string) => `@"${s.replace(/"/g, '""')}"`;
const ci = (re: string) => `(?i)${re}`;

function reFor(m: Match): string {
  const e = regexEscape(m.value);
  return m.op === "re"
    ? m.value
    : m.op === "eq"
      ? `^${e}$`
      : m.op === "starts"
        ? `^${e}`
        : m.op === "ends"
          ? `${e}$`
          : e;
}

const RENDERERS: Record<ConvertPlatform, Renderer> = {
  defender: {
    fields: {
      Image: "FolderPath",
      CommandLine: "ProcessCommandLine",
      ParentImage: "InitiatingProcessFolderPath",
      ParentCommandLine: "InitiatingProcessCommandLine",
      OriginalFileName: "ProcessVersionInfoOriginalFileName",
      User: "AccountName",
      IntegrityLevel: "ProcessIntegrityLevel",
      Description: "ProcessVersionInfoFileDescription",
      Product: "ProcessVersionInfoProductName",
      Company: "ProcessVersionInfoCompanyName",
    },
    leaf: (f, m) => {
      const v = kqlVerbatim(m.value);
      if (m.op === "re") return `${f} matches regex ${kqlVerbatim(ci(m.value))}`;
      return `${f} ${{ eq: "=~", contains: "contains", starts: "startswith", ends: "endswith" }[m.op]} ${v}`;
    },
    wrap: (e) =>
      `DeviceProcessEvents\n| where ${e}\n| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine`,
    notes: ["Returns Timestamp, DeviceId and ReportId, which Defender custom detection rules require."],
  },
  crowdstrike: {
    fields: { Image: "ImageFileName", CommandLine: "CommandLine" },
    leaf: (f, m) => `${f}=/${reFor(m).replace(/(?<!\\)\//g, "\\/")}/i`,
    wrap: (e) => `#event_simpleName=ProcessRollup2\n| ${e}`,
    notes: [
      "CrowdStrike process events expose only the parent's file name, so ParentImage, ParentCommandLine, OriginalFileName and User conditions are not converted.",
    ],
  },
  sentinelone: {
    fields: {
      Image: "tgt.process.image.path",
      CommandLine: "tgt.process.cmdline",
      ParentImage: "src.process.image.path",
      ParentCommandLine: "src.process.cmdline",
      User: "tgt.process.user",
    },
    leaf: (f, m) => {
      const v = `"${dq(m.value)}"`;
      if (m.op === "re") return `${f} RegExp "${dq(m.value)}"`;
      return `${f} ${{ eq: "=", contains: "ContainsCIS", starts: "StartsWithCIS", ends: "EndsWithCIS" }[m.op]} ${v}`;
    },
    wrap: (e) => `event.type = "Process Creation" AND (${e})`,
    notes: ["Deep Visibility string operators are case-insensitive (…CIS). Check path escaping in your console."],
  },
  cortex_xdr: {
    fields: {
      Image: "action_process_image_path",
      CommandLine: "action_process_image_command_line",
      ParentImage: "actor_process_image_path",
      ParentCommandLine: "actor_process_command_line",
      User: "action_process_username",
    },
    leaf: (f, m) => (m.op === "contains" ? `${f} contains "${dq(m.value)}"` : `${f} ~= "${dq(ci(reFor(m)))}"`),
    wrap: (e) =>
      `dataset = xdr_data\n| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and (${e})`,
    notes: ["Process-start events only. Regex operators use (?i) for case-insensitive matching."],
  },
  elastic: {
    fields: {
      Image: "process.executable",
      CommandLine: "process.command_line",
      ParentImage: "process.parent.executable",
      ParentCommandLine: "process.parent.command_line",
      OriginalFileName: "process.pe.original_file_name",
      User: "user.name",
      CurrentDirectory: "process.working_directory",
      Description: "process.pe.description",
      Product: "process.pe.product",
      Company: "process.pe.company",
    },
    leaf: (f, m) => {
      if (m.op === "re") return `${f} regex~ "${dq(m.value)}"`;
      const lit = dq(m.value);
      const pat = { eq: lit, contains: `*${lit}*`, starts: `${lit}*`, ends: `*${lit}` }[m.op];
      return `${f} : "${pat}"`;
    },
    wrap: (e) => `process where event.type == "start" and (${e})`,
    notes: ["`:` matching is case-insensitive and supports wildcards."],
  },
  splunk: {
    fields: {
      Image: "Image",
      CommandLine: "CommandLine",
      ParentImage: "ParentImage",
      ParentCommandLine: "ParentCommandLine",
      OriginalFileName: "OriginalFileName",
      User: "User",
      CurrentDirectory: "CurrentDirectory",
      Description: "Description",
      Product: "Product",
      Company: "Company",
      IntegrityLevel: "IntegrityLevel",
    },
    leaf: (f, m) => {
      if (m.op === "re") return `match(${f}, "${dq(ci(m.value))}")`;
      const esc = (s: string) => dq(s.toLowerCase()).replace(/([%_])/g, "\\$1");
      const v = esc(m.value);
      const pat = { eq: v, contains: `%${v}%`, starts: `${v}%`, ends: `%${v}` }[m.op];
      return `like(lower(${f}), "${pat}")`;
    },
    wrap: (e) => `index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n| where ${e}`,
    notes: [
      "Assumes Sysmon process-creation events (EventCode 1) and Sysmon field names. Adjust index/source to your environment.",
    ],
  },
};

function render(node: Node, r: Renderer, unsupportedFields: Set<string>, top = true): string {
  switch (node.kind) {
    case "match": {
      const native = r.fields[node.field];
      if (!native) {
        unsupportedFields.add(node.field);
        return "false";
      }
      return r.leaf(native, node);
    }
    case "not":
      return `not (${render(node.kid, r, unsupportedFields, false)})`;
    case "and":
    case "or": {
      const parts = node.kids.map((k) => render(k, r, unsupportedFields, false));
      const joined = parts.join(` ${node.kind} `);
      return top ? joined : `(${joined})`;
    }
  }
}

export function convertSigma(rawYaml: string, platform: ConvertPlatform): ConvertResult {
  const r = RENDERERS[platform];
  const fail = (error: string): ConvertResult => ({ platform, supported: false, notes: [], error });
  if (!r) return fail(`unknown platform "${platform}"`);
  let doc: any;
  try {
    doc = yaml.load(rawYaml);
  } catch {
    return fail("the rule is not valid YAML");
  }
  const ls = doc?.logsource ?? {};
  if (String(ls.category ?? "") !== "process_creation") {
    return fail(
      `only process_creation rules can be converted automatically (this rule's log source is ${[ls.product, ls.category ?? ls.service].filter(Boolean).join(" / ") || "unknown"}). Use the AI hunt-query generator for other log sources.`,
    );
  }
  const det = doc?.detection;
  if (!det || typeof det !== "object" || typeof det.condition !== "string") {
    return fail("the rule has no single-string condition (multi-condition rules are not supported)");
  }
  try {
    const sels = new Map<string, Node>();
    for (const [name, body] of Object.entries(det)) {
      if (name === "condition" || name === "timeframe") continue;
      sels.set(name, selectionNode(body));
    }
    const tree = conditionNode(det.condition, sels);
    const unsupportedFields = new Set<string>();
    const expr = render(tree, r, unsupportedFields);
    if (unsupportedFields.size > 0) {
      return fail(`this platform cannot express the field(s): ${Array.from(unsupportedFields).join(", ")}`);
    }
    return {
      platform,
      supported: true,
      query: r.wrap(expr),
      notes: [
        ...r.notes,
        "Converted automatically from Sigma — test against known-good and known-bad activity before deploying.",
      ],
    };
  } catch (e) {
    if (e instanceof Unsupported) return fail(e.message);
    return fail("conversion failed: " + String((e as Error)?.message ?? e).slice(0, 160));
  }
}
