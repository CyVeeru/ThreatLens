/**
 * Private / internal document ingest.
 *
 * Analysts upload the intel that never appears in RSS — ISAC bulletins,
 * vendor PDFs, incident write-ups, emails. The text is extracted server-side
 * and pushed through the same extraction pipeline as feed items (CVEs, IoCs,
 * technology and actor detection), producing a normal finding under the
 * "Analyst uploads" source so triage, AI analysis, hunts and cases all work
 * on it unchanged. The original bytes are kept under data/uploads/.
 */
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { sqlite, storage } from "./storage";
import { DATA_DIR } from "./kek";
import { detectActors, detectTech, extractCves, extractIoCs, severityFromText } from "./osintFetcher";
import { ensureClusterIdPersisted } from "./osintClustering";
import { OSINT_SOURCES } from "./osintSeed";
import type { DocumentIngestResultDTO } from "@shared/schema";

export const UPLOAD_SOURCE_ID = "osrc-9001";
const UPLOADS_DIR = resolve(DATA_DIR, "uploads");
const MAX_BYTES = 10 * 1024 * 1024;
const MAX_TEXT_CHARS = 200_000;

const MIME_EXT: Record<string, string> = {
  "text/plain": "txt",
  "text/markdown": "md",
  "text/html": "html",
  "application/pdf": "pdf",
  "application/json": "json",
};

function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

async function extractText(mimeType: string, bytes: Buffer): Promise<string> {
  if (mimeType === "application/pdf") {
    const pdfParse = (await import("pdf-parse")).default as unknown as (
      data: Buffer,
      options?: { max?: number },
    ) => Promise<{ text: string }>;
    const parsed = await pdfParse(bytes, { max: 400 });
    return String(parsed.text || "")
      .replace(/\r\n?/g, "\n")
      .replace(/[ \t]+\n/g, "\n")
      .trim();
  }
  const text = bytes.toString("utf8");
  if (mimeType === "text/html") return stripHtml(text);
  if (mimeType === "application/json") {
    try {
      const j = JSON.parse(text);
      // STIX-ish / MISP-ish / arbitrary: flatten string leaves.
      const parts: string[] = [];
      const walk = (v: unknown, depth: number) => {
        if (depth > 6 || parts.length > 5000) return;
        if (typeof v === "string") {
          if (v.trim()) parts.push(v.trim());
          return;
        }
        if (Array.isArray(v)) {
          for (const x of v) walk(x, depth + 1);
          return;
        }
        if (v && typeof v === "object") {
          for (const x of Object.values(v)) walk(x, depth + 1);
        }
      };
      walk(j, 0);
      return parts.join("\n");
    } catch {
      return text;
    }
  }
  return text.replace(/\r\n?/g, "\n").trim();
}

function ensureUploadSource(): void {
  const seed = OSINT_SOURCES.find((s) => s.id === UPLOAD_SOURCE_ID);
  sqlite
    .prepare(
      `
    INSERT INTO osint_sources (id, category, name, url, language, region, reliability, enabled)
    VALUES (?, ?, ?, ?, 'en', NULL, ?, 1)
    ON CONFLICT(id) DO NOTHING
  `,
    )
    .run(
      UPLOAD_SOURCE_ID,
      seed?.category ?? "THREAT_INTEL",
      seed?.name ?? "Analyst uploads",
      seed?.url ?? "https://threatlens.local/uploads",
      seed?.reliability ?? "B",
    );
}

function deriveTitle(filename: string, text: string): string {
  // Strip markdown heading / emphasis punctuation so the finding title reads
  // as a title, not as source markup.
  const firstLine = text
    .split("\n")
    .map((l) =>
      l
        .trim()
        .replace(/^#{1,6}\s*/, "")
        .replace(/^[*_~`>\s-]+/, "")
        .replace(/[*_~`\s]+$/, "")
        .trim(),
    )
    .find((l) => l.length >= 12 && l.length <= 160 && !/^https?:/i.test(l));
  const base = firstLine || filename.replace(/\.[a-z0-9]+$/i, "").replace(/[_-]+/g, " ");
  return base.slice(0, 280);
}

export async function ingestDocument(
  tenantId: string,
  input: {
    filename: string;
    mimeType: string;
    contentBase64: string;
    title?: string;
    origin?: string;
    tlp?: string;
    publishedAt?: string;
  },
  actor: string,
): Promise<DocumentIngestResultDTO> {
  const bytes = Buffer.from(input.contentBase64.replace(/^data:[^;]+;base64,/, ""), "base64");
  if (bytes.length === 0) {
    const e = new Error("empty document");
    (e as any).status = 400;
    throw e;
  }
  if (bytes.length > MAX_BYTES) {
    const e = new Error(`document exceeds ${MAX_BYTES / 1024 / 1024} MB`);
    (e as any).status = 413;
    throw e;
  }
  if (input.mimeType === "application/pdf" && bytes.subarray(0, 5).toString("latin1") !== "%PDF-") {
    const e = new Error("file is not a PDF (magic bytes mismatch)");
    (e as any).status = 400;
    throw e;
  }

  let text = await extractText(input.mimeType, bytes);
  if (text.length > MAX_TEXT_CHARS) text = text.slice(0, MAX_TEXT_CHARS);
  if (text.replace(/\s+/g, "").length < 40) {
    const e = new Error("no extractable text in document (scanned PDF?)");
    (e as any).status = 422;
    throw e;
  }

  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const dup = sqlite
    .prepare("SELECT finding_id FROM analyst_documents WHERE tenant_id = ? AND sha256 = ? AND finding_id IS NOT NULL")
    .get(tenantId, sha256) as any;
  if (dup?.finding_id) {
    const existing = storage.getOsintFinding(tenantId, dup.finding_id);
    if (existing) {
      const e = new Error(`this document was already ingested as finding "${existing.title}"`);
      (e as any).status = 409;
      (e as any).findingId = existing.id;
      throw e;
    }
  }

  ensureUploadSource();
  const title = (input.title?.trim() || deriveTitle(input.filename, text)).slice(0, 280);
  const cveIds = extractCves(text).slice(0, 25);
  const iocs = extractIoCs(text, null);
  const affectedTech = detectTech(text);
  const threatActors = detectActors(text);
  const severity = severityFromText(`${title} ${text.slice(0, 5000)}`);
  const publishedAt = input.publishedAt ? new Date(input.publishedAt).toISOString() : new Date().toISOString();
  const now = new Date().toISOString();

  // Persist original bytes (analyst-only; never served publicly).
  let storedPath: string | null = null;
  const docId = randomUUID();
  try {
    mkdirSync(UPLOADS_DIR, { recursive: true });
    const ext = MIME_EXT[input.mimeType] ?? "bin";
    storedPath = join(UPLOADS_DIR, `${docId}.${ext}`);
    writeFileSync(storedPath, bytes, { mode: 0o600 });
  } catch (e) {
    console.warn("[documents] could not persist original bytes:", (e as Error).message);
    storedPath = null;
  }

  const findingId = randomUUID();
  const originLabel = input.origin?.trim() || "analyst upload";
  const summary = text.replace(/\s+/g, " ").slice(0, 320);
  const rawSnippet = `[${originLabel}] ${input.filename}\nTLP:${input.tlp ?? "AMBER"}\n\n${text.slice(0, 2000)}`;
  sqlite.transaction(() => {
    sqlite
      .prepare(
        `INSERT INTO osint_findings (
      id, tenant_id, source_id, title, url, published_at, severity,
      cve_ids, affected_tech, threat_actors, iocs, content_hash, summary, raw_snippet,
      source_content, source_fetched_at,
      analyst_tags, status, created_at
    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)`,
      )
      .run(
        findingId,
        tenantId,
        UPLOAD_SOURCE_ID,
        title,
        publishedAt,
        severity,
        JSON.stringify(cveIds),
        JSON.stringify(affectedTech),
        JSON.stringify(threatActors),
        JSON.stringify(iocs),
        `doc:${sha256}`,
        summary,
        rawSnippet,
        text,
        now,
        JSON.stringify([`origin:${originLabel}`, `tlp:${input.tlp ?? "AMBER"}`, "uploaded-document"]),
        now,
      );
    sqlite
      .prepare(
        `INSERT INTO analyst_documents (id, tenant_id, finding_id, filename, mime_type, bytes, sha256, stored_path, origin, tlp, uploaded_by, uploaded_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        docId,
        tenantId,
        findingId,
        input.filename,
        input.mimeType,
        bytes.length,
        sha256,
        storedPath,
        originLabel,
        input.tlp ?? "AMBER",
        actor,
        now,
      );
  })();
  try {
    ensureClusterIdPersisted(sqlite, findingId);
  } catch {
    /* best-effort */
  }
  storage.appendAudit(tenantId, actor, "osint.document.ingest", findingId, {
    filename: input.filename,
    mimeType: input.mimeType,
    bytes: bytes.length,
    sha256,
    cves: cveIds.length,
    origin: originLabel,
  });

  const iocCounts: Record<string, number> = {};
  for (const [k, v] of Object.entries(iocs)) if (Array.isArray(v) && v.length) iocCounts[k] = v.length;
  return { findingId, title, extractedChars: text.length, cveIds, iocCounts, affectedTech, threatActors, storedPath };
}

export function listDocuments(tenantId: string, limit = 100) {
  return sqlite
    .prepare(
      `
    SELECT d.id, d.finding_id AS findingId, d.filename, d.mime_type AS mimeType, d.bytes, d.sha256, d.origin, d.tlp,
           d.uploaded_by AS uploadedBy, d.uploaded_at AS uploadedAt, f.title AS findingTitle, f.status AS findingStatus
    FROM analyst_documents d LEFT JOIN osint_findings f ON f.id = d.finding_id
    WHERE d.tenant_id = ?
    ORDER BY d.uploaded_at DESC LIMIT ?
  `,
    )
    .all(tenantId, Math.max(1, Math.min(500, limit)));
}
