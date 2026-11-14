import type Database from "better-sqlite3";

/**
 * Tables and columns for the Tier B analyst-workflow features: cases, hunt
 * result capture, CVE enrichment, review-queue ownership/SLA, document
 * ingest. Idempotent; called from storage.ts right after ensureSchema().
 */
export function ensureTierBSchema(sqlite: Database.Database): void {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS investigations (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      severity TEXT NOT NULL DEFAULT 'medium',
      summary TEXT, assignee TEXT,
      source_type TEXT, source_id TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_investigations_tenant ON investigations(tenant_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS investigation_links (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
      label TEXT,
      created_at TEXT NOT NULL, created_by TEXT NOT NULL,
      UNIQUE(investigation_id, entity_type, entity_id)
    );
    CREATE INDEX IF NOT EXISTS idx_investigation_links_inv ON investigation_links(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_investigation_links_entity ON investigation_links(tenant_id, entity_type, entity_id);
    CREATE TABLE IF NOT EXISTS investigation_notes (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      investigation_id TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'analyst',
      body TEXT NOT NULL,
      created_at TEXT NOT NULL, created_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_investigation_notes_inv ON investigation_notes(investigation_id, created_at);

    CREATE TABLE IF NOT EXISTS org_assets (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'product',
      criticality TEXT NOT NULL DEFAULT 'medium',
      aliases TEXT NOT NULL DEFAULT '[]',
      notes TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL,
      UNIQUE(tenant_id, name)
    );
    CREATE INDEX IF NOT EXISTS idx_org_assets_tenant ON org_assets(tenant_id);

    CREATE TABLE IF NOT EXISTS ioc_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ioc_type TEXT NOT NULL, value TEXT NOT NULL, name TEXT NOT NULL,
      source TEXT NOT NULL, port INTEGER, status TEXT,
      first_seen TEXT, last_seen TEXT, confidence INTEGER NOT NULL DEFAULT 50,
      fetched_at TEXT NOT NULL,
      UNIQUE(ioc_type, value, source)
    );
    CREATE INDEX IF NOT EXISTS idx_ioc_intel_name ON ioc_intel(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_ioc_intel_seen ON ioc_intel(last_seen DESC);

    CREATE TABLE IF NOT EXISTS rule_library (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL, rule_id TEXT NOT NULL,
      title TEXT NOT NULL, status TEXT, level TEXT, description TEXT, author TEXT,
      tags TEXT NOT NULL DEFAULT '[]', techniques TEXT NOT NULL DEFAULT '[]',
      cves TEXT NOT NULL DEFAULT '[]', refs TEXT NOT NULL DEFAULT '[]',
      product TEXT, category TEXT, service TEXT,
      raw TEXT NOT NULL, path TEXT, modified TEXT, license TEXT, synced_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rule_library_level ON rule_library(level);
    CREATE INDEX IF NOT EXISTS idx_rule_library_product ON rule_library(product);

    CREATE TABLE IF NOT EXISTS attack_tactics (
      shortname TEXT PRIMARY KEY, name TEXT NOT NULL, ext_id TEXT, ord INTEGER NOT NULL DEFAULT 999
    );
    CREATE TABLE IF NOT EXISTS attack_techniques (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, is_sub INTEGER NOT NULL DEFAULT 0, parent TEXT,
      tactics TEXT NOT NULL DEFAULT '[]', description TEXT, detection TEXT,
      platforms TEXT NOT NULL DEFAULT '[]', url TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_attack_techniques_parent ON attack_techniques(parent);
    CREATE TABLE IF NOT EXISTS attack_detections (
      technique_id TEXT NOT NULL, det_id TEXT NOT NULL, name TEXT NOT NULL, url TEXT,
      analytics TEXT NOT NULL DEFAULT '[]',
      PRIMARY KEY (technique_id, det_id)
    );

    CREATE TABLE IF NOT EXISTS intel_sync_state (
      key TEXT PRIMARY KEY, last_run TEXT, item_count INTEGER NOT NULL DEFAULT 0, last_error TEXT
    );

    CREATE TABLE IF NOT EXISTS hunt_results (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      hunt_query_id TEXT NOT NULL,
      language TEXT NOT NULL,
      outcome TEXT NOT NULL,
      hit_count INTEGER,
      evidence TEXT, notes TEXT,
      recorded_by TEXT NOT NULL, recorded_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_hunt_results_query ON hunt_results(hunt_query_id, recorded_at DESC);

    CREATE TABLE IF NOT EXISTS cve_enrichment (
      cve_id TEXT PRIMARY KEY,
      cvss_score REAL, cvss_vector TEXT, cvss_severity TEXT,
      epss_score REAL, epss_percentile REAL,
      kev INTEGER NOT NULL DEFAULT 0, kev_date_added TEXT, kev_known_ransomware INTEGER NOT NULL DEFAULT 0,
      published_at TEXT, description TEXT,
      nvd_checked_at TEXT, epss_checked_at TEXT, kev_checked_at TEXT,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cve_enrichment_kev ON cve_enrichment(kev, epss_score DESC);

    CREATE TABLE IF NOT EXISTS analyst_documents (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
      finding_id TEXT,
      filename TEXT NOT NULL, mime_type TEXT NOT NULL,
      bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
      stored_path TEXT,
      origin TEXT, tlp TEXT NOT NULL DEFAULT 'AMBER',
      uploaded_by TEXT NOT NULL, uploaded_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_analyst_documents_tenant ON analyst_documents(tenant_id, uploaded_at DESC);
  `);

  const alters = [
    `ALTER TABLE osint_findings ADD COLUMN assignee TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN due_at TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN triaged_at TEXT`,
    `ALTER TABLE osint_findings ADD COLUMN closed_at TEXT`,
  ];
  for (const stmt of alters) {
    try {
      sqlite.exec(stmt);
    } catch (e: any) {
      if (!/duplicate column/i.test(String(e?.message ?? ""))) throw e;
    }
  }
  sqlite.exec(`
    CREATE INDEX IF NOT EXISTS idx_osint_findings_queue ON osint_findings(tenant_id, status, due_at);
    CREATE INDEX IF NOT EXISTS idx_osint_findings_assignee ON osint_findings(tenant_id, assignee);
  `);
}
