export type AccessMode = "credentialed" | "guest";

export type Capability =
  | "view_intel"
  | "view_tap"
  | "view_hunt_queries"
  | "task_analysis"
  | "manage_sources"
  | "configure_ai"
  | "view_jobs"
  | "manage_jobs"
  | "manage_cases"
  | "record_hunt_results"
  | "upload_documents"
  | "export_reports"
  | "global_view"
  | "full_platform";

const BATCH_ONE_REVIEW_CAPABILITIES: Capability[] = [
  "view_intel",
  "view_tap",
  "view_hunt_queries",
  "task_analysis",
  "view_jobs",
  // Review access does the triage work: owns cases, records what a hunt found,
  // pulls reports. Still cannot change sources, providers or platform users.
  "manage_cases",
  "record_hunt_results",
  "export_reports",
];

const BATCH_ONE_OPERATOR_CAPABILITIES: Capability[] = [
  ...BATCH_ONE_REVIEW_CAPABILITIES,
  "manage_sources",
  "configure_ai",
  "manage_jobs",
  "upload_documents",
];

const FULL_PLATFORM_ADMIN_CAPABILITIES: Capability[] = [
  ...BATCH_ONE_OPERATOR_CAPABILITIES,
  "global_view",
  "full_platform",
];

export function resolveCapabilities(opts: {
  role?: string | null;
  accessMode?: AccessMode | null;
  batchOne?: boolean;
}): Capability[] {
  const role = opts.role ?? "analyst";
  const accessMode = opts.accessMode ?? "credentialed";
  const unique = (items: Capability[]) => Array.from(new Set(items));

  if (opts.batchOne) {
    return unique(
      accessMode === "guest" || role === "reviewer" ? BATCH_ONE_REVIEW_CAPABILITIES : BATCH_ONE_OPERATOR_CAPABILITIES,
    );
  }

  if (role === "admin" || role === "owner") return unique(FULL_PLATFORM_ADMIN_CAPABILITIES);
  return unique(BATCH_ONE_REVIEW_CAPABILITIES);
}

export function hasCapability(capabilities: readonly Capability[] | undefined | null, capability: Capability): boolean {
  return !!capabilities?.includes(capability);
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

function matches(path: string, pattern: string | RegExp): boolean {
  return typeof pattern === "string" ? path === pattern : pattern.test(path);
}

const BATCH_ONE_GUEST_API_ALLOW: Partial<Record<Method, Array<string | RegExp>>> = {
  GET: [
    "/api/v1/me",
    "/api/v1/search",
    "/api/v1/auth/mfa/setup",
    "/api/v1/taxonomies",
    "/api/v1/ai/providers",
    "/api/v1/ai/assignments",
    "/api/v1/threat-actors",
    "/api/v1/threat-actors/_meta",
    "/api/v1/threat-actors/portrait-generator/availability",
    /^\/api\/v1\/threat-actors\/[^/]+(?:\/full|\/export\.docx)?$/,
    "/api/v1/osint/findings",
    /^\/api\/v1\/osint\/findings\/[^/]+$/,
    /^\/api\/v1\/osint\/findings\/[^/]+\/cirt-cache$/,
    "/api/v1/osint/sources",
    "/api/v1/osint/hunt-queries",
    "/api/v1/osint/ai-jobs/history",
    /^\/api\/v1\/osint\/ai-jobs\/[^/]+$/,
    "/api/v1/ai-jobs/active",
    /^\/api\/v1\/ai-jobs\/[^/]+(?:\/full)?$/,
    "/api/v1/operations/audit",
    /^\/api\/v1\/exchange\/stix\/(?:preview|export)$/,
    // Tier B — analyst workflow reads
    "/api/v1/cases",
    "/api/v1/cases/for-entity",
    /^\/api\/v1\/cases\/[^/]+$/,
    /^\/api\/v1\/osint\/hunt-queries\/[^/]+\/results$/,
    "/api/v1/osint/hunt-results/latest",
    "/api/v1/osint/cve",
    "/api/v1/osint/cve/pending",
    "/api/v1/osint/review/metrics",
    "/api/v1/osint/review/queue",
    "/api/v1/osint/documents",
    "/api/v1/osint/attack-coverage",
    "/api/v1/org/assets",
    "/api/v1/org/exposure",
    "/api/v1/detections/iocs/export",
    "/api/v1/detections/iocs",
    "/api/v1/detections/iocs/summary",
    "/api/v1/detections/rules",
    "/api/v1/detections/rules/summary",
    /^\/api\/v1\/detections\/rules\/[^/]+$/,
    /^\/api\/v1\/detections\/rules\/[^/]+\/convert$/,
    "/api/v1/detections/attack/matrix",
    /^\/api\/v1\/detections\/attack\/techniques\/[^/]+$/,
    "/api/v1/detections/coverage",
    "/api/v1/detections/sync/status",
    "/api/v1/osint/attack-coverage/navigator-layer.json",
    /^\/api\/v1\/threat-actors\/[^/]+\/navigator-layer\.json$/,
  ],
  POST: [
    "/api/v1/auth/logout",
    "/api/v1/auth/change-password",
    "/api/v1/auth/mfa/verify",
    "/api/v1/osint/findings/ai-analyze",
    "/api/v1/osint/chat/triage",
    "/api/v1/osint/chat/deep-dive",
    "/api/v1/osint/chat/converse",
    // Tier B — cases, hunt outcomes, CVE enrichment, reports
    "/api/v1/cases",
    /^\/api\/v1\/cases\/[^/]+\/(?:links|notes)$/,
    /^\/api\/v1\/osint\/hunt-queries\/[^/]+\/results$/,
    "/api/v1/osint/cve/enrich",
    "/api/v1/reports/brief",
  ],
};

const BATCH_ONE_OPERATOR_API_ALLOW: Partial<Record<Method, Array<string | RegExp>>> = {
  GET: [
    ...(BATCH_ONE_GUEST_API_ALLOW.GET ?? []),
    "/api/v1/admin/platform-users",
    "/api/v1/osint/sources/analytics",
    "/api/v1/osint/sources/health",
    "/api/v1/osint/sources/heatmaps",
    "/api/v1/osint/sources/overlap",
    "/api/v1/osint/sources/quadrant",
    "/api/v1/osint/sources/scorecard",
    "/api/v1/osint/automation/settings",
    "/api/v1/admin/osint/ingest/status",
    /^\/api\/v1\/osint\/reanalyze-jobs\/[^/]+$/,
    "/api/v1/osint/dictionaries",
    "/api/v1/operations/audit",
    "/api/v1/scans",
  ],
  POST: [
    ...(BATCH_ONE_GUEST_API_ALLOW.POST ?? []),
    "/api/v1/osint/sources/bulk",
    "/api/v1/osint/findings/reanalyze",
    "/api/v1/osint/scan",
    "/api/v1/osint/automation/fetch-now",
    "/api/v1/osint/automation/analyze-now",
    "/api/v1/osint/automation/reset-cache",
    "/api/v1/admin/osint/ingest",
    "/api/v1/osint/overview",
    "/api/v1/osint/hunt-queries",
    "/api/v1/ai/providers",
    /^\/api\/v1\/ai\/providers\/[^/]+\/test$/,
    "/api/v1/threat-actors",
    "/api/v1/admin/platform-users",
    // `bulk` is a literal path segment, so the :uid regex below never matches
    // it — without this entry the Platform Users bulk action always 403s.
    "/api/v1/admin/platform-users/bulk",
    /^\/api\/v1\/admin\/platform-users\/[^/]+\/(?:reset-mfa|disable)$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/(?:portrait|portrait\/upload|enrich|ttps|tools|campaigns|iocs|references|rule-links)$/,
    "/api/v1/operations/jobs/cancel-running",
    /^\/api\/v1\/operations\/jobs\/[^/]+\/[^/]+\/cancel$/,
    // Tier B — operators may also ingest private documents
    "/api/v1/osint/documents",
    // Organization profile — operators maintain the tech stack
    "/api/v1/org/assets",
    "/api/v1/org/assets/bulk",
    "/api/v1/detections/sync",
  ],
  PUT: [/^\/api\/v1\/ai\/providers\/[^/]+$/, /^\/api\/v1\/admin\/platform-users\/[^/]+$/, "/api/v1/ai/assignments"],
  PATCH: [
    /^\/api\/v1\/org\/assets\/[^/]+$/,
    /^\/api\/v1\/osint\/findings\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+$/,
    "/api/v1/osint/automation/settings",
    /^\/api\/v1\/cases\/[^/]+$/,
    /^\/api\/v1\/osint\/findings\/[^/]+\/review$/,
    /^\/api\/v1\/org\/assets\/[^/]+$/,
  ],
  DELETE: [
    /^\/api\/v1\/org\/assets\/[^/]+$/,
    /^\/api\/v1\/org\/assets\/[^/]+$/,
    /^\/api\/v1\/cases\/[^/]+$/,
    /^\/api\/v1\/cases\/[^/]+\/(?:links|notes)\/[^/]+$/,
    /^\/api\/v1\/osint\/hunt-queries\/[^/]+\/results\/[^/]+$/,
    /^\/api\/v1\/ai\/providers\/[^/]+$/,
    /^\/api\/v1\/admin\/platform-users\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/portrait$/,
    /^\/api\/v1\/threat-actors\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/(?:ttps|tools|campaigns|iocs|references)\/[^/]+$/,
    /^\/api\/v1\/threat-actors\/[^/]+\/rule-links\/[^/]+$/,
  ],
};

// Review-access analysts may still edit the workflow objects they own: their
// cases (status, notes, links), finding triage/assignment, and hunt outcomes.
const BATCH_ONE_GUEST_WRITE_ALLOW: Partial<Record<Method, Array<string | RegExp>>> = {
  PATCH: [
    /^\/api\/v1\/cases\/[^/]+$/,
    /^\/api\/v1\/osint\/findings\/[^/]+$/,
    /^\/api\/v1\/osint\/findings\/[^/]+\/review$/,
  ],
  DELETE: [
    /^\/api\/v1\/cases\/[^/]+\/(?:links|notes)\/[^/]+$/,
    /^\/api\/v1\/osint\/hunt-queries\/[^/]+\/results\/[^/]+$/,
  ],
};

export function isBatchOneApiAllowed(opts: { method: string; path: string; accessMode?: AccessMode | null }): boolean {
  const method = opts.method.toUpperCase() as Method;
  if (method === "HEAD" || method === "OPTIONS") return true;
  if (opts.accessMode === "guest") {
    const guest = [...(BATCH_ONE_GUEST_API_ALLOW[method] ?? []), ...(BATCH_ONE_GUEST_WRITE_ALLOW[method] ?? [])];
    return guest.some((pattern) => matches(opts.path, pattern));
  }
  return (BATCH_ONE_OPERATOR_API_ALLOW[method] ?? []).some((pattern) => matches(opts.path, pattern));
}
