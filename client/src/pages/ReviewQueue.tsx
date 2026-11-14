import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { STATIC_DEMO_MODE } from "@/lib/staticDemoApi";
import { showStaticDemoNotice } from "@/lib/staticDemoNotice";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { OrgBadge, OrgScopeToggle } from "@/components/OrgScope";
import { useOrgScope } from "@/lib/orgScope";
import type { OsintFindingDTO, ReviewQueueMetricsDTO } from "@shared/schema";
import {
  ListChecks,
  ShieldAlert,
  Clock,
  UserPlus,
  FileDown,
  Upload,
  Grid3x3,
  Loader2,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";

interface QueueResp {
  findings: OsintFindingDTO[];
  total: number;
}
interface DocumentRow {
  id: string;
  findingId: string | null;
  filename: string;
  mimeType: string;
  bytes: number;
  origin: string | null;
  tlp: string;
  uploadedBy: string;
  uploadedAt: string;
  findingTitle: string | null;
  findingStatus: string | null;
}
interface CoverageTechnique {
  id: string;
  name: string | null;
  tactics: string[];
  coverage: string;
  findings: number;
  actors: number;
  huntQueries: number;
}
interface CoverageResp {
  counts: { hit: number; hunted: number; drafted: number; none: number };
  techniqueCount: number;
  tacticOrder?: Array<{ slug: string; label: string; id: string }>;
  techniques: CoverageTechnique[];
}

/** Solid fills for matrix cells — the badge tones are too faint to read as a heat map. */
const COVERAGE_CELL: Record<string, string> = {
  hit: "bg-emerald-500/85 text-white border-emerald-600/40",
  hunted: "bg-indigo-500/80 text-white border-indigo-600/40",
  drafted: "bg-amber-400/85 text-amber-950 border-amber-500/40",
  none: "bg-rose-500/20 text-rose-900 dark:text-rose-200 border-rose-500/40",
};
const COVERAGE_LABEL: Record<string, string> = {
  hit: "Hunted — hit recorded",
  hunted: "Hunted — no hit",
  drafted: "Query drafted, never run",
  none: "Observed, no hunt written",
};

function guard(): boolean {
  if (STATIC_DEMO_MODE) {
    showStaticDemoNotice({ kind: "write", action: "Queue editing restricted" });
    return true;
  }
  return false;
}

export default function ReviewQueue() {
  return (
    <AppShell>
      <div className="px-4 md:px-10 py-6 md:py-8 max-w-[1400px]">
        <PageHeader
          title="Analyst Queue"
          description="Work the queue by exploitation evidence, track triage SLAs, ingest private intel, check hunt coverage and pull briefs."
        />
        <Tabs defaultValue="queue">
          <TabsList className="mb-4">
            <TabsTrigger value="queue" data-testid="tab-queue">
              Queue
            </TabsTrigger>
            <TabsTrigger value="metrics" data-testid="tab-metrics">
              SLA metrics
            </TabsTrigger>
            <TabsTrigger value="coverage" data-testid="tab-coverage">
              ATT&amp;CK coverage
            </TabsTrigger>
            <TabsTrigger value="documents" data-testid="tab-documents">
              Private intel
            </TabsTrigger>
            <TabsTrigger value="reports" data-testid="tab-reports">
              Reports
            </TabsTrigger>
          </TabsList>
          <TabsContent value="queue" className="mt-0">
            <QueueTab />
          </TabsContent>
          <TabsContent value="metrics" className="mt-0">
            <MetricsTab />
          </TabsContent>
          <TabsContent value="coverage" className="mt-0">
            <CoverageTab />
          </TabsContent>
          <TabsContent value="documents" className="mt-0">
            <DocumentsTab />
          </TabsContent>
          <TabsContent value="reports" className="mt-0">
            <ReportsTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}

// ---------------------------------------------------------------- queue

function QueueTab() {
  const { toast } = useToast();
  const { user } = useAuth();
  const [mineOnly, setMineOnly] = useState(false);
  const { data, isLoading } = useQuery<QueueResp>({
    queryKey: ["/api/v1/osint/review/queue"],
  });
  const [orgScope] = useOrgScope();
  const orgMatchedCount = useMemo(() => (data?.findings ?? []).filter((f) => f.orgRelevance).length, [data]);
  // The server already ranks the queue with org exposure boosted; "My
  // organization" additionally hides everything that does not match the profile.
  const findings = useMemo(() => {
    let all = data?.findings ?? [];
    if (orgScope === "org") all = all.filter((f) => f.orgRelevance);
    return mineOnly ? all.filter((f) => f.assignee === user?.email) : all;
  }, [data, mineOnly, orgScope, user?.email]);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/review/queue"] });
    queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/review/metrics"] });
  };
  const review = useMutation({
    mutationFn: async (v: { id: string; assignee?: string | null; dueAt?: string | null }) =>
      (
        await apiRequest("PATCH", `/api/v1/osint/findings/${v.id}/review`, { assignee: v.assignee, dueAt: v.dueAt })
      ).json(),
    onSuccess: invalidate,
    onError: (e: any) =>
      toast({ variant: "destructive", title: "Update failed", description: String(e?.message ?? e) }),
  });
  const setStatus = useMutation({
    mutationFn: async (v: { id: string; status: string }) =>
      (await apiRequest("PATCH", `/api/v1/osint/findings/${v.id}`, { status: v.status })).json(),
    onSuccess: () => {
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] });
    },
    onError: (e: any) =>
      toast({ variant: "destructive", title: "Status change failed", description: String(e?.message ?? e) }),
  });

  const nowIso = new Date().toISOString();
  return (
    <div className="space-y-3">
      <OrgScopeToggle matchedCount={orgMatchedCount} />
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant={mineOnly ? "default" : "outline"}
          className="h-7"
          onClick={() => setMineOnly((v) => !v)}
          data-testid="button-filter-mine"
        >
          Assigned to me
        </Button>
        <span className="text-xs text-muted-foreground">
          {findings.length} shown · {data?.total ?? 0} open
        </span>
        <Button
          size="sm"
          variant="ghost"
          className="h-7 ml-auto"
          onClick={invalidate}
          data-testid="button-refresh-queue"
        >
          <RefreshCw size={12} className="mr-1" /> Refresh
        </Button>
      </div>

      {isLoading ? (
        <Card className="p-8 text-center text-sm text-muted-foreground">Loading queue…</Card>
      ) : findings.length === 0 ? (
        <Card className="p-10 text-center">
          <CheckCircle2 size={24} className="mx-auto mb-2 text-signal" />
          <div className="text-sm font-medium">Queue clear</div>
          <p className="text-xs text-muted-foreground mt-1">Nothing open matching this filter.</p>
        </Card>
      ) : (
        <div className="space-y-1.5">
          {findings.slice(0, 100).map((f) => {
            const overdue = !!f.dueAt && f.dueAt < nowIso;
            const cve = f.cveEnrichment;
            return (
              <Card
                key={f.id}
                className={cn("p-2.5", overdue && "border-[hsl(var(--sev-high))]/50")}
                data-testid={`row-queue-${f.id}`}
              >
                <div className="flex items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <OrgBadge relevance={f.orgRelevance} testId={`badge-org-${f.id}`} />
                      {cve?.kev && (
                        <Badge
                          variant="outline"
                          className="text-[9px] bg-[hsl(var(--sev-critical))]/12 text-[hsl(var(--sev-critical))] border-[hsl(var(--sev-critical))]/30"
                          data-testid={`badge-kev-${f.id}`}
                        >
                          KEV
                        </Badge>
                      )}
                      {typeof cve?.epssScore === "number" && cve.epssScore >= 0.1 && (
                        <Badge variant="outline" className="text-[9px]">
                          EPSS {Math.round(cve.epssScore * 100)}%
                        </Badge>
                      )}
                      {typeof cve?.cvssScore === "number" && (
                        <Badge variant="outline" className="text-[9px]">
                          CVSS {cve.cvssScore}
                        </Badge>
                      )}
                      <Badge variant="outline" className="text-[9px] capitalize">
                        {f.severity}
                      </Badge>
                      <Badge variant="secondary" className="text-[9px] capitalize">
                        {f.status}
                      </Badge>
                      {overdue && (
                        <Badge
                          variant="outline"
                          className="text-[9px] bg-[hsl(var(--sev-high))]/12 text-[hsl(var(--sev-high))] border-[hsl(var(--sev-high))]/30"
                        >
                          overdue
                        </Badge>
                      )}
                    </div>
                    <a
                      className="text-xs font-medium hover:underline block mt-1 truncate"
                      href={`#/osint?finding=${encodeURIComponent(f.id)}`}
                      data-testid={`link-finding-${f.id}`}
                    >
                      {f.title}
                    </a>
                    <div className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-2 flex-wrap">
                      <span>{f.sourceName}</span>
                      <span>{relativeTime(f.publishedAt)}</span>
                      {f.assignee && (
                        <span className="inline-flex items-center gap-1">
                          <UserPlus size={9} /> {f.assignee}
                        </span>
                      )}
                      {f.dueAt && (
                        <span className="inline-flex items-center gap-1">
                          <Clock size={9} /> due {String(f.dueAt).slice(0, 10)}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-[10px]"
                      onClick={() => {
                        if (!guard())
                          review.mutate({
                            id: f.id,
                            assignee: f.assignee === user?.email ? null : (user?.email ?? null),
                          });
                      }}
                      data-testid={`button-claim-${f.id}`}
                    >
                      {f.assignee === user?.email ? "Unclaim" : "Claim"}
                    </Button>
                    <Select
                      value={f.status}
                      onValueChange={(v) => {
                        if (!guard()) setStatus.mutate({ id: f.id, status: v });
                      }}
                    >
                      <SelectTrigger className="h-7 w-[110px] text-[10px]" data-testid={`select-status-${f.id}`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {["new", "triaged", "assessed", "escalated", "dismissed"].map((s) => (
                          <SelectItem key={s} value={s}>
                            {s}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- metrics

function MetricsTab() {
  const [days, setDays] = useState("30");
  const { data } = useQuery<ReviewQueueMetricsDTO>({
    queryKey: ["/api/v1/osint/review/metrics", days],
    queryFn: async () => (await apiRequest("GET", `/api/v1/osint/review/metrics?days=${days}`)).json(),
  });
  if (!data) return <Card className="p-8 text-center text-sm text-muted-foreground">Loading metrics…</Card>;
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Label className="text-xs text-muted-foreground">Window</Label>
        <Select value={days} onValueChange={setDays}>
          <SelectTrigger className="h-7 w-[120px] text-xs" data-testid="select-metrics-window">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {["7", "14", "30", "90"].map((d) => (
              <SelectItem key={d} value={d}>
                {d} days
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Open" value={data.backlog.total} icon={<ListChecks size={14} />} />
        <Stat
          label="Overdue"
          value={data.backlog.overdue}
          tone={data.backlog.overdue > 0 ? "warn" : undefined}
          icon={<Clock size={14} />}
        />
        <Stat label="Unassigned" value={data.backlog.unassigned} icon={<UserPlus size={14} />} />
        <Stat
          label="KEV open"
          value={data.exploited.kevOpen}
          tone={data.exploited.kevOpen > 0 ? "danger" : undefined}
          icon={<ShieldAlert size={14} />}
        />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Card className="p-3">
          <div className="text-xs font-semibold mb-2">Backlog age</div>
          {[
            ["< 24h", data.backlog.byAge.lt24h],
            ["1–3 days", data.backlog.byAge.d1to3],
            ["3–7 days", data.backlog.byAge.d3to7],
            ["> 7 days", data.backlog.byAge.gt7d],
          ].map(([l, v]) => (
            <div key={String(l)} className="flex justify-between text-xs py-0.5">
              <span className="text-muted-foreground">{l}</span>
              <span className="font-mono">{v}</span>
            </div>
          ))}
        </Card>
        <Card className="p-3">
          <div className="text-xs font-semibold mb-2">Throughput ({data.windowDays}d)</div>
          {[
            ["Triaged", data.throughput.triaged],
            ["Dismissed", data.throughput.dismissed],
            ["Escalated", data.throughput.escalated],
            [
              "Mean time to triage",
              data.throughput.meanTimeToTriageHours != null ? `${data.throughput.meanTimeToTriageHours} h` : "—",
            ],
            [
              "Median time to triage",
              data.throughput.medianTimeToTriageHours != null ? `${data.throughput.medianTimeToTriageHours} h` : "—",
            ],
          ].map(([l, v]) => (
            <div key={String(l)} className="flex justify-between text-xs py-0.5">
              <span className="text-muted-foreground">{l}</span>
              <span className="font-mono">{v}</span>
            </div>
          ))}
        </Card>
      </div>
      {data.bySource.length > 0 && (
        <Card className="p-3">
          <div className="text-xs font-semibold mb-2">Source signal quality</div>
          <p className="text-[10px] text-muted-foreground mb-2">
            A high dismissal rate means the source costs analyst time without producing action.
          </p>
          <div className="space-y-1">
            {data.bySource.slice(0, 12).map((s) => (
              <div
                key={s.sourceId}
                className="flex items-center gap-2 text-xs"
                data-testid={`row-source-quality-${s.sourceId}`}
              >
                <span className="truncate flex-1">{s.sourceName}</span>
                <span className="font-mono text-muted-foreground">{s.total}</span>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[9px]",
                    s.dismissalRate > 0.5 &&
                      "bg-[hsl(var(--sev-high))]/12 text-[hsl(var(--sev-high))] border-[hsl(var(--sev-high))]/30",
                  )}
                >
                  {Math.round(s.dismissalRate * 100)}% dismissed
                </Badge>
              </div>
            ))}
          </div>
        </Card>
      )}
      {data.byAssignee.length > 0 && (
        <Card className="p-3">
          <div className="text-xs font-semibold mb-2">Load by analyst</div>
          {data.byAssignee.map((a) => (
            <div key={a.assignee} className="flex justify-between text-xs py-0.5">
              <span className="text-muted-foreground">{a.assignee}</span>
              <span className="font-mono">
                {a.open} open{a.overdue ? ` · ${a.overdue} overdue` : ""}
              </span>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: number;
  icon?: React.ReactNode;
  tone?: "warn" | "danger";
}) {
  return (
    <Card
      className={cn(
        "p-3",
        tone === "danger" && "border-[hsl(var(--sev-critical))]/40",
        tone === "warn" && "border-[hsl(var(--sev-high))]/40",
      )}
      data-testid={`stat-${label.toLowerCase().replace(/\s+/g, "-")}`}
    >
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="text-2xl font-semibold mt-1 tabular-nums">{value}</div>
    </Card>
  );
}

// ---------------------------------------------------------------- coverage

/**
 * ATT&CK matrix: tactics as columns in kill-chain order, techniques stacked
 * beneath the tactic they belong to, each cell coloured by hunt coverage.
 *
 * Only tactics that actually contain an observed technique get a column — a
 * full 14-wide Enterprise matrix of mostly-empty columns reads as noise at this
 * data volume. Techniques whose tactic was never recorded are collected into a
 * trailing "Unmapped" column rather than dropped, so the count on screen always
 * reconciles with the totals above it.
 */
function AttackMatrix({ data }: { data: CoverageResp }) {
  const order = data.tacticOrder ?? [];
  const byTactic = new Map<string, CoverageTechnique[]>();
  const unmapped: CoverageTechnique[] = [];

  for (const t of data.techniques) {
    if (!t.tactics || t.tactics.length === 0) {
      unmapped.push(t);
      continue;
    }
    // A technique used across several tactics appears under each, as in ATT&CK.
    for (const slug of t.tactics) {
      if (!byTactic.has(slug)) byTactic.set(slug, []);
      byTactic.get(slug)!.push(t);
    }
  }

  const columns = order
    .filter((tac) => (byTactic.get(tac.slug) ?? []).length > 0)
    .map((tac) => ({ ...tac, techniques: byTactic.get(tac.slug)! }));
  if (unmapped.length > 0) {
    columns.push({ slug: "unmapped", label: "Unmapped", id: "—", techniques: unmapped });
  }

  // Worst coverage first inside a column: the gaps are the point of the view.
  const rank: Record<string, number> = { none: 0, drafted: 1, hunted: 2, hit: 3 };
  for (const c of columns) c.techniques.sort((a, b) => (rank[a.coverage] ?? 0) - (rank[b.coverage] ?? 0) || b.actors - a.actors);

  if (columns.length === 0) {
    return (
      <Card className="p-8 text-center text-sm text-muted-foreground">
        No ATT&amp;CK techniques observed in this window. Techniques appear here once findings are AI-analysed or actor
        dossiers record TTPs.
      </Card>
    );
  }

  return (
    <Card className="p-3">
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1">
        <div className="text-xs font-semibold">
          ATT&amp;CK matrix · {data.techniqueCount} technique{data.techniqueCount === 1 ? "" : "s"} across {columns.length}{" "}
          tactic{columns.length === 1 ? "" : "s"}
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
          {(["hit", "hunted", "drafted", "none"] as const).map((k) => (
            <span key={k} className="inline-flex items-center gap-1">
              <span className={cn("inline-block h-2.5 w-2.5 rounded-sm border", COVERAGE_CELL[k])} />
              {COVERAGE_LABEL[k]}
            </span>
          ))}
        </div>
      </div>

      {/* Tactics can exceed the viewport; the matrix is the one thing allowed to scroll sideways. */}
      <div className="overflow-x-auto">
        <div className="flex gap-2 min-w-max pb-1" data-testid="grid-attack-matrix">
          {columns.map((col) => (
            <div key={col.slug} className="w-[168px] shrink-0">
              <div className="mb-1.5 border-b border-border pb-1">
                <div className="text-[11px] font-semibold leading-tight">{col.label}</div>
                <div className="text-[10px] text-muted-foreground font-mono">
                  {col.id} · {col.techniques.length}
                </div>
              </div>
              <div className="flex flex-col gap-1">
                {col.techniques.map((t) => (
                  <div
                    key={`${col.slug}-${t.id}`}
                    className={cn("rounded-md border px-2 py-1.5 cursor-default transition-transform hover:scale-[1.02]", COVERAGE_CELL[t.coverage])}
                    title={[
                      `${t.id}${t.name ? ` — ${t.name}` : ""}`,
                      COVERAGE_LABEL[t.coverage] ?? t.coverage,
                      `${t.findings} finding(s) in window`,
                      `${t.actors} actor(s) attributed`,
                      `${t.huntQueries} hunt quer${t.huntQueries === 1 ? "y" : "ies"}`,
                    ].join("\n")}
                    data-testid={`cell-technique-${t.id}`}
                  >
                    <div className="font-mono text-[10px] opacity-90">{t.id}</div>
                    {t.name && <div className="text-[11px] font-medium leading-tight line-clamp-2">{t.name}</div>}
                    <div className="mt-0.5 flex items-center gap-2 text-[9px] opacity-80">
                      {t.actors > 0 && <span>{t.actors} actor{t.actors === 1 ? "" : "s"}</span>}
                      {t.findings > 0 && <span>{t.findings} intel</span>}
                      {t.huntQueries > 0 && <span>{t.huntQueries} hunt</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}

function CoverageTab() {
  const { toast } = useToast();
  const [days, setDays] = useState("90");
  const { data } = useQuery<CoverageResp>({
    queryKey: ["/api/v1/osint/attack-coverage", days],
    queryFn: async () => (await apiRequest("GET", `/api/v1/osint/attack-coverage?days=${days}`)).json(),
  });
  const download = async () => {
    try {
      const r = await apiRequest("GET", `/api/v1/osint/attack-coverage/navigator-layer.json?days=${days}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `attack-coverage-${days}d.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e: any) {
      toast({ variant: "destructive", title: "Export failed", description: String(e?.message ?? e) });
    }
  };
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <Select value={days} onValueChange={setDays}>
          <SelectTrigger className="h-7 w-[120px] text-xs" data-testid="select-coverage-window">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {["30", "90", "180", "365"].map((d) => (
              <SelectItem key={d} value={d}>
                {d} days
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button size="sm" variant="outline" className="h-7" onClick={download} data-testid="button-export-navigator">
          <Grid3x3 size={12} className="mr-1" /> ATT&amp;CK Navigator layer
        </Button>
      </div>
      {!data ? (
        <Card className="p-8 text-center text-sm text-muted-foreground">Loading coverage…</Card>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat label="Hunted, hit" value={data.counts.hit} />
            <Stat label="Hunted, no hit" value={data.counts.hunted} />
            <Stat label="Drafted only" value={data.counts.drafted} tone="warn" />
            <Stat label="No hunt" value={data.counts.none} tone="danger" />
          </div>
          <AttackMatrix data={data} />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- documents

function DocumentsTab() {
  const { toast } = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [origin, setOrigin] = useState("");
  const [busy, setBusy] = useState(false);
  const { data } = useQuery<{ documents: DocumentRow[] }>({ queryKey: ["/api/v1/osint/documents"] });

  const upload = async (file: File) => {
    if (guard()) return;
    setBusy(true);
    try {
      const mimeByExt: Record<string, string> = {
        pdf: "application/pdf",
        md: "text/markdown",
        txt: "text/plain",
        html: "text/html",
        json: "application/json",
      };
      const ext = (file.name.split(".").pop() ?? "").toLowerCase();
      const mimeType = mimeByExt[ext];
      if (!mimeType) throw new Error("supported types: pdf, md, txt, html, json");
      const buf = await file.arrayBuffer();
      let binary = "";
      const bytes = new Uint8Array(buf);
      for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
      const r = await apiRequest("POST", "/api/v1/osint/documents", {
        filename: file.name,
        mimeType,
        origin: origin.trim() || undefined,
        contentBase64: btoa(binary),
      });
      const out = await r.json();
      toast({
        title: "Document ingested",
        description: `${out.title} — ${out.cveIds.length} CVE(s), ${Object.values(out.iocCounts as Record<string, number>).reduce((a, b) => a + b, 0)} indicator(s)`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/documents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/review/queue"] });
    } catch (e: any) {
      toast({ variant: "destructive", title: "Upload failed", description: String(e?.message ?? e) });
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return (
    <div className="space-y-3">
      <Card className="p-4">
        <div className="text-sm font-medium mb-1">Ingest private intel</div>
        <p className="text-xs text-muted-foreground mb-3">
          ISAC bulletins, vendor PDFs, incident write-ups. Text is extracted server-side and pushed through the same CVE
          / indicator / actor extraction as feed items, so it triages, hunts and reports like any other finding.
        </p>
        <div className="flex flex-wrap items-end gap-2">
          <div>
            <Label className="text-[10px] text-muted-foreground">Origin label</Label>
            <Input
              value={origin}
              onChange={(e) => setOrigin(e.target.value)}
              placeholder="ACME-ISAC"
              className="h-8 w-[180px] text-xs"
              data-testid="input-doc-origin"
            />
          </div>
          <input
            ref={fileRef}
            type="file"
            accept=".pdf,.md,.txt,.html,.json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void upload(f);
            }}
            data-testid="input-doc-file"
          />
          <Button
            size="sm"
            className="h-8"
            onClick={() => fileRef.current?.click()}
            disabled={busy}
            data-testid="button-upload-doc"
          >
            {busy ? (
              <>
                <Loader2 size={13} className="mr-1.5 animate-spin" /> Extracting
              </>
            ) : (
              <>
                <Upload size={13} className="mr-1.5" /> Choose file
              </>
            )}
          </Button>
          <span className="text-[10px] text-muted-foreground">pdf · md · txt · html · json, max 10 MB</span>
        </div>
      </Card>

      {(data?.documents ?? []).length === 0 ? (
        <Card className="p-8 text-center text-sm text-muted-foreground">No documents ingested yet.</Card>
      ) : (
        <div className="space-y-1.5">
          {data!.documents.map((d) => (
            <Card key={d.id} className="p-2.5" data-testid={`row-document-${d.id}`}>
              <div className="flex items-center gap-2">
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium truncate">{d.findingTitle ?? d.filename}</div>
                  <div className="text-[10px] text-muted-foreground">
                    {d.filename} · {(d.bytes / 1024).toFixed(0)} KB · {d.origin ?? "upload"} · TLP:{d.tlp} ·{" "}
                    {d.uploadedBy} · {relativeTime(d.uploadedAt)}
                  </div>
                </div>
                {d.findingId && (
                  <a
                    className="text-[11px] text-primary hover:underline shrink-0"
                    href={`#/osint?finding=${encodeURIComponent(d.findingId)}`}
                    data-testid={`link-doc-finding-${d.id}`}
                  >
                    open finding
                  </a>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- reports

function ReportsTab() {
  const { toast } = useToast();
  const [days, setDays] = useState("14");
  const [busy, setBusy] = useState<string | null>(null);

  const pull = async (kind: "executive_brief" | "weekly_landscape", format: "docx" | "md") => {
    setBusy(`${kind}:${format}`);
    try {
      const r = await apiRequest("POST", "/api/v1/reports/brief", { kind, format, days: Number(days) });
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${kind}-${days}d.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e: any) {
      toast({ variant: "destructive", title: "Report failed", description: String(e?.message ?? e) });
    } finally {
      setBusy(null);
    }
  };

  const kinds: Array<{ kind: "executive_brief" | "weekly_landscape"; title: string; blurb: string }> = [
    {
      kind: "executive_brief",
      title: "Executive brief",
      blurb: "Exploited items, escalations, queue health and hunt coverage for leadership.",
    },
    {
      kind: "weekly_landscape",
      title: "Threat landscape",
      blurb: "Volume by source, new CVEs ranked by KEV/EPSS, techniques observed, hunts run.",
    },
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Label className="text-xs text-muted-foreground">Window</Label>
        <Select value={days} onValueChange={setDays}>
          <SelectTrigger className="h-7 w-[120px] text-xs" data-testid="select-report-window">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {["7", "14", "30", "90"].map((d) => (
              <SelectItem key={d} value={d}>
                {d} days
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="rounded-md border border-border/70 bg-muted/20 p-3 text-[11px] text-muted-foreground flex gap-2">
        <AlertTriangle size={13} className="shrink-0 mt-0.5" />
        <span>
          Reports label every section: <strong>[verified]</strong> analyst-recorded, <strong>[feed]</strong> ingested
          source data, <strong>[ai]</strong> model output that has not been independently verified.
        </span>
      </div>
      {kinds.map((k) => (
        <Card key={k.kind} className="p-3 flex items-center gap-3" data-testid={`card-report-${k.kind}`}>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium">{k.title}</div>
            <p className="text-xs text-muted-foreground">{k.blurb}</p>
          </div>
          <Button
            size="sm"
            variant="outline"
            className="h-7 shrink-0"
            onClick={() => pull(k.kind, "docx")}
            disabled={busy !== null}
            data-testid={`button-${k.kind}-docx`}
          >
            {busy === `${k.kind}:docx` ? (
              <Loader2 size={12} className="mr-1 animate-spin" />
            ) : (
              <FileDown size={12} className="mr-1" />
            )}{" "}
            DOCX
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-7 shrink-0"
            onClick={() => pull(k.kind, "md")}
            disabled={busy !== null}
            data-testid={`button-${k.kind}-md`}
          >
            <FileDown size={12} className="mr-1" /> MD
          </Button>
        </Card>
      ))}
      <p className="text-[11px] text-muted-foreground">
        Case reports are generated from a case — open one in{" "}
        <a className="text-primary hover:underline" href="#/cases">
          Cases
        </a>
        .
      </p>
    </div>
  );
}
