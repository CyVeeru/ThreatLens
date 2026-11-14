import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { STATIC_DEMO_MODE } from "@/lib/staticDemoApi";
import { showStaticDemoNotice } from "@/lib/staticDemoNotice";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  INVESTIGATION_SEVERITIES,
  INVESTIGATION_STATUSES,
  type CaseFullDTO,
  type CaseLinkType,
  type InvestigationDTO,
  type InvestigationSeverity,
  type InvestigationStatus,
} from "@shared/schema";
import {
  Briefcase,
  Plus,
  Link2,
  StickyNote,
  Trash2,
  FileDown,
  Target,
  Bug,
  Radar,
  Fingerprint,
  X,
  Clock,
  Loader2,
} from "lucide-react";

interface CasesResp {
  cases: InvestigationDTO[];
}

const STATUS_TONE: Record<string, string> = {
  open: "bg-[hsl(var(--sev-high))]/12 text-[hsl(var(--sev-high))] border-[hsl(var(--sev-high))]/30",
  investigating: "bg-primary/12 text-primary border-primary/30",
  contained: "bg-signal/12 text-signal border-signal/30",
  monitoring: "bg-muted text-muted-foreground border-border",
  closed: "bg-muted text-muted-foreground border-border",
};
const SEV_TONE: Record<string, string> = {
  critical: "bg-[hsl(var(--sev-critical))]/12 text-[hsl(var(--sev-critical))] border-[hsl(var(--sev-critical))]/30",
  high: "bg-[hsl(var(--sev-high))]/12 text-[hsl(var(--sev-high))] border-[hsl(var(--sev-high))]/30",
  medium: "bg-[hsl(var(--sev-medium))]/12 text-[hsl(var(--sev-medium))] border-[hsl(var(--sev-medium))]/30",
  low: "bg-muted text-muted-foreground border-border",
  info: "bg-muted text-muted-foreground border-border",
};
const LINK_ICON: Record<CaseLinkType, typeof Target> = {
  osint_finding: Radar,
  threat_actor: Fingerprint,
  hunt_query: Target,
  cve: Bug,
};

function readOnlyGuard(): boolean {
  if (STATIC_DEMO_MODE) {
    showStaticDemoNotice({ kind: "write", action: "Case editing restricted" });
    return true;
  }
  return false;
}

export default function Cases() {
  const [statusFilter, setStatusFilter] = useState<"all" | InvestigationStatus>("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const { data, isLoading } = useQuery<CasesResp>({
    queryKey: ["/api/v1/cases"],
  });
  const cases = data?.cases ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return cases.filter(
      (c) =>
        (statusFilter === "all" || c.status === statusFilter) &&
        (!q || c.title.toLowerCase().includes(q) || (c.summary ?? "").toLowerCase().includes(q)),
    );
  }, [cases, statusFilter, search]);

  const openCount = cases.filter((c) => c.status !== "closed").length;

  return (
    <AppShell>
      <div className="px-4 md:px-10 py-6 md:py-8 max-w-[1400px]">
        <PageHeader
          title="Cases"
          description="Group findings, actors, hunts and CVEs into one investigation with status, notes and an evidence timeline."
          actions={
            <Button
              size="sm"
              onClick={() => {
                if (!readOnlyGuard()) setCreateOpen(true);
              }}
              data-testid="button-create-case"
            >
              <Plus size={14} className="mr-1" /> New case
            </Button>
          }
        />

        <div className="flex flex-wrap items-center gap-2 mb-4">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search cases…"
            className="h-8 w-[240px] text-sm"
            data-testid="input-case-search"
          />
          <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as any)}>
            <SelectTrigger className="h-8 w-[170px] text-xs" data-testid="select-case-status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              {INVESTIGATION_STATUSES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground ml-1" data-testid="text-case-counts">
            {openCount} open · {cases.length} total
          </span>
        </div>

        {isLoading ? (
          <Card className="p-8 text-center text-sm text-muted-foreground">Loading cases…</Card>
        ) : filtered.length === 0 ? (
          <Card className="p-10 text-center" data-testid="empty-cases">
            <Briefcase size={26} className="mx-auto mb-3 text-muted-foreground" />
            <div className="text-sm font-medium mb-1">No cases yet</div>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              Open a case when a finding needs more than triage — it keeps the evidence, hunt outcomes and analyst notes
              together, and it is what the case report is generated from.
            </p>
          </Card>
        ) : (
          <div className="space-y-2">
            {filtered.map((c) => (
              <Card
                key={c.id}
                className="p-3 cursor-pointer hover:border-primary/50 transition-colors"
                onClick={() => setSelectedId(c.id)}
                data-testid={`card-case-${c.id}`}
              >
                <div className="flex items-start gap-3">
                  <Briefcase size={15} className="text-primary mt-0.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium truncate">{c.title}</span>
                      <Badge variant="outline" className={cn("text-[10px] capitalize", STATUS_TONE[c.status])}>
                        {c.status}
                      </Badge>
                      <Badge variant="outline" className={cn("text-[10px] capitalize", SEV_TONE[c.severity])}>
                        {c.severity}
                      </Badge>
                    </div>
                    {c.summary && <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{c.summary}</p>}
                    <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        <Link2 size={10} /> {c.linkCount ?? 0} linked
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <StickyNote size={10} /> {c.noteCount ?? 0} notes
                      </span>
                      {c.assignee && <span>owner {c.assignee}</span>}
                      <span className="ml-auto">{relativeTime(c.updatedAt)}</span>
                    </div>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      <CreateCaseDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(id) => {
          setCreateOpen(false);
          setSelectedId(id);
        }}
      />
      <CaseDetail caseId={selectedId} onClose={() => setSelectedId(null)} />
    </AppShell>
  );
}

function CreateCaseDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const { toast } = useToast();
  const { user } = useAuth();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<InvestigationSeverity>("medium");
  const [summary, setSummary] = useState("");
  const [assignee, setAssignee] = useState("");

  const create = useMutation({
    mutationFn: async () => {
      const r = await apiRequest("POST", "/api/v1/cases", {
        title: title.trim(),
        severity,
        summary: summary.trim() || null,
        assignee: assignee.trim() || null,
      });
      return r.json() as Promise<InvestigationDTO>;
    },
    onSuccess: (c) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/cases"] });
      toast({ title: "Case opened", description: c.title });
      setTitle("");
      setSummary("");
      setAssignee("");
      setSeverity("medium");
      onCreated(c.id);
    },
    onError: (e: any) =>
      toast({ variant: "destructive", title: "Could not open case", description: String(e?.message ?? e) }),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Open a case</DialogTitle>
          <DialogDescription className="text-xs">
            Link findings, actors, hunts and CVEs to it once it exists.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label className="text-xs text-muted-foreground">Title</Label>
            <Input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Edge appliance exploitation — Sept"
              data-testid="input-case-title"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label className="text-xs text-muted-foreground">Severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as InvestigationSeverity)}>
                <SelectTrigger data-testid="select-new-case-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INVESTIGATION_SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">Owner</Label>
              <Input
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
                placeholder={user?.email ?? "analyst@…"}
                data-testid="input-case-assignee"
              />
            </div>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">Summary</Label>
            <Textarea
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              className="min-h-[80px] text-sm"
              placeholder="What prompted this case?"
              data-testid="textarea-case-summary"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => create.mutate()}
            disabled={title.trim().length < 2 || create.isPending}
            data-testid="button-save-case"
          >
            {create.isPending ? (
              <>
                <Loader2 size={14} className="mr-1.5 animate-spin" /> Opening
              </>
            ) : (
              "Open case"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function CaseDetail({ caseId, onClose }: { caseId: string | null; onClose: () => void }) {
  const { toast } = useToast();
  const [note, setNote] = useState("");
  const [linkType, setLinkType] = useState<CaseLinkType>("cve");
  const [linkId, setLinkId] = useState("");

  const { data: full, isLoading } = useQuery<CaseFullDTO>({
    queryKey: ["/api/v1/cases", caseId],
    enabled: !!caseId,
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/cases/${caseId}`);
      return r.json();
    },
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/v1/cases"] });
    queryClient.invalidateQueries({ queryKey: ["/api/v1/cases", caseId] });
  };

  const patch = useMutation({
    mutationFn: async (body: Record<string, unknown>) =>
      (await apiRequest("PATCH", `/api/v1/cases/${caseId}`, body)).json(),
    onSuccess: invalidate,
    onError: (e: any) =>
      toast({ variant: "destructive", title: "Update failed", description: String(e?.message ?? e) }),
  });
  const addNote = useMutation({
    mutationFn: async () => (await apiRequest("POST", `/api/v1/cases/${caseId}/notes`, { body: note.trim() })).json(),
    onSuccess: () => {
      setNote("");
      invalidate();
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Note failed", description: String(e?.message ?? e) }),
  });
  const addLink = useMutation({
    mutationFn: async () =>
      (
        await apiRequest("POST", `/api/v1/cases/${caseId}/links`, { entityType: linkType, entityId: linkId.trim() })
      ).json(),
    onSuccess: () => {
      setLinkId("");
      invalidate();
      toast({ title: "Linked" });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Link failed", description: String(e?.message ?? e) }),
  });
  const removeLink = useMutation({
    mutationFn: async (lid: string) => apiRequest("DELETE", `/api/v1/cases/${caseId}/links/${lid}`),
    onSuccess: invalidate,
  });
  const report = useMutation({
    mutationFn: async (format: "docx" | "md") => {
      const r = await apiRequest("POST", "/api/v1/reports/brief", { kind: "case_report", format, caseId });
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_${(full?.title ?? "report").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 50)}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
    onError: (e: any) =>
      toast({ variant: "destructive", title: "Report failed", description: String(e?.message ?? e) }),
  });

  return (
    <Sheet open={!!caseId} onOpenChange={(v) => !v && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-2xl overflow-y-auto p-0">
        {isLoading || !full ? (
          <div className="p-8 text-sm text-muted-foreground">Loading case…</div>
        ) : (
          <div className="p-5 space-y-4">
            <div className="flex items-start gap-2">
              <div className="min-w-0 flex-1">
                <div className="text-base font-semibold">{full.title}</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  opened {relativeTime(full.createdAt)} by {full.createdBy}
                  {full.assignee ? ` · owner ${full.assignee}` : ""}
                </div>
              </div>
              <Button size="icon" variant="ghost" className="h-7 w-7" onClick={onClose} data-testid="button-close-case">
                <X size={14} />
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Select
                value={full.status}
                onValueChange={(v) => {
                  if (!readOnlyGuard()) patch.mutate({ status: v });
                }}
              >
                <SelectTrigger className="h-7 w-[150px] text-xs" data-testid="select-case-detail-status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INVESTIGATION_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select
                value={full.severity}
                onValueChange={(v) => {
                  if (!readOnlyGuard()) patch.mutate({ severity: v });
                }}
              >
                <SelectTrigger className="h-7 w-[120px] text-xs" data-testid="select-case-detail-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INVESTIGATION_SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <div className="ml-auto flex items-center gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7"
                  onClick={() => report.mutate("docx")}
                  disabled={report.isPending}
                  data-testid="button-case-report-docx"
                >
                  <FileDown size={12} className="mr-1" /> DOCX
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7"
                  onClick={() => report.mutate("md")}
                  disabled={report.isPending}
                  data-testid="button-case-report-md"
                >
                  <FileDown size={12} className="mr-1" /> MD
                </Button>
              </div>
            </div>

            {full.summary && <p className="text-sm text-muted-foreground leading-relaxed">{full.summary}</p>}

            <Tabs defaultValue="evidence">
              <TabsList className="h-8">
                <TabsTrigger value="evidence" className="text-xs" data-testid="tab-case-evidence">
                  Evidence ({full.links.length})
                </TabsTrigger>
                <TabsTrigger value="timeline" className="text-xs" data-testid="tab-case-timeline">
                  Timeline ({full.timeline.length})
                </TabsTrigger>
                <TabsTrigger value="notes" className="text-xs" data-testid="tab-case-notes">
                  Notes ({full.notes.length})
                </TabsTrigger>
              </TabsList>

              <TabsContent value="evidence" className="mt-3 space-y-3">
                <div className="flex items-end gap-1.5">
                  <div>
                    <Label className="text-[10px] text-muted-foreground">Link</Label>
                    <Select value={linkType} onValueChange={(v) => setLinkType(v as CaseLinkType)}>
                      <SelectTrigger className="h-8 w-[150px] text-xs" data-testid="select-link-type">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="cve">CVE</SelectItem>
                        <SelectItem value="osint_finding">Finding id</SelectItem>
                        <SelectItem value="threat_actor">Actor id</SelectItem>
                        <SelectItem value="hunt_query">Hunt query id</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Input
                    value={linkId}
                    onChange={(e) => setLinkId(e.target.value)}
                    placeholder={linkType === "cve" ? "CVE-2024-21762" : "paste id"}
                    className="h-8 text-xs font-mono flex-1"
                    data-testid="input-link-id"
                  />
                  <Button
                    size="sm"
                    className="h-8"
                    onClick={() => {
                      if (!readOnlyGuard()) addLink.mutate();
                    }}
                    disabled={!linkId.trim() || addLink.isPending}
                    data-testid="button-add-link"
                  >
                    <Link2 size={12} className="mr-1" /> Add
                  </Button>
                </div>

                {full.links.length === 0 ? (
                  <p className="text-xs text-muted-foreground">Nothing linked yet.</p>
                ) : (
                  <div className="space-y-1.5">
                    {full.links.map((l) => {
                      const Icon = LINK_ICON[l.entityType] ?? Link2;
                      return (
                        <div
                          key={l.id}
                          className="flex items-start gap-2 rounded-md border p-2"
                          data-testid={`row-link-${l.id}`}
                        >
                          <Icon size={13} className="text-primary mt-0.5 shrink-0" />
                          <div className="min-w-0 flex-1">
                            <div className="text-xs font-medium truncate">
                              {l.href ? (
                                <a
                                  className="hover:underline"
                                  href={l.href}
                                  target={l.href.startsWith("http") ? "_blank" : undefined}
                                  rel="noopener noreferrer"
                                >
                                  {l.title}
                                </a>
                              ) : (
                                l.title
                              )}
                            </div>
                            {l.subtitle && (
                              <div className="text-[10px] text-muted-foreground truncate">{l.subtitle}</div>
                            )}
                          </div>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-6 w-6 shrink-0"
                            onClick={() => {
                              if (!readOnlyGuard()) removeLink.mutate(l.id);
                            }}
                            data-testid={`button-unlink-${l.id}`}
                          >
                            <Trash2 size={11} />
                          </Button>
                        </div>
                      );
                    })}
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3 pt-1">
                  <SummaryBox label="CVEs" items={full.cveIds} />
                  <SummaryBox label="ATT&CK techniques" items={full.attackTechniques} />
                  <SummaryBox label="Actors" items={full.relatedActors.map((a) => `${a.profileId} ${a.name}`)} />
                  <SummaryBox
                    label="Hunt outcomes"
                    items={full.huntResults.map(
                      (r) => `${r.language}: ${r.outcome}${r.hitCount ? ` (${r.hitCount})` : ""}`,
                    )}
                  />
                </div>

                {Object.keys(full.iocs).length > 0 && (
                  <div>
                    <div className="text-[10px] font-semibold uppercase text-muted-foreground mb-1">Indicators</div>
                    <div className="rounded-md border p-2 max-h-48 overflow-y-auto space-y-1">
                      {Object.entries(full.iocs).map(
                        ([k, v]) =>
                          Array.isArray(v) &&
                          v.length > 0 && (
                            <div key={k} className="text-[11px]">
                              <span className="font-mono uppercase text-muted-foreground mr-1.5">{k}</span>
                              <span className="font-mono break-all">
                                {v.slice(0, 20).join(", ")}
                                {v.length > 20 ? ` +${v.length - 20}` : ""}
                              </span>
                            </div>
                          ),
                      )}
                    </div>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="timeline" className="mt-3">
                <div className="space-y-2">
                  {full.timeline.map((t) => (
                    <div key={t.id} className="flex gap-2 text-xs" data-testid={`row-timeline-${t.id}`}>
                      <Clock size={11} className="text-muted-foreground mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <span className="text-muted-foreground font-mono mr-2">
                          {String(t.at).replace("T", " ").slice(0, 16)}
                        </span>
                        <span>{t.title}</span>
                        {t.detail && <div className="text-[10px] text-muted-foreground mt-0.5">{t.detail}</div>}
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>

              <TabsContent value="notes" className="mt-3 space-y-3">
                <div className="flex items-end gap-1.5">
                  <Textarea
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="What did you find?"
                    className="min-h-[64px] text-sm"
                    data-testid="textarea-case-note"
                  />
                  <Button
                    size="sm"
                    onClick={() => {
                      if (!readOnlyGuard()) addNote.mutate();
                    }}
                    disabled={!note.trim() || addNote.isPending}
                    data-testid="button-add-note"
                  >
                    Add
                  </Button>
                </div>
                {full.notes.map((n) => (
                  <div key={n.id} className="rounded-md border p-2" data-testid={`row-note-${n.id}`}>
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className="text-[9px] uppercase">
                        {n.kind === "ai" ? "AI" : n.kind}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground">
                        {n.createdBy} · {relativeTime(n.createdAt)}
                      </span>
                    </div>
                    <p className="text-xs whitespace-pre-wrap">{n.body}</p>
                  </div>
                ))}
              </TabsContent>
            </Tabs>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

function SummaryBox({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-[10px] font-semibold uppercase text-muted-foreground mb-1">{label}</div>
      {items.length === 0 ? (
        <div className="text-[11px] text-muted-foreground">—</div>
      ) : (
        <div className="flex flex-wrap gap-1">
          {items.slice(0, 12).map((i) => (
            <Badge key={i} variant="secondary" className="text-[10px] font-mono">
              {i}
            </Badge>
          ))}
          {items.length > 12 && (
            <span className="text-[10px] text-muted-foreground self-center">+{items.length - 12}</span>
          )}
        </div>
      )}
    </div>
  );
}
