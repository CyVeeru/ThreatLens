import { useMemo, useState } from "react";
import { Link } from "wouter";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Building2, Plus, Trash2, ShieldAlert, Eye, Target, Sparkles } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { OrgBadge } from "@/components/OrgScope";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { setOrgScope } from "@/lib/orgScope";
import {
  ORG_ASSET_KINDS,
  ORG_CRITICALITIES,
  type OrgAssetDTO,
  type OrgAssetKind,
  type OrgCriticality,
  type OrgExposureDTO,
} from "@shared/schema";

type Preset = { name: string; kind: OrgAssetKind; aliases?: string[] };

/** One-click starting points. Aliases catch the names advisories actually use. */
const PRESET_GROUPS: Array<{ label: string; items: Preset[] }> = [
  {
    label: "Operating systems & virtualization",
    items: [
      { name: "Microsoft Windows", kind: "product", aliases: ["Windows Server", "Windows 10", "Windows 11"] },
      { name: "Linux", kind: "technology", aliases: ["Linux kernel", "Ubuntu", "Red Hat", "RHEL", "Debian"] },
      { name: "VMware", kind: "vendor", aliases: ["ESXi", "vCenter", "vSphere"] },
      { name: "Docker", kind: "technology", aliases: ["containerd"] },
      { name: "Kubernetes", kind: "technology", aliases: ["K8s"] },
    ],
  },
  {
    label: "Network & security vendors",
    items: [
      { name: "Cisco", kind: "vendor", aliases: ["Cisco IOS", "IOS XE", "Cisco ASA", "Catalyst"] },
      { name: "Fortinet", kind: "vendor", aliases: ["FortiGate", "FortiOS", "FortiManager", "FortiWeb"] },
      { name: "Palo Alto Networks", kind: "vendor", aliases: ["PAN-OS", "GlobalProtect"] },
      { name: "Citrix", kind: "vendor", aliases: ["NetScaler", "Citrix ADC"] },
      { name: "Ivanti", kind: "vendor", aliases: ["Pulse Secure", "Ivanti Connect Secure"] },
      { name: "SonicWall", kind: "vendor" },
      { name: "F5", kind: "vendor", aliases: ["BIG-IP"] },
    ],
  },
  {
    label: "Cloud & identity",
    items: [
      {
        name: "Microsoft 365",
        kind: "cloud",
        aliases: ["Office 365", "Exchange Online", "SharePoint", "Microsoft Exchange", "Outlook"],
      },
      { name: "Microsoft Azure", kind: "cloud", aliases: ["Azure AD", "Entra ID", "Entra"] },
      { name: "Amazon Web Services", kind: "cloud", aliases: ["AWS", "Amazon S3", "EC2"] },
      { name: "Google Cloud", kind: "cloud", aliases: ["GCP", "Google Workspace"] },
      { name: "Okta", kind: "cloud" },
      { name: "Salesforce", kind: "cloud" },
    ],
  },
  {
    label: "Web, apps & data",
    items: [
      { name: "Apache", kind: "technology", aliases: ["Apache HTTP Server", "Apache Tomcat", "Apache Struts"] },
      { name: "Nginx", kind: "technology" },
      { name: "WordPress", kind: "product" },
      { name: "PostgreSQL", kind: "technology", aliases: ["Postgres"] },
      { name: "MySQL", kind: "technology", aliases: ["MariaDB"] },
      { name: "Oracle", kind: "vendor", aliases: ["Oracle WebLogic", "Oracle Database"] },
      { name: "Atlassian", kind: "vendor", aliases: ["Confluence", "Jira"] },
      { name: "GitLab", kind: "product", aliases: ["GitHub"] },
    ],
  },
];

const CRIT_STYLE: Record<OrgCriticality, string> = {
  critical: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  low: "border-border bg-muted text-muted-foreground",
};

const KIND_LABEL: Record<OrgAssetKind, string> = {
  vendor: "Vendor",
  product: "Product",
  technology: "Technology",
  cloud: "Cloud / SaaS",
  keyword: "Keyword",
};

function refreshOrgData() {
  queryClient.invalidateQueries({ queryKey: ["/api/v1/org/assets"] });
  queryClient.invalidateQueries({ queryKey: ["/api/v1/org/exposure"] });
  queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/findings"] });
  queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/review/queue"] });
}

function StatTile({
  label,
  value,
  tone,
  icon,
}: {
  label: string;
  value: number | string;
  tone: string;
  icon: React.ReactNode;
}) {
  return (
    <Card className="p-4 flex items-center gap-3">
      <div className={`h-9 w-9 rounded-md flex items-center justify-center ${tone}`}>{icon}</div>
      <div>
        <div className="text-2xl font-semibold leading-none tabular-nums">{value}</div>
        <div className="text-[11px] uppercase tracking-wide text-muted-foreground mt-1">{label}</div>
      </div>
    </Card>
  );
}

export default function Organization() {
  const { toast } = useToast();
  const { user } = useAuth();
  const canEdit = !(user?.access_mode === "guest" || user?.role === "reviewer");

  const { data: assetsResp, isLoading } = useQuery<{ assets: OrgAssetDTO[] }>({ queryKey: ["/api/v1/org/assets"] });
  const { data: exposure } = useQuery<OrgExposureDTO>({ queryKey: ["/api/v1/org/exposure"] });
  const assets = assetsResp?.assets ?? [];
  const counts = useMemo(() => new Map((exposure?.byAsset ?? []).map((a) => [a.assetId, a])), [exposure]);
  const existing = useMemo(() => new Set(assets.map((a) => a.name.toLowerCase())), [assets]);

  const [name, setName] = useState("");
  const [kind, setKind] = useState<OrgAssetKind>("product");
  const [criticality, setCriticality] = useState<OrgCriticality>("medium");
  const [aliases, setAliases] = useState("");

  const onError = (e: any) =>
    toast({
      variant: "destructive",
      title: "Could not save",
      description: String(e?.message ?? e).replace(/^\d+:\s*/, ""),
    });

  const addOne = useMutation({
    mutationFn: async () =>
      (
        await apiRequest("POST", "/api/v1/org/assets", {
          name,
          kind,
          criticality,
          aliases: aliases
            .split(",")
            .map((a) => a.trim())
            .filter(Boolean),
        })
      ).json(),
    onSuccess: () => {
      setName("");
      setAliases("");
      refreshOrgData();
    },
    onError,
  });
  const addPresets = useMutation({
    mutationFn: async (items: Preset[]) =>
      (
        await apiRequest("POST", "/api/v1/org/assets/bulk", {
          assets: items.map((p) => ({ name: p.name, kind: p.kind, criticality: "medium", aliases: p.aliases ?? [] })),
        })
      ).json() as Promise<{ created: OrgAssetDTO[]; skipped: string[] }>,
    onSuccess: (r) => {
      toast({
        title: `Added ${r.created.length} item${r.created.length === 1 ? "" : "s"}`,
        description: r.skipped.length ? `${r.skipped.length} already in your profile.` : undefined,
      });
      refreshOrgData();
    },
    onError,
  });
  const patch = useMutation({
    mutationFn: async (v: { id: string; criticality: OrgCriticality }) =>
      (await apiRequest("PATCH", `/api/v1/org/assets/${v.id}`, { criticality: v.criticality })).json(),
    onSuccess: refreshOrgData,
    onError,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => apiRequest("DELETE", `/api/v1/org/assets/${id}`),
    onSuccess: refreshOrgData,
    onError,
  });

  const totals = exposure?.totals;
  const hasProfile = assets.length > 0;

  return (
    <AppShell>
      <div className="px-4 md:px-10 py-6 md:py-8 max-w-[1400px]">
        <PageHeader
          title="Organization Profile"
          description="Tell ThreatLens what you run. Every finding is then matched against your own technology so you can switch between the global feed and what actually affects you."
        />

        {hasProfile && totals && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6" data-testid="org-exposure-stats">
            <StatTile
              label="Urgent"
              value={totals.urgent}
              tone="bg-red-500/10 text-red-600 dark:text-red-300"
              icon={<ShieldAlert size={18} />}
            />
            <StatTile
              label="High"
              value={totals.high}
              tone="bg-orange-500/10 text-orange-600 dark:text-orange-300"
              icon={<Target size={18} />}
            />
            <StatTile
              label="Watch"
              value={totals.watch}
              tone="bg-amber-500/10 text-amber-600 dark:text-amber-300"
              icon={<Eye size={18} />}
            />
            <StatTile
              label={`Matched of ${totals.totalFindings}`}
              value={totals.matchedFindings}
              tone="bg-primary/10 text-primary"
              icon={<Building2 size={18} />}
            />
          </div>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)] gap-6">
          <div className="space-y-6 min-w-0">
            {canEdit && (
              <Card className="p-4 space-y-4" data-testid="card-add-asset">
                <div className="text-sm font-semibold">Add technology</div>
                <form
                  className="grid grid-cols-1 md:grid-cols-[1.4fr_1fr_1fr] gap-3"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (name.trim().length >= 2) addOne.mutate();
                  }}
                >
                  <div className="space-y-1.5">
                    <Label htmlFor="org-name" className="text-xs">
                      Name
                    </Label>
                    <Input
                      id="org-name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Fortinet FortiGate"
                      data-testid="input-org-name"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Type</Label>
                    <Select value={kind} onValueChange={(v) => setKind(v as OrgAssetKind)}>
                      <SelectTrigger data-testid="select-org-kind">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ORG_ASSET_KINDS.map((k) => (
                          <SelectItem key={k} value={k}>
                            {KIND_LABEL[k]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Criticality</Label>
                    <Select value={criticality} onValueChange={(v) => setCriticality(v as OrgCriticality)}>
                      <SelectTrigger data-testid="select-org-criticality">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ORG_CRITICALITIES.map((c) => (
                          <SelectItem key={c} value={c} className="capitalize">
                            {c}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5 md:col-span-3">
                    <Label htmlFor="org-aliases" className="text-xs">
                      Also known as (comma separated, optional)
                    </Label>
                    <Input
                      id="org-aliases"
                      value={aliases}
                      onChange={(e) => setAliases(e.target.value)}
                      placeholder="FortiOS, FortiManager"
                      data-testid="input-org-aliases"
                    />
                  </div>
                  <div className="md:col-span-3">
                    <Button
                      type="submit"
                      size="sm"
                      disabled={name.trim().length < 2 || addOne.isPending}
                      data-testid="button-add-asset"
                    >
                      <Plus size={14} className="mr-1.5" /> Add to profile
                    </Button>
                  </div>
                </form>

                <div className="border-t pt-4 space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <Sparkles size={14} className="text-primary" /> Quick add
                  </div>
                  {PRESET_GROUPS.map((g) => {
                    const missing = g.items.filter((p) => !existing.has(p.name.toLowerCase()));
                    return (
                      <div key={g.label}>
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{g.label}</div>
                          {missing.length > 1 && (
                            <button
                              type="button"
                              className="text-[11px] text-primary hover:underline"
                              onClick={() => addPresets.mutate(missing)}
                              data-testid={`button-add-group-${g.label.split(" ")[0].toLowerCase()}`}
                            >
                              Add all
                            </button>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {g.items.map((p) => {
                            const have = existing.has(p.name.toLowerCase());
                            return (
                              <button
                                key={p.name}
                                type="button"
                                disabled={have || addPresets.isPending}
                                onClick={() => addPresets.mutate([p])}
                                className={`text-xs rounded-full border px-2.5 py-1 transition-colors ${
                                  have
                                    ? "opacity-50 cursor-default bg-muted"
                                    : "hover:bg-accent hover:border-primary/40"
                                }`}
                                data-testid={`button-preset-${p.name.toLowerCase().replace(/\s+/g, "-")}`}
                              >
                                {have ? "✓ " : "+ "}
                                {p.name}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Card>
            )}

            <Card className="p-0 overflow-hidden" data-testid="card-asset-list">
              <div className="px-4 py-3 border-b flex items-center justify-between">
                <div className="text-sm font-semibold">Your technology ({assets.length})</div>
                {!canEdit && <span className="text-xs text-muted-foreground">Read-only access</span>}
              </div>
              {isLoading ? (
                <div className="p-6 text-sm text-muted-foreground">Loading…</div>
              ) : assets.length === 0 ? (
                <div className="p-8 text-center">
                  <Building2 size={24} className="mx-auto mb-2 text-muted-foreground" />
                  <div className="text-sm font-medium">No technology added yet</div>
                  <p className="text-xs text-muted-foreground mt-1 max-w-sm mx-auto">
                    Add the vendors, products and cloud services you run. Until then, ThreatLens shows the global feed
                    only.
                  </p>
                </div>
              ) : (
                <ul className="divide-y">
                  {assets.map((a) => {
                    const c = counts.get(a.id);
                    return (
                      <li key={a.id} className="px-4 py-2.5 flex items-center gap-3" data-testid={`row-asset-${a.id}`}>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium truncate">{a.name}</span>
                            <Badge variant="outline" className="text-[10px]">
                              {KIND_LABEL[a.kind]}
                            </Badge>
                          </div>
                          {a.aliases.length > 0 && (
                            <div className="text-[11px] text-muted-foreground truncate">
                              Also: {a.aliases.join(", ")}
                            </div>
                          )}
                        </div>
                        {c && c.count > 0 && (
                          <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {c.count} finding{c.count === 1 ? "" : "s"}
                            {c.urgent > 0 && (
                              <span className="text-red-600 dark:text-red-300 font-medium"> · {c.urgent} urgent</span>
                            )}
                          </span>
                        )}
                        {canEdit ? (
                          <Select
                            value={a.criticality}
                            onValueChange={(v) => patch.mutate({ id: a.id, criticality: v as OrgCriticality })}
                          >
                            <SelectTrigger
                              className="h-8 w-[104px] text-xs capitalize"
                              data-testid={`select-criticality-${a.id}`}
                            >
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ORG_CRITICALITIES.map((cr) => (
                                <SelectItem key={cr} value={cr} className="capitalize">
                                  {cr}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <Badge
                            variant="outline"
                            className={`text-[10px] capitalize border ${CRIT_STYLE[a.criticality]}`}
                          >
                            {a.criticality}
                          </Badge>
                        )}
                        {canEdit && (
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 text-muted-foreground"
                            onClick={() => remove.mutate(a.id)}
                            aria-label={`Remove ${a.name}`}
                            data-testid={`button-remove-${a.id}`}
                          >
                            <Trash2 size={14} />
                          </Button>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>
          </div>

          <Card className="p-0 overflow-hidden self-start" data-testid="card-top-exposure">
            <div className="px-4 py-3 border-b flex items-center justify-between">
              <div className="text-sm font-semibold">Top exposure right now</div>
              <Link
                href="/osint"
                onClick={() => setOrgScope("org")}
                className="text-xs text-primary hover:underline"
                data-testid="link-view-org-feed"
              >
                View in feed →
              </Link>
            </div>
            {!hasProfile ? (
              <div className="p-6 text-sm text-muted-foreground">Add technology to see which findings affect you.</div>
            ) : (exposure?.top.length ?? 0) === 0 ? (
              <div className="p-6 text-sm text-muted-foreground">No current findings match your technology.</div>
            ) : (
              <ul className="divide-y">
                {exposure!.top.map((f) => (
                  <li key={f.id} className="px-4 py-3 space-y-1.5" data-testid={`row-exposure-${f.id}`}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <OrgBadge relevance={f.orgRelevance} />
                      {f.cveEnrichment?.kev && (
                        <Badge
                          variant="outline"
                          className="text-[10px] border-red-500/40 text-red-600 dark:text-red-300"
                        >
                          KEV
                        </Badge>
                      )}
                      {f.cveIds.slice(0, 2).map((c) => (
                        <span key={c} className="text-[10px] font-mono text-muted-foreground">
                          {c}
                        </span>
                      ))}
                    </div>
                    <div className="text-sm leading-snug">{f.title}</div>
                    <div className="text-[11px] text-muted-foreground">
                      {f.orgRelevance.reasons[0]} · {f.sourceName}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </AppShell>
  );
}
