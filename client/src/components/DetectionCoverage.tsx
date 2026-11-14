import { Link } from "wouter";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, CircleHelp, ShieldCheck, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { apiRequest, queryClient } from "@/lib/queryClient";

export interface RuleSummaryDTO {
  id: string;
  ruleId: string;
  title: string;
  level: string | null;
  author: string | null;
  techniques: string[];
  product: string | null;
  category: string | null;
  matchedTechnique?: string;
}
export interface CoverageDTO {
  verdict: "covered" | "partial" | "gap" | "unknown";
  summary: string;
  techniques: string[];
  techniquesInferred: boolean;
  cves: string[];
  cveRules: RuleSummaryDTO[];
  techniqueRules: RuleSummaryDTO[];
  libraryEmpty: boolean;
}

const VERDICT = {
  covered: {
    label: "Covered",
    icon: CheckCircle2,
    cls: "text-emerald-700 dark:text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  },
  partial: {
    label: "Partially covered",
    icon: ShieldCheck,
    cls: "text-amber-700 dark:text-amber-300 border-amber-500/40 bg-amber-500/10",
  },
  gap: {
    label: "Detection gap",
    icon: CircleAlert,
    cls: "text-red-700 dark:text-red-300 border-red-500/40 bg-red-500/10",
  },
  unknown: { label: "Cannot assess", icon: CircleHelp, cls: "text-muted-foreground border-border bg-muted" },
} as const;

export const LEVEL_CLS: Record<string, string> = {
  critical: "border-red-500/40 text-red-700 dark:text-red-300",
  high: "border-orange-500/40 text-orange-700 dark:text-orange-300",
  medium: "border-amber-500/40 text-amber-700 dark:text-amber-300",
  low: "border-border text-muted-foreground",
};

function RuleRow({ r }: { r: RuleSummaryDTO }) {
  return (
    <li className="flex items-start gap-2 py-1.5">
      <Badge variant="outline" className={`text-[9px] uppercase shrink-0 ${LEVEL_CLS[r.level ?? ""] ?? ""}`}>
        {r.level ?? "n/a"}
      </Badge>
      <div className="min-w-0">
        <Link
          href={`/detections?tab=rules&rule=${encodeURIComponent(r.id)}`}
          className="text-xs font-medium hover:underline"
          data-testid={`link-rule-${r.ruleId}`}
        >
          {r.title}
        </Link>
        <div className="text-[10px] text-muted-foreground truncate">
          {[r.product, r.category].filter(Boolean).join(" · ")}
          {r.matchedTechnique ? ` · matches ${r.matchedTechnique}` : ""}
        </div>
      </div>
    </li>
  );
}

const GENERATE_OPTIONS: Array<{ id: string; label: string }> = [
  { id: "sigma", label: "Sigma rule (vendor-neutral)" },
  { id: "ioa", label: "Indicators of Attack (behaviours)" },
  { id: "crowdstrike_ioa", label: "CrowdStrike Falcon Custom IOA" },
  { id: "defender_rule", label: "Defender XDR custom detection" },
  { id: "sentinelone_star", label: "SentinelOne STAR rule" },
  { id: "cortex_bioc", label: "Cortex XDR BIOC" },
  { id: "elastic_rule", label: "Elastic detection rule (EQL)" },
];

/** One click: ask the configured AI to write the missing detection for this finding. */
function GenerateDetection({ findingId }: { findingId: string }) {
  const { toast } = useToast();
  const { user } = useAuth();
  const canGenerate = !(user?.access_mode === "guest" || user?.role === "reviewer");
  const gen = useMutation({
    mutationFn: async (language: string) =>
      (
        await apiRequest("POST", "/api/v1/osint/hunt-queries", { findingIds: [findingId], languages: [language] })
      ).json(),
    onSuccess: () => {
      toast({
        title: "Generating detection",
        description: "The AI job is running. Track it in the jobs tray; the result appears under Hunting queries.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/osint/hunt-queries"] });
    },
    onError: (e: any) =>
      toast({
        variant: "destructive",
        title: "Could not start generation",
        description: String(e?.message ?? e).replace(/^\d+:\s*/, ""),
      }),
  });
  if (!canGenerate) return null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="sm" className="h-8 text-xs" disabled={gen.isPending} data-testid="button-generate-detection">
          <Sparkles size={13} className="mr-1.5" /> Generate detection
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-[280px]">
        <DropdownMenuLabel className="text-xs">Pick a format</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {GENERATE_OPTIONS.map((o) => (
          <DropdownMenuItem
            key={o.id}
            className="text-xs"
            onClick={() => gen.mutate(o.id)}
            data-testid={`menu-generate-${o.id}`}
          >
            {o.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** "Do we already detect this?" — existing library rules for a finding's CVEs and ATT&CK behaviour. */
export function DetectionCoverage({ findingId }: { findingId: string }) {
  const { data, isLoading, isError } = useQuery<CoverageDTO>({
    queryKey: [`/api/v1/detections/coverage?findingId=${encodeURIComponent(findingId)}`],
  });
  if (isLoading)
    return (
      <div className="text-xs text-muted-foreground" data-testid="coverage-loading">
        Checking existing detections…
      </div>
    );
  if (isError || !data) return null;
  const v = VERDICT[data.verdict];
  const Icon = v.icon;
  return (
    <div className="rounded-lg border p-3 space-y-2" data-testid="detection-coverage">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Existing detections</div>
        <Badge variant="outline" className={`gap-1 ${v.cls}`} data-testid="coverage-verdict">
          <Icon size={12} /> {v.label}
        </Badge>
      </div>
      <p className="text-xs text-muted-foreground leading-relaxed">{data.summary}</p>
      {data.techniques.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-[10px] text-muted-foreground">
            {data.techniquesInferred ? "Inferred behaviour:" : "ATT&CK:"}
          </span>
          {data.techniques.map((t) => (
            <Link key={t} href={`/detections?tab=rules&technique=${t}`}>
              <Badge variant="outline" className="font-mono text-[10px] cursor-pointer hover:bg-accent">
                {t}
              </Badge>
            </Link>
          ))}
          {data.techniquesInferred && (
            <span className="text-[10px] text-muted-foreground">(from article text — run AI analysis to confirm)</span>
          )}
        </div>
      )}
      {data.cveRules.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground mt-1">Rules for this CVE</div>
          <ul className="divide-y">
            {data.cveRules.map((r) => (
              <RuleRow key={r.id} r={r} />
            ))}
          </ul>
        </div>
      )}
      {data.techniqueRules.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground mt-1">
            Rules for the same behaviour ({data.techniqueRules.length})
          </div>
          <ul className="divide-y">
            {data.techniqueRules.slice(0, 6).map((r) => (
              <RuleRow key={r.id} r={r} />
            ))}
          </ul>
          {data.techniqueRules.length > 6 && (
            <Link
              href={`/detections?tab=rules&technique=${data.techniques[0]}`}
              className="text-[11px] text-primary hover:underline"
            >
              See all {data.techniqueRules.length} →
            </Link>
          )}
        </div>
      )}
      {(data.verdict === "gap" || data.verdict === "partial") && (
        <div className="border-t pt-2 space-y-1.5" data-testid="coverage-gap-actions">
          <GenerateDetection findingId={findingId} />
          <p className="text-[11px] text-muted-foreground">
            Writes a new detection for this finding with your configured AI. You can also use{" "}
            <strong>Export IoCs</strong> from the feed for blocklists, or convert an existing rule above in the
            Detection Library.
          </p>
        </div>
      )}
    </div>
  );
}
