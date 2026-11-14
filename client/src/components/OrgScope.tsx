import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Building2, Globe2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useOrgScope } from "@/lib/orgScope";
import type { OrgAssetDTO, OrgPriority, OrgRelevance } from "@shared/schema";

const PRIORITY_STYLE: Record<OrgPriority, { label: string; cls: string }> = {
  urgent: { label: "Urgent", cls: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300" },
  high: { label: "High", cls: "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300" },
  watch: { label: "Watch", cls: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300" },
};

/** "Affects you" marker for a finding that matches the org's own technology. */
export function OrgBadge({ relevance, testId }: { relevance?: OrgRelevance | null; testId?: string }) {
  if (!relevance) return null;
  const style = PRIORITY_STYLE[relevance.priority];
  const top = relevance.matches[0];
  return (
    <Badge
      variant="outline"
      className={`text-[10px] uppercase gap-1 border ${style.cls}`}
      title={relevance.reasons.join("\n")}
      data-testid={testId}
    >
      <Building2 size={10} />
      Affects you · {style.label}
      {top ? <span className="normal-case font-medium opacity-80">· {top.assetName}</span> : null}
    </Badge>
  );
}

/** Segmented Global / My Organization switch. */
export function OrgScopeToggle({ matchedCount }: { matchedCount?: number }) {
  const [scope, setScope] = useOrgScope();
  const { data } = useQuery<{ assets: OrgAssetDTO[] }>({ queryKey: ["/api/v1/org/assets"] });
  const hasProfile = (data?.assets?.length ?? 0) > 0;
  const btn = (value: "global" | "org", label: string, icon: React.ReactNode) => (
    <button
      type="button"
      onClick={() => setScope(value)}
      aria-pressed={scope === value}
      data-testid={`button-scope-${value}`}
      className={`inline-flex items-center gap-1.5 px-3 h-8 text-xs font-medium rounded-md transition-colors ${
        scope === value ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
      }`}
    >
      {icon}
      {label}
    </button>
  );
  return (
    <div className="flex items-center gap-3 flex-wrap" data-testid="org-scope-toggle">
      <div className="inline-flex items-center gap-0.5 rounded-lg bg-muted p-0.5" role="group" aria-label="Intel scope">
        {btn("global", "Global", <Globe2 size={13} />)}
        {btn(
          "org",
          `My organization${scope === "org" && matchedCount != null ? ` (${matchedCount})` : ""}`,
          <Building2 size={13} />,
        )}
      </div>
      {scope === "org" && !hasProfile && (
        <span className="text-xs text-muted-foreground">
          No technology added yet.{" "}
          <Link href="/organization" className="text-primary underline underline-offset-2">
            Set up your organization profile
          </Link>{" "}
          to see what affects you.
        </span>
      )}
    </div>
  );
}
