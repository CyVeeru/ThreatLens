import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { relativeTime } from "@/lib/format";

interface MatrixDTO {
  tactics: Array<{
    shortname: string;
    name: string;
    extId: string;
    techniques: Array<{ id: string; name: string; subCount: number; ruleCount: number; subs: string[] }>;
  }>;
  totals: { techniques: number; covered: number; uncovered: number };
  version: string | null;
  lastSync: string | null;
  lastError: string | null;
}
interface TechniqueDTO {
  id: string;
  name: string;
  tactics: Array<{ shortname: string; name: string }>;
  description: string;
  detection: string;
  platforms: string[];
  url: string | null;
  detections: Array<{
    id: string;
    name: string;
    url: string | null;
    analytics: Array<{ platform: string; description: string }>;
  }>;
  subTechniques: Array<{ id: string; name: string; ruleCount: number }>;
  ruleCount: number;
}

const cellTone = (n: number) =>
  n === 0
    ? "border-border bg-background text-muted-foreground hover:bg-muted/60"
    : n < 3
      ? "border-amber-500/40 bg-amber-500/10 hover:bg-amber-500/20"
      : "border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25";

/** ATT&CK matrix coloured by how many library rules detect each technique. */
export function AttackMatrix({ onViewRules }: { onViewRules: (technique: string) => void }) {
  const { data, isLoading } = useQuery<MatrixDTO>({ queryKey: ["/api/v1/detections/attack/matrix"] });
  const [filter, setFilter] = useState("");
  const [gapsOnly, setGapsOnly] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const { data: tech } = useQuery<TechniqueDTO>({
    queryKey: [`/api/v1/detections/attack/techniques/${openId ?? ""}`],
    enabled: !!openId,
  });
  const q = filter.trim().toLowerCase();
  const pct = useMemo(
    () => (data && data.totals.techniques ? Math.round((data.totals.covered / data.totals.techniques) * 100) : 0),
    [data],
  );

  if (isLoading) return <div className="text-sm text-muted-foreground p-6">Loading ATT&amp;CK matrix…</div>;
  if (!data || data.tactics.length === 0) {
    return (
      <div className="rounded-lg border p-8 text-center" data-testid="attack-empty">
        <div className="text-sm font-medium">ATT&amp;CK data has not been downloaded yet</div>
        <p className="text-xs text-muted-foreground mt-1">
          Use “Refresh feeds” at the top right to sync the MITRE ATT&amp;CK Enterprise matrix.
        </p>
        {data?.lastError && (
          <p className="text-xs text-red-600 dark:text-red-300 mt-2">Last sync failed: {data.lastError}</p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="attack-matrix">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span>
          <strong className="text-sm">{data.totals.covered}</strong> of {data.totals.techniques} techniques have at
          least one rule <strong>({pct}%)</strong>
        </span>
        <span className="flex items-center gap-1.5 text-muted-foreground">
          <i className="inline-block h-3 w-3 rounded-sm border border-border" /> none
          <i className="inline-block h-3 w-3 rounded-sm border border-amber-500/40 bg-amber-500/20 ml-2" /> 1–2
          <i className="inline-block h-3 w-3 rounded-sm border border-emerald-500/40 bg-emerald-500/25 ml-2" /> 3+
        </span>
        <span className="text-muted-foreground">
          ATT&amp;CK {data.version ?? ""} · synced {data.lastSync ? relativeTime(data.lastSync) : "never"}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Find technique…"
            className="h-8 w-[200px] text-xs"
            data-testid="input-attack-filter"
          />
          <Button
            size="sm"
            variant={gapsOnly ? "default" : "outline"}
            className="h-8 text-xs"
            onClick={() => setGapsOnly((v) => !v)}
            data-testid="button-attack-gaps"
          >
            {gapsOnly ? "Showing gaps only" : "Show gaps only"}
          </Button>
        </div>
      </div>

      <div className="overflow-x-auto pb-2">
        <div className="flex gap-2 min-w-max">
          {data.tactics.map((tac) => {
            const items = tac.techniques.filter(
              (t) =>
                (!gapsOnly || t.ruleCount === 0) &&
                (!q ||
                  t.name.toLowerCase().includes(q) ||
                  t.id.toLowerCase().includes(q) ||
                  t.subs.some((s) => s.toLowerCase().includes(q))),
            );
            return (
              <div key={tac.shortname} className="w-[150px] shrink-0">
                <div className="rounded-md bg-muted px-2 py-1.5 mb-1.5">
                  <div className="text-[11px] font-semibold leading-tight">{tac.name}</div>
                  <div className="text-[10px] text-muted-foreground">
                    {tac.techniques.filter((t) => t.ruleCount > 0).length}/{tac.techniques.length} covered
                  </div>
                </div>
                <div className="space-y-1">
                  {items.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => setOpenId(t.id)}
                      className={`w-full text-left rounded border px-1.5 py-1 transition-colors ${cellTone(t.ruleCount)}`}
                      title={`${t.id} · ${t.ruleCount} rule${t.ruleCount === 1 ? "" : "s"}${t.subCount ? ` · ${t.subCount} sub-techniques` : ""}${q ? ` · matches: ${t.subs.filter((s) => s.toLowerCase().includes(q)).join(", ")}` : ""}`}
                      data-testid={`cell-${t.id}`}
                    >
                      <div className="text-[10px] font-mono text-muted-foreground leading-none">
                        {t.id}
                        {t.ruleCount > 0 ? ` · ${t.ruleCount}` : ""}
                      </div>
                      <div className="text-[11px] leading-snug mt-0.5">{t.name}</div>
                    </button>
                  ))}
                  {items.length === 0 && <div className="text-[10px] text-muted-foreground px-1">—</div>}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <Dialog open={!!openId} onOpenChange={(o) => !o && setOpenId(null)}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="pr-6">{tech ? `${tech.id} · ${tech.name}` : "Technique"}</DialogTitle>
            <DialogDescription>
              {tech?.tactics.map((t) => t.name).join(", ")}
              {tech?.platforms?.length ? ` · ${tech.platforms.join(", ")}` : ""}
            </DialogDescription>
          </DialogHeader>
          {tech && (
            <div className="space-y-3 text-sm">
              <p className="text-xs leading-relaxed whitespace-pre-line">{tech.description}</p>
              {tech.detections.length > 0 && (
                <div data-testid="attack-detections">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">
                    How to detect — MITRE detection strategies ({tech.detections.length})
                  </div>
                  <ul className="space-y-2">
                    {tech.detections.slice(0, 6).map((d) => (
                      <li key={d.id} className="rounded border p-2">
                        <div className="text-xs font-medium">
                          <span className="font-mono text-muted-foreground mr-1.5">{d.id}</span>
                          {d.url ? (
                            <a href={d.url} target="_blank" rel="noreferrer noopener" className="hover:underline">
                              {d.name}
                            </a>
                          ) : (
                            d.name
                          )}
                        </div>
                        {d.analytics[0] && (
                          <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
                            {d.analytics[0].platform ? <strong>{d.analytics[0].platform}: </strong> : null}
                            {d.analytics[0].description}
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                  {tech.detections.length > 6 && (
                    <p className="text-[11px] text-muted-foreground mt-1">
                      +{tech.detections.length - 6} more on attack.mitre.org
                    </p>
                  )}
                </div>
              )}
              {tech.detection && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">
                    How to detect (MITRE guidance)
                  </div>
                  <p className="text-xs leading-relaxed whitespace-pre-line">{tech.detection}</p>
                </div>
              )}
              {tech.subTechniques.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Sub-techniques</div>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-1">
                    {tech.subTechniques.map((s) => (
                      <li
                        key={s.id}
                        className="text-xs flex items-center justify-between gap-2 rounded border px-2 py-1"
                      >
                        <span className="truncate">
                          <span className="font-mono text-muted-foreground">{s.id}</span> {s.name}
                        </span>
                        <Badge
                          variant="outline"
                          className={`text-[10px] shrink-0 ${s.ruleCount ? "" : "text-muted-foreground"}`}
                        >
                          {s.ruleCount} rule{s.ruleCount === 1 ? "" : "s"}
                        </Badge>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <Button
                  size="sm"
                  onClick={() => {
                    onViewRules(tech.id);
                    setOpenId(null);
                  }}
                  data-testid="button-attack-view-rules"
                >
                  View rules for {tech.id}
                </Button>
                {tech.url && (
                  <a
                    href={tech.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-xs text-primary hover:underline inline-flex items-center gap-1"
                  >
                    Open on attack.mitre.org <ExternalLink size={11} />
                  </a>
                )}
              </div>
              <p className="text-[10px] text-muted-foreground border-t pt-2">
                MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation. Content used under the ATT&amp;CK
                terms of use.
              </p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
