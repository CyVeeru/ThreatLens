import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Copy, Download, RefreshCw, Search as SearchIcon, ExternalLink } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { LEVEL_CLS } from "@/components/DetectionCoverage";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { relativeTime } from "@/lib/format";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { IOC_EXPORT_PLATFORMS, RULE_CONVERT_PLATFORMS } from "@shared/schema";
import { AttackMatrix } from "@/components/AttackMatrix";

const PAGE = 50;

/** Query params can arrive in the real search string or after the hash route. */
function readParams(): URLSearchParams {
  const fromHash = window.location.hash.split("?")[1] ?? "";
  const p = new URLSearchParams(window.location.search);
  new URLSearchParams(fromHash).forEach((v, k) => p.set(k, v));
  return p;
}

type IocRow = {
  type: string;
  value: string;
  name: string;
  source: string;
  port: number | null;
  status: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  confidence: number;
};
type IocSummary = {
  total: number;
  names: Array<{ name: string; count: number }>;
  types: Record<string, number>;
  feeds: Array<{
    id: string;
    label: string;
    homepage: string;
    count: number;
    lastRun: string | null;
    lastError: string | null;
  }>;
};
type RuleRow = {
  id: string;
  source: string;
  ruleId: string;
  title: string;
  level: string | null;
  author: string | null;
  techniques: string[];
  product: string | null;
  category: string | null;
  modified: string | null;
  status: string | null;
};
type RuleSummary = {
  total: number;
  bySource: Record<string, number>;
  byLevel: Record<string, number>;
  byProduct: Array<{ product: string; count: number }>;
  lastSync: string | null;
  lastError: string | null;
  version: string | null;
  license: string;
};
type RuleDetail = RuleRow & { raw: string; refs: string[]; tags: string[]; license: string | null };
type ConvertResult = { platform: string; supported: boolean; query?: string; notes: string[]; error?: string };
const SOURCE_LABEL: Record<string, string> = { sigmahq: "Sigma", "reversinglabs-yara": "YARA" };

function Pager({ total, offset, onChange }: { total: number; offset: number; onChange: (o: number) => void }) {
  if (total <= PAGE) return null;
  return (
    <div className="flex items-center justify-between text-xs text-muted-foreground pt-2">
      <span>
        {offset + 1}–{Math.min(total, offset + PAGE)} of {total.toLocaleString()}
      </span>
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="outline"
          className="h-7"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - PAGE))}
        >
          Previous
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="h-7"
          disabled={offset + PAGE >= total}
          onClick={() => onChange(offset + PAGE)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/yaml;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function IocsTab() {
  const { toast } = useToast();
  const [q, setQ] = useState("");
  const [type, setType] = useState("_all");
  const [name, setName] = useState("");
  const [offset, setOffset] = useState(0);
  const { data: summary } = useQuery<IocSummary>({ queryKey: ["/api/v1/detections/iocs/summary"] });
  const qs = useMemo(() => {
    const p = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    if (q.trim()) p.set("q", q.trim());
    if (type !== "_all") p.set("type", type);
    if (name) p.set("name", name);
    return p.toString();
  }, [q, type, name, offset]);
  const { data, isFetching } = useQuery<{ total: number; iocs: IocRow[] }>({
    queryKey: [`/api/v1/detections/iocs?${qs}`],
  });
  useEffect(() => setOffset(0), [q, type, name]);

  // Download every indicator for the selected threat in an EDR / SIEM import format.
  const exportThreat = async (platform: string) => {
    try {
      const r = await apiRequest(
        "GET",
        `/api/v1/detections/iocs/export?platform=${platform}&intelName=${encodeURIComponent(name)}`,
      );
      const total = r.headers.get("X-Ioc-Total");
      const file =
        /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "")?.[1] ?? `threatlens-iocs-${platform}.txt`;
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = file;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast({ title: `Exported ${total ?? ""} ${name} indicators`, description: `${file} · review before importing.` });
    } catch (e) {
      const msg = String((e as Error).message ?? e).replace(/^\d+:\s*/, "");
      let detail = msg;
      try {
        detail = JSON.parse(msg).detail ?? msg;
      } catch {
        /* plain text */
      }
      toast({ variant: "destructive", title: "Export failed", description: detail });
    }
  };

  const copy = async (v: string) => {
    try {
      await navigator.clipboard.writeText(v);
      toast({ title: "Copied", description: v.length > 60 ? v.slice(0, 60) + "…" : v });
    } catch {
      toast({ variant: "destructive", title: "Copy failed" });
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-4">
        <Card className="p-4">
          <div className="text-sm font-semibold mb-2">Top threats by name</div>
          <div className="flex flex-wrap gap-1.5" data-testid="ioc-names">
            {(summary?.names ?? []).map((n) => (
              <button
                key={n.name}
                type="button"
                onClick={() => setName(name === n.name ? "" : n.name)}
                className={`text-xs rounded-full border px-2.5 py-1 transition-colors ${name === n.name ? "bg-primary text-primary-foreground border-primary" : "hover:bg-accent"}`}
                data-testid={`chip-ioc-name-${n.name.toLowerCase().replace(/\s+/g, "-")}`}
              >
                {n.name} <span className="opacity-70">· {n.count}</span>
              </button>
            ))}
            {!summary?.names?.length && (
              <span className="text-xs text-muted-foreground">No indicators yet — use “Refresh feeds”.</span>
            )}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm font-semibold mb-2">Feeds</div>
          <ul className="space-y-1.5">
            {(summary?.feeds ?? []).map((f) => (
              <li key={f.id} className="flex items-center justify-between gap-3 text-xs" data-testid={`feed-${f.id}`}>
                <a
                  href={f.homepage}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="hover:underline inline-flex items-center gap-1 min-w-0 truncate"
                >
                  {f.label} <ExternalLink size={10} />
                </a>
                <span
                  className={
                    f.lastError ? "text-red-600 dark:text-red-300 truncate" : "text-muted-foreground whitespace-nowrap"
                  }
                  title={f.lastError ?? undefined}
                >
                  {f.lastError
                    ? "failed — " + f.lastError
                    : `${f.count} · ${f.lastRun ? relativeTime(f.lastRun) : "never"}`}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <SearchIcon
            size={14}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
          />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search IP, URL or threat name…"
            className="w-[280px] pl-7 text-xs"
            data-testid="input-ioc-search"
          />
        </div>
        <Select value={type} onValueChange={setType}>
          <SelectTrigger className="w-[150px] h-9 text-xs" data-testid="select-ioc-type">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All types</SelectItem>
            {Object.keys(summary?.types ?? {}).map((t) => (
              <SelectItem key={t} value={t}>
                {t} ({summary!.types[t]})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {name && (
          <Button size="sm" variant="ghost" className="h-8 text-xs" onClick={() => setName("")}>
            Clear “{name}” ✕
          </Button>
        )}
        {name && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline" className="h-8 text-xs" data-testid="button-export-threat">
                <Download size={13} className="mr-1.5" /> Export “{name}” for your EDR
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-[320px]">
              <DropdownMenuLabel className="text-xs">Choose your EDR / SIEM</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {IOC_EXPORT_PLATFORMS.map((p) => (
                <DropdownMenuItem
                  key={p.id}
                  onClick={() => exportThreat(p.id)}
                  className="text-xs"
                  data-testid={`menu-export-threat-${p.id}`}
                >
                  {p.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
        <span className="text-xs text-muted-foreground ml-auto">
          {isFetching ? "Loading…" : `${(data?.total ?? 0).toLocaleString()} indicators`}
        </span>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs" data-testid="table-iocs">
            <thead className="bg-muted/50 text-muted-foreground">
              <tr className="text-left">
                <th className="px-3 py-2 font-medium">Indicator</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Threat</th>
                <th className="px-3 py-2 font-medium">Source</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Last seen</th>
                <th className="px-3 py-2 font-medium text-right">Conf.</th>
                <th className="px-1 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y">
              {(data?.iocs ?? []).map((r) => (
                <tr key={`${r.type}|${r.value}|${r.source}`} className="hover:bg-muted/30">
                  <td className="px-3 py-1.5 font-mono max-w-[360px] truncate" title={r.value}>
                    {r.value}
                    {r.port ? `:${r.port}` : ""}
                  </td>
                  <td className="px-3 py-1.5">
                    <Badge variant="outline" className="text-[10px]">
                      {r.type}
                    </Badge>
                  </td>
                  <td className="px-3 py-1.5 font-medium">{r.name}</td>
                  <td className="px-3 py-1.5 text-muted-foreground">{r.source}</td>
                  <td className="px-3 py-1.5 text-muted-foreground">{r.status ?? "—"}</td>
                  <td className="px-3 py-1.5 text-muted-foreground whitespace-nowrap">
                    {r.lastSeen ? relativeTime(r.lastSeen) : "—"}
                  </td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{r.confidence}</td>
                  <td className="px-1 py-1.5">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7"
                      onClick={() => copy(r.value)}
                      aria-label={`Copy ${r.value}`}
                    >
                      <Copy size={12} />
                    </Button>
                  </td>
                </tr>
              ))}
              {data && data.iocs.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-8 text-center text-muted-foreground">
                    No indicators match.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
      <Pager total={data?.total ?? 0} offset={offset} onChange={setOffset} />
      <p className="text-[11px] text-muted-foreground">
        Public intelligence — validate before blocking. Indicators from the feeds age out automatically when a feed
        stops listing them. To block them in your EDR, select findings in the Intelligence Feed and use{" "}
        <strong>Export IoCs</strong>.
      </p>
    </div>
  );
}

function RulesTab({ initial }: { initial: URLSearchParams }) {
  const { toast } = useToast();
  const [q, setQ] = useState(initial.get("q") ?? "");
  const [technique, setTechnique] = useState(initial.get("technique") ?? "");
  const [product, setProduct] = useState("_all");
  const [level, setLevel] = useState("_all");
  const [source, setSource] = useState("_all");
  const [offset, setOffset] = useState(0);
  const [openId, setOpenId] = useState<string | null>(initial.get("rule"));
  const [conv, setConv] = useState<ConvertResult | null>(null);
  const { data: summary } = useQuery<RuleSummary>({ queryKey: ["/api/v1/detections/rules/summary"] });
  const qs = useMemo(() => {
    const p = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    if (q.trim()) p.set("q", q.trim());
    if (technique.trim()) p.set("technique", technique.trim());
    if (product !== "_all") p.set("product", product);
    if (level !== "_all") p.set("level", level);
    if (source !== "_all") p.set("source", source);
    return p.toString();
  }, [q, technique, product, level, source, offset]);
  const { data, isFetching } = useQuery<{ total: number; rules: RuleRow[] }>({
    queryKey: [`/api/v1/detections/rules?${qs}`],
  });
  const { data: detail } = useQuery<RuleDetail>({
    queryKey: [`/api/v1/detections/rules/${encodeURIComponent(openId ?? "")}`],
    enabled: !!openId,
  });
  useEffect(() => setOffset(0), [q, technique, product, level, source]);
  useEffect(() => setConv(null), [openId]);

  const runConvert = async (platform: string) => {
    if (!openId) return;
    try {
      const r = await apiRequest(
        "GET",
        `/api/v1/detections/rules/${encodeURIComponent(openId)}/convert?platform=${platform}`,
      );
      setConv(await r.json());
    } catch (e) {
      setConv({
        platform,
        supported: false,
        notes: [],
        error: String((e as Error).message ?? e).replace(/^\d+:\s*/, ""),
      });
    }
  };

  return (
    <div className="space-y-4">
      {summary && summary.total > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground" data-testid="rule-summary">
          <span>
            <strong className="text-foreground">{summary.total.toLocaleString()}</strong> rules
          </span>
          {Object.entries(summary.bySource ?? {}).map(([k, v]) => (
            <Badge key={k} variant="secondary" className="text-[10px]">
              {SOURCE_LABEL[k] ?? k} {v}
            </Badge>
          ))}
          {Object.entries(summary.byLevel).map(([k, v]) => (
            <Badge key={k} variant="outline" className={`text-[10px] ${LEVEL_CLS[k] ?? ""}`}>
              {k} {v}
            </Badge>
          ))}
          <span>
            · SigmaHQ {summary.version ?? ""} · synced {summary.lastSync ? relativeTime(summary.lastSync) : "never"}
          </span>
          {summary.lastError && (
            <span className="text-red-600 dark:text-red-300">· last sync failed: {summary.lastError}</span>
          )}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <SearchIcon
            size={14}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
          />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search title, description, CVE…"
            className="w-[260px] pl-7 text-xs"
            data-testid="input-rule-search"
          />
        </div>
        <Input
          value={technique}
          onChange={(e) => setTechnique(e.target.value.toUpperCase())}
          placeholder="ATT&CK e.g. T1059"
          className="w-[150px] text-xs font-mono"
          data-testid="input-rule-technique"
        />
        <Select value={product} onValueChange={setProduct}>
          <SelectTrigger className="w-[150px] h-9 text-xs" data-testid="select-rule-product">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All products</SelectItem>
            {(summary?.byProduct ?? []).map((p) => (
              <SelectItem key={p.product} value={p.product}>
                {p.product} ({p.count})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={source} onValueChange={setSource}>
          <SelectTrigger className="w-[130px] h-9 text-xs" data-testid="select-rule-source">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All sources</SelectItem>
            {Object.keys(summary?.bySource ?? {}).map((k) => (
              <SelectItem key={k} value={k}>
                {SOURCE_LABEL[k] ?? k}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={level} onValueChange={setLevel}>
          <SelectTrigger className="w-[130px] h-9 text-xs" data-testid="select-rule-level">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all">All severities</SelectItem>
            {["critical", "high", "medium", "low"].map((l) => (
              <SelectItem key={l} value={l} className="capitalize">
                {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground ml-auto">
          {isFetching ? "Loading…" : `${(data?.total ?? 0).toLocaleString()} rules`}
        </span>
      </div>

      <Card className="p-0 overflow-hidden">
        <ul className="divide-y" data-testid="list-rules">
          {(data?.rules ?? []).map((r) => (
            <li key={r.id}>
              <button
                type="button"
                onClick={() => setOpenId(r.id)}
                className="w-full text-left px-4 py-2.5 hover:bg-muted/40 flex items-start gap-3"
                data-testid={`row-rule-${r.ruleId}`}
              >
                <Badge
                  variant="outline"
                  className={`text-[10px] uppercase shrink-0 mt-0.5 ${LEVEL_CLS[r.level ?? ""] ?? ""}`}
                >
                  {r.level ?? SOURCE_LABEL[r.source] ?? "n/a"}
                </Badge>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{r.title}</div>
                  <div className="text-[11px] text-muted-foreground mt-0.5">
                    {[r.product, r.category].filter(Boolean).join(" · ")}
                    {r.author ? ` · ${r.author}` : ""}
                  </div>
                </div>
                <div className="hidden md:flex flex-wrap gap-1 justify-end max-w-[240px]">
                  {r.techniques.slice(0, 4).map((t) => (
                    <Badge key={t} variant="outline" className="font-mono text-[10px]">
                      {t}
                    </Badge>
                  ))}
                </div>
              </button>
            </li>
          ))}
          {data && data.rules.length === 0 && (
            <li className="px-4 py-10 text-center text-sm text-muted-foreground">
              {summary && summary.total === 0
                ? "The rule library is empty. Use “Refresh feeds” to download the SigmaHQ rules."
                : "No rules match."}
            </li>
          )}
        </ul>
      </Card>
      <Pager total={data?.total ?? 0} offset={offset} onChange={setOffset} />

      <Dialog open={!!openId} onOpenChange={(o) => !o && setOpenId(null)}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="pr-6">{detail?.title ?? "Rule"}</DialogTitle>
            <DialogDescription>
              {SOURCE_LABEL[detail?.source ?? "sigmahq"] ?? "Rule"} rule · {detail?.license ?? summary?.license ?? ""} ·
              author attribution is part of the rule and must be kept when you reuse it.
            </DialogDescription>
          </DialogHeader>
          {detail && (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-1.5">
                <Badge variant="outline" className={`text-[10px] uppercase ${LEVEL_CLS[detail.level ?? ""] ?? ""}`}>
                  {detail.level ?? "n/a"}
                </Badge>
                {detail.techniques.map((t) => (
                  <Badge key={t} variant="outline" className="font-mono text-[10px]">
                    {t}
                  </Badge>
                ))}
                {[detail.product, detail.category].filter(Boolean).map((x) => (
                  <Badge key={x} variant="secondary" className="text-[10px]">
                    {x}
                  </Badge>
                ))}
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(detail.raw);
                      toast({ title: "Rule copied" });
                    } catch {
                      toast({ variant: "destructive", title: "Copy failed" });
                    }
                  }}
                  data-testid="button-copy-rule"
                >
                  <Copy size={13} className="mr-1.5" /> Copy YAML
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => download(`${detail.ruleId}.yml`, detail.raw)}
                  data-testid="button-download-rule"
                >
                  <Download size={13} className="mr-1.5" /> Download
                </Button>
              </div>
              {detail.source === "sigmahq" && (
                <div className="rounded-lg border p-3 space-y-2" data-testid="rule-convert">
                  <div className="text-xs font-semibold">Convert to your EDR / SIEM</div>
                  <div className="flex flex-wrap gap-1.5">
                    {RULE_CONVERT_PLATFORMS.map((p) => (
                      <Button
                        key={p.id}
                        size="sm"
                        variant={conv?.platform === p.id ? "default" : "outline"}
                        className="h-7 text-[11px]"
                        onClick={() => runConvert(p.id)}
                        data-testid={`button-convert-${p.id}`}
                      >
                        {p.label}
                      </Button>
                    ))}
                  </div>
                  {conv &&
                    (conv.supported && conv.query ? (
                      <div className="space-y-2">
                        <pre
                          className="text-[11px] leading-relaxed font-mono bg-muted/50 rounded-md p-3 overflow-x-auto whitespace-pre"
                          data-testid="convert-output"
                        >
                          {conv.query}
                        </pre>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-[11px]"
                          onClick={async () => {
                            try {
                              await navigator.clipboard.writeText(conv.query!);
                              toast({ title: "Query copied" });
                            } catch {
                              toast({ variant: "destructive", title: "Copy failed" });
                            }
                          }}
                        >
                          <Copy size={12} className="mr-1.5" /> Copy query
                        </Button>
                        <ul className="text-[11px] text-muted-foreground list-disc pl-4 space-y-0.5">
                          {conv.notes.map((n) => (
                            <li key={n}>{n}</li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <p className="text-xs text-amber-700 dark:text-amber-300" data-testid="convert-error">
                        Can’t convert for this platform: {conv.error}
                      </p>
                    ))}
                  <p className="text-[10px] text-muted-foreground">
                    Conversion is rule-based (no AI) and covers process-creation rules. Test every converted query
                    before deploying.
                  </p>
                </div>
              )}
              <pre
                className="text-[11px] leading-relaxed font-mono bg-muted/50 rounded-md p-3 overflow-x-auto whitespace-pre"
                data-testid="rule-yaml"
              >
                {detail.raw}
              </pre>
              {detail.refs.length > 0 && (
                <div className="text-[11px] text-muted-foreground">
                  <div className="font-medium mb-1">References</div>
                  <ul className="space-y-0.5">
                    {detail.refs.slice(0, 8).map((u) => (
                      <li key={u} className="truncate">
                        {/^https?:\/\//.test(u) ? (
                          <a href={u} target="_blank" rel="noreferrer noopener" className="hover:underline">
                            {u}
                          </a>
                        ) : (
                          u
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="text-[11px] text-muted-foreground border-t pt-2">
                {detail.source === "sigmahq"
                  ? "Rules that can't be converted automatically can be generated by the AI hunt-query tool from a related finding (CrowdStrike IOA, Defender, SentinelOne STAR, Cortex BIOC, Elastic)."
                  : "YARA rules are used as-is by YARA-capable scanners and EDR YARA scan features."}
              </p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function DetectionLibrary() {
  const { toast } = useToast();
  const { user } = useAuth();
  const canSync = !(user?.access_mode === "guest" || user?.role === "reviewer");
  const initial = useMemo(readParams, []);
  const [tab, setTab] = useState(
    initial.get("tab") === "attack"
      ? "attack"
      : initial.get("tab") === "rules" || initial.get("rule") || initial.get("technique")
        ? "rules"
        : "iocs",
  );
  // Jumping from the ATT&CK matrix into the rules list remounts it with the technique preset.
  const [rulesNav, setRulesNav] = useState<{ key: number; params: URLSearchParams }>({ key: 0, params: initial });
  const viewRules = (technique: string) => {
    setRulesNav((n) => ({ key: n.key + 1, params: new URLSearchParams({ technique }) }));
    setTab("rules");
  };

  const { data: status } = useQuery<{ busy: boolean }>({
    queryKey: ["/api/v1/detections/sync/status"],
    refetchInterval: (q) => (q.state.data?.busy ? 3000 : false),
  });
  const sync = useMutation({
    mutationFn: async () => (await apiRequest("POST", "/api/v1/detections/sync", { target: "all" })).json(),
    onSuccess: () => {
      toast({ title: "Refreshing feeds and rules", description: "This takes under a minute." });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/detections/sync/status"] });
    },
    onError: (e: any) =>
      toast({
        variant: "destructive",
        title: "Could not start sync",
        description: String(e?.message ?? e).replace(/^\d+:\s*/, ""),
      }),
  });
  // When a running sync finishes, reload everything on the page.
  const [wasBusy, setWasBusy] = useState(false);
  useEffect(() => {
    if (status?.busy) setWasBusy(true);
    else if (wasBusy) {
      setWasBusy(false);
      queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith("/api/v1/detections") });
    }
  }, [status?.busy, wasBusy]);

  return (
    <AppShell>
      <div className="px-4 md:px-10 py-6 md:py-8 max-w-[1400px]">
        <PageHeader
          title="Detection Library"
          description="Named threat indicators from open feeds and a searchable library of existing detection rules (IoAs) mapped to MITRE ATT&CK — so you know what is already covered before writing a new rule."
          actions={
            canSync ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => sync.mutate()}
                disabled={sync.isPending || !!status?.busy}
                data-testid="button-sync-intel"
              >
                <RefreshCw size={14} className={`mr-1.5 ${status?.busy ? "animate-spin" : ""}`} />{" "}
                {status?.busy ? "Refreshing…" : "Refresh feeds"}
              </Button>
            ) : undefined
          }
        />
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="mb-4">
            <TabsTrigger value="iocs" data-testid="tab-detections-iocs">
              Named IoCs
            </TabsTrigger>
            <TabsTrigger value="rules" data-testid="tab-detections-rules">
              Detection rules
            </TabsTrigger>
            <TabsTrigger value="attack" data-testid="tab-detections-attack">
              MITRE ATT&amp;CK
            </TabsTrigger>
          </TabsList>
          <TabsContent value="iocs" className="mt-0">
            <IocsTab />
          </TabsContent>
          <TabsContent value="rules" className="mt-0">
            <RulesTab key={rulesNav.key} initial={rulesNav.params} />
          </TabsContent>
          <TabsContent value="attack" className="mt-0">
            <AttackMatrix onViewRules={viewRules} />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
