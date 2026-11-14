import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Logo } from "@/components/Logo";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { ArrowRight, CheckCircle2, KeyRound, RadioTower, ShieldCheck, UserRoundCheck } from "lucide-react";

type LoginStep = "credentials" | "mfa";

type SeedAccount = { email: string; password: string; role: string };

/** Batch One entry surface: platform admin and read-only reviewer accounts. */
export default function Login() {
  const { login, loading } = useAuth();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  // Never pre-fill credentials. A pre-filled admin password turns "open the
  // page" into "one click to platform admin" for anyone at the keyboard.
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [step, setStep] = useState<LoginStep>("credentials");
  const [submitting, setSubmitting] = useState(false);
  const mfaRequired = step === "mfa";
  // First-run helper: the server lists seed accounts only while they still use
  // their documented initial password, and only for loopback clients. Once
  // they are rotated this comes back empty and the panel disappears.
  const [seedAccounts, setSeedAccounts] = useState<SeedAccount[]>([]);

  useEffect(() => {
    let cancelled = false;
    apiRequest("GET", "/api/v1/auth/bootstrap")
      .then((r) => (r.ok ? r.json() : { seedAccounts: [] }))
      .then((d) => {
        if (!cancelled) setSeedAccounts(Array.isArray(d?.seedAccounts) ? d.seedAccounts : []);
      })
      .catch(() => {
        /* the hint is optional — a failure just means no panel */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password, mfaRequired ? mfaCode : undefined);
      navigate("/osint");
    } catch (err: any) {
      if (/MFA code required|mfaRequired/i.test(String(err.message ?? err))) {
        setStep("mfa");
        setMfaCode("");
        toast({ title: "MFA code required", description: "Enter the 6-digit code from your authenticator app." });
      } else {
        if (!mfaRequired) setStep("credentials");
        toast({ variant: "destructive", title: "Sign-in failed", description: err.message });
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="tl-identity-shell min-h-screen flex items-center justify-center px-4 sm:px-8 py-6 [@media(min-height:800px)]:py-8">
      <div className="relative z-10 w-full max-w-[1180px] grid grid-cols-1 xl:grid-cols-[0.85fr_1.15fr] gap-6 xl:gap-8">
        <section className="tl-orbit-card xl:order-2 rounded-[10px] p-7 sm:p-10 xl:p-12 flex flex-col justify-between min-h-[430px] xl:min-h-[min(620px,calc(100vh-3rem))] [@media(max-height:800px)]:xl:p-9">
          <div className="relative z-10 max-w-2xl">
            <div className="tl-brand-kicker mb-5 [@media(min-height:800px)]:mb-7">ThreatLens Intel Workstation</div>

            <div className="flex items-center gap-4 mb-5 [@media(min-height:800px)]:mb-8">
              <Logo size={64} className="shrink-0" />
              <div className="flex flex-col leading-none">
                <span className="tl-wordmark text-[38px] sm:text-[44px]">
                  <span className="brand-lead">Threat</span><span className="brand-tail">Lens</span>
                </span>
                <span className="mt-2 text-[11px] font-semibold uppercase text-muted-foreground tracking-[0.22em]">
                  Evidence-led threat operations
                </span>
              </div>
            </div>

            <h1 className="tl-display max-w-[760px]">
              Turn threat signal into actor intelligence and hunt logic.
            </h1>
            <p className="text-[15px] text-muted-foreground leading-[1.7] mt-6 max-w-[590px]">
              Review current intel, inspect actor profiles, and preserve source context
              in one traceable ThreatLens analyst console.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6 [@media(min-height:800px)]:mt-9 max-w-[650px]">
              <Proof icon={<RadioTower size={16} />} label="Review" value="Intel intake" />
              <Proof icon={<UserRoundCheck size={16} />} label="Correlate" value="Actor profiles" />
              <Proof icon={<ShieldCheck size={16} />} label="Queue" value="Hunt queries" />
            </div>
          </div>

          <div className="relative z-10 mt-6 [@media(min-height:800px)]:mt-10 grid grid-cols-1 lg:grid-cols-[1fr_0.86fr] gap-4 items-end [@media(max-height:800px)]:hidden">
            <div className="tl-terminal" aria-hidden="true">
              <div className="tl-terminal-bar"><span /><span /><span /><em>live-feed</em></div>
              <pre>{`$ ingest --sources 40 --window 24h
[kev]   CVE-2026-xxxx  exploited   score 9.8
[epss]  top-1% percentile flagged
[actor] cluster linked -> T1190
[hunt]  sigma + kql generated
$ _`}</pre>
            </div>
            <div className="space-y-3 text-sm">
              <BrandLine text="Strict mode surfaces provider errors" />
              <BrandLine text="Evidence stays linked from source to finding" />
              <BrandLine text="Built for intel triage, threat actor profiling, AI configuration and job monitoring" />
            </div>
          </div>
        </section>

        <section className="tl-card xl:order-1 p-7 sm:p-9 flex flex-col justify-center min-h-[420px] xl:min-h-[min(620px,calc(100vh-3rem))]">
          <div className="mb-7">
            <h2 className="tl-page-title">Sign in</h2>
            <p className="text-sm text-muted-foreground leading-[1.55] mt-1.5">
              Sign in with an assigned account. Reviewer accounts are read-only;
              platform admin accounts enable source, automation, and configuration workflows.
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <KeyRound size={16} className="text-primary" />
              Account sign-in
            </div>
            {!mfaRequired ? (
              <>
                <div className="space-y-1.5">
                  <label className="text-[11px] font-medium uppercase text-muted-foreground tracking-[0.12em]" htmlFor="email">Email</label>
                  <Input
                    id="email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    data-testid="input-email"
                    className="h-11"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-[11px] font-medium uppercase text-muted-foreground tracking-[0.12em]" htmlFor="password">Password</label>
                  <Input
                    id="password"
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    data-testid="input-password"
                    className="h-11"
                  />
                </div>
              </>
            ) : (
              <div className="space-y-1.5">
                <label className="text-[11px] font-medium uppercase text-muted-foreground tracking-[0.12em]" htmlFor="mfaCode">MFA code</label>
                <Input
                  id="mfaCode"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="Enter 6-digit code"
                  data-testid="input-mfa-code"
                  className="h-11 font-mono"
                />
              </div>
            )}
            <Button
              type="submit"
              variant="outline"
              className="w-full h-11 mt-2 justify-between"
              disabled={loading || submitting || (mfaRequired && mfaCode.length !== 6)}
              data-testid="button-login"
            >
              <span>{submitting ? "Signing in..." : mfaRequired ? "Verify MFA code" : "Sign in"}</span>
              <ArrowRight size={15} />
            </Button>
          </form>

          {seedAccounts.length > 0 && (
            <div className="mt-8 pt-5 border-t border-border/60 space-y-2 text-[11px] text-muted-foreground leading-[1.6]">
              <div className="tl-eyebrow text-muted-foreground mb-1">First-run credentials for this install</div>
              {seedAccounts.map((acct) => (
                <div key={acct.email}>
                  <span className="capitalize">{acct.role}</span> ·{" "}
                  <button
                    type="button"
                    className="tl-mono underline underline-offset-2 hover:text-foreground"
                    onClick={() => {
                      setEmail(acct.email);
                      setPassword(acct.password);
                    }}
                    data-testid={`button-seed-${acct.role}`}
                  >
                    {acct.email}
                  </button>{" "}
                  · <span className="tl-mono">{acct.password}</span>
                </div>
              ))}
              <div>Generated on first boot and shown only on this machine. Change them to make this panel disappear.</div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function Proof({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="tl-brand-proof">
      <div className="flex items-center gap-2 text-primary">
        {icon}
        <span className="text-[10px] uppercase font-semibold tracking-[0.1em]">{label}</span>
      </div>
      <div className="mt-2 text-[13px] font-semibold text-foreground">{value}</div>
    </div>
  );
}

function BrandLine({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-border bg-background/55 px-3 py-2 text-xs text-muted-foreground">
      <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-primary" />
      <span>{text}</span>
    </div>
  );
}
