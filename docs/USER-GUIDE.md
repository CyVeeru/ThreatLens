# ThreatLens User Guide

How to run a threat intelligence workflow in ThreatLens, from raw feed noise to
a report someone else can act on.

This guide is for the analyst or engineer operating the tool. For how the code
is laid out see [ARCHITECTURE.md](../ARCHITECTURE.md); for hosting and hardening
see [DEPLOYMENT.md](../DEPLOYMENT.md) and [SECURITY.md](../SECURITY.md).

---

## Contents

1. [What ThreatLens is for](#1-what-threatlens-is-for)
2. [The evidence model](#2-the-evidence-model)
3. [First run](#3-first-run)
4. [Intel Inbox — intake and triage](#4-intel-inbox--intake-and-triage)
5. [Review Desk — the work queue](#5-review-desk--the-work-queue)
6. [Cases — investigations](#6-cases--investigations)
7. [Actor Observatory — dossiers](#7-actor-observatory--dossiers)
8. [Hunt queries and hunt results](#8-hunt-queries-and-hunt-results)
9. [CVE enrichment and exploitation ranking](#9-cve-enrichment-and-exploitation-ranking)
10. [ATT&CK coverage](#10-attck-coverage)
11. [Private intel ingest](#11-private-intel-ingest)
12. [Reports](#12-reports)
13. [AI: what it does and what it will not do](#13-ai-what-it-does-and-what-it-will-not-do)
14. [Roles and permissions](#14-roles-and-permissions)
15. [Job Control and automation](#15-job-control-and-automation)
16. [A worked week](#16-a-worked-week)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. What ThreatLens is for

ThreatLens is a single-operator CTI workstation. It pulls public threat
intelligence from a curated source catalog, helps you triage it, and keeps the
chain from *original source* to *analyst conclusion* intact so that the report
you hand over can be defended.

It is deliberately **not** a SIEM, a TIP with a STIX/TAXII server, or a
detection pipeline. It does not ingest your telemetry and it does not run
queries against your estate — it drafts the queries and records what you found
when you ran them elsewhere.

**Use it when** you need to know what is being publicly reported, decide what
matters to your organisation, and produce something written.

**Do not use it** as your only source of truth for exploitation status, or as an
automated blocklist feed. Every finding is public reporting until an analyst
marks it otherwise.

---

## 2. The evidence model

Everything in ThreatLens hangs off four object types. Understanding how they
relate is most of learning the tool.

| Object | What it is | Created by |
|---|---|---|
| **Finding** | One item of intelligence — an advisory, blog post, CVE writeup, leak-site listing | Ingest from a source, or a document you upload |
| **Threat actor** | A dossier: aliases, TTPs, tooling, campaigns, IOCs, references | Seeded catalog, or created by you |
| **Hunt query** | Detection logic drafted for a specific platform | You, usually with AI assistance |
| **Case** | An investigation that links the above together with notes and a timeline | You |

Three rules govern the whole system:

1. **A finding always keeps its source.** Source name, URL, category and fetch
   time travel with it. Nothing becomes anonymous "intel".
2. **Provenance is tracked separately from content.** Report sections are tagged
   `[feed]` (ingested), `[verified]` (analyst-recorded) or `[ai]` (model output).
   Analyst-verified content is always included in a report; AI content is
   optional and can be excluded with `includeAi: false`.
3. **AI-authored rows are marked and replaceable.** Actor enrichment writes rows
   with `origin='ai'`. Re-running enrichment deletes only those rows — anything
   you typed yourself survives.

---

## 3. First run

ThreatLens ships **no passwords**. On first boot it creates two accounts and
generates a random password for each, unique to your install:

| Account | Role |
|---|---|
| `admin@threatlens.local` | Platform admin |
| `reviewer@threatlens.local` | Read-only reviewer |

The generated passwords are printed to the server log and written to
`data/initial-credentials.json`. The sign-in page shows them too, but **only**
while the accounts still use them and **only** to a browser on the same machine.
Set `THREATLENS_SHOW_SEED_CREDENTIALS=1` if you reach the UI from another host.

Change both passwords at first login. Doing so prunes each account from
`data/initial-credentials.json`, deletes the file once empty, and removes the
sign-in hint — a configured install carries no first-run credential anywhere.

MFA (TOTP) is optional and recommended. Set `THREATLENS_REQUIRE_MFA=1` to make
enrolment mandatory for every account. Accounts that enrol voluntarily are
always asked for a code, whether or not enforcement is on.

ThreatLens binds to `127.0.0.1:7099` by default. It holds credentials, provider
keys and unreviewed intel, so it is not reachable from your network until you
ask. To serve other machines set `THREATLENS_HOST=0.0.0.0` and put a
TLS-terminating reverse proxy in front.

---

## 4. Intel Inbox — intake and triage

The Intel Inbox is where raw intelligence lands. Four tabs:

### Findings

The working list. Filter by severity, status, category, source, or free text
across title, IOC, CVE and actor. Findings carry:

- **Severity** — from the source or inferred at parse time
- **Category** — `CERT_GOV`, `CVE_VULN`, `RANSOMWARE_LEAK`, `SECURITY_NEWS`,
  `THREAT_INTEL`, `VENDOR_RESEARCH`
- **Confidence** and **staleness** — how much to trust it and how old it is
- **Extracted entities** — CVE IDs, affected technologies, IOCs, actor names

**Scan now** walks the source catalog over a recent window (7 days) and
persists everything it parses. Ingest deduplicates, so re-scanning is safe and a
scan that returns `count: 0` genuinely means "nothing new since last time".

Filtering happens at *view* time, not ingest time: a scan stores what the feeds
published, and the severity/category/source/date controls decide what you look
at. That separation matters — narrowing at ingest throws away reporting you
cannot get back without re-fetching.

For a deeper backfill than the 7-day window, the **Sources** tab has a
**Refresh all sources** button (admin only) that walks the whole catalog over a
year and takes a few minutes.

**AI analyse** runs per-finding analysis on the selection. **Hunt query** drafts
detection logic from the selected findings. **STIX preview** shows the STIX 2.1
bundle for what you have selected.

### Sources

The catalog — 90+ curated feeds with category, region, language, reliability
rating (A–D), finding count and last fetch time. You can enable, disable, or
add your own.

Two things worth knowing:

- Outbound fetching is **HTTPS-only**. An `http://` source URL can never be
  fetched; the test suite enforces this on the shipped catalog.
- Sources with hand-written **deep parsers** (MISP event feeds, CSV IOC lists,
  JSON APIs) extract structured IOCs. Everything else goes through a generic
  RSS/Atom/RDF adapter.
- Seeding never overwrites an existing source row, so your edits to name, URL,
  reliability or enabled state survive upgrades. The trade-off: a corrected
  catalog URL in a new release does not reach a source row you already have.

### Hunting queries

Saved detection logic. See [section 8](#8-hunt-queries-and-hunt-results).

### Automation

Background fetch and analyse, off by default. See
[section 15](#15-job-control-and-automation).

---

## 5. Review Desk — the work queue

The Intel Inbox is the firehose. The Review Desk is the part you are accountable
for. Five tabs:

### Queue

Findings awaiting a decision, ordered by a score that weights severity and age.
Each finding moves through:

`new` → `triaged` → `assessed` → `escalated` **or** `dismissed`

Every transition is recorded with who made it and when. Dismissing something is
a decision with a name on it, not a delete.

### SLA metrics

Backlog broken down by age (`<24h`, `1–3d`, `3–7d`, `>7d`), plus unassigned and
overdue counts, and throughput over a rolling window — how many findings were
triaged, dismissed and escalated.

This is the tab that tells you whether the queue is being worked or is quietly
growing.

### ATT&CK coverage

See [section 10](#10-attck-coverage).

### Private intel

See [section 11](#11-private-intel-ingest).

### Reports

See [section 12](#12-reports).

---

## 6. Cases — investigations

A case is what you open when a finding needs more than a triage decision.

Cases hold **links** to four entity types:

- `osint_finding`
- `threat_actor`
- `hunt_query`
- `cve`

…plus free-text **notes**, a status, a severity, and an automatically derived
**timeline**. The timeline is not a separate thing you maintain — it is built
from the case's own history: creation, each link added, each note, each status
change, in order.

That timeline is what makes a case reportable. When you generate a
`case_report`, it renders from the links and notes you actually recorded, with
provenance tags intact.

**Typical flow:** escalate a finding from the Review Desk → open a case → link
the finding, the CVE it references, and the actor dossier → draft a hunt query
and link it → record what the hunt found → generate the case report.

---

## 7. Actor Observatory — dossiers

Threat actor profiles. Each dossier holds aliases, actor type, threat level,
TLP marking, target geographies and industries, plus sub-resources:

- **TTPs** mapped to MITRE ATT&CK technique IDs, with a detection priority and status
- **Tooling** — malware families and utilities
- **Campaigns** — named operations with dates
- **IOCs** — typed indicators
- **References** — the reporting the dossier is built from

**Enrichment** uses AI to populate a dossier from public reporting. It runs in a
transaction and deletes only rows marked `origin='ai'` before writing new ones,
so hand-entered intelligence is never overwritten by a re-run. Always review
enriched content before treating it as fact — see
[section 13](#13-ai-what-it-does-and-what-it-will-not-do).

Each dossier can export a **MITRE ATT&CK Navigator layer** (format 4.5) of that
actor's techniques, for loading into Navigator alongside your own coverage.

### Activity signals — is this actor active *now*?

A dossier is a written document: it is accurate as of the day someone last
wrote it, and says nothing about whether the actor is active today. The
Observatory answers that separately, from your ingested intel rather than from
the dossier.

Every actor carries a freshness chip derived by matching its primary name,
aliases and vendor synonyms against the actor names parsed out of findings:

| Signal | Meaning |
|---|---|
| **Active** | Named in a finding inside the activity window (30 days by default) |
| **Quiet** | Has intel, but none inside the window |
| **No intel** | No ingested finding has ever named this actor |

The header strip totals these and flags how many **dossiers are behind their own
intel** — that is, actors whose most recent finding is newer than the last time
the dossier was written. Those are your re-write candidates.

This costs nothing and needs no AI: it is a query over data you have already
ingested, so it is correct the moment a scan finishes. The list defaults to
ordering by activity rather than by name, and refreshes every 30 seconds, so
ingesting a document that names a quiet actor moves it to the top on the next
tick. Toggle **By activity / By name** to change the ordering.

Note what this does and does not do: it tells you *which* dossiers have gone
stale against current reporting. It does not rewrite dossier prose — that is
still the enrichment job, run per actor when you decide the evidence warrants
it.

---

## 8. Hunt queries and hunt results

ThreatLens drafts detection logic in nine dialects:

| | |
|---|---|
| Splunk SPL | ELK KQL (Kibana / Elastic) |
| Google Chronicle YARA-L 2.0 | Microsoft Defender / Sentinel KQL |
| CrowdStrike Falcon LogScale (CQL) | Palo Alto Cortex XDR (XQL) |
| SentinelOne PowerQuery | YARA |
| Sigma (YAML) | |

Generate a query from one or more findings, then save it. Saved queries carry
the findings and ATT&CK techniques they came from.

**Recording hunt results is the step people skip, and it is the one that makes
the tool worth running.** When you run a query in your SIEM or EDR, come back
and record the outcome — hit or no hit, with a note. This does two things:

1. It closes the loop on the case.
2. It is the only input that flips ATT&CK coverage from "we wrote a query" to
   "we actually looked".

---

## 9. CVE enrichment and exploitation ranking

ThreatLens enriches CVE IDs from three public sources:

| Source | What it provides |
|---|---|
| **NVD** | CVSS base score and vector, severity, description, publication date |
| **FIRST EPSS** | Probability of exploitation in the next 30 days, plus percentile |
| **CISA KEV** | Whether it is a *known* exploited vulnerability, date added, known ransomware use |

These are combined into a single 0–100 **exploitation priority**:

```
priority = 60 if in KEV
         + round(EPSS × 30)
         + round(CVSS ÷ 10 × 10)
         capped at 100
```

The weighting is deliberate and it is the opinion the tool holds most strongly:

**Confirmed exploitation outranks predicted exploitation, which outranks
theoretical severity.** A CVSS 10.0 with no evidence of exploitation scores
below a CVSS 7.5 sitting in KEV. This exists to counter the habit of patching by
CVSS alone.

Worked example — CVE-2021-44228 (Log4Shell): KEV `true` (+60), EPSS 0.99999
(+30), CVSS 10.0 (+10) = **100**, flagged for known ransomware use.

NVD's public API allows roughly 5 requests per 30 seconds without a key, so
background enrichment is rate-limited (`THREATLENS_NVD_PER_TICK`, default 4).
EPSS and KEV are bulk downloads and are not throttled.

---

## 10. ATT&CK coverage

The coverage view answers one question: **for the techniques appearing in our
intel, have we actually looked?**

Every ATT&CK technique observed in findings or actor dossiers gets one of four
states:

| State | Meaning |
|---|---|
| `hit` | A hunt ran and found something |
| `hunted` | A hunt ran and found nothing |
| `drafted` | A query exists but no result was ever recorded |
| `none` | The technique shows up in intel, but nobody wrote a query |

`none` and `drafted` are your gaps. `drafted` is the more uncomfortable one — it
means the work was started and never finished.

Export as a **Navigator layer (format 4.5)** to overlay this on the ATT&CK
matrix, or diff it against a client's or a team's existing coverage layer.

---

## 11. Private intel ingest

Not all intelligence is public. Upload ISAC bulletins, vendor PDFs, incident
notes or partner reports and they become normal findings.

Accepted: **PDF, Markdown, plain text, HTML, JSON.**

Uploaded documents are parsed for the same entities as any feed item — CVE IDs,
IOCs, affected technology, actor names — and filed under the `Analyst uploads`
source (`osrc-9001`) so they are visible and attributable in the Sources tab
like everything else. Re-uploading the same document is rejected as a duplicate.

Once ingested they triage, link to cases, and appear in reports exactly like
public findings.

---

## 12. Reports

Three report kinds:

| Kind | Covers |
|---|---|
| `executive_brief` | Current posture: volume, escalations, backlog, coverage |
| `weekly_landscape` | What changed across the reporting window |
| `case_report` | One investigation, from its links, notes and timeline |

Two formats: **Markdown** (`md`) and **Word** (`docx`).

Every section is provenance-tagged. `[verified]` content — what analysts
actually recorded — is always included. `[ai]` content is included only when
`includeAi` is true, so you can produce a document containing nothing a model
wrote. `[feed]` marks figures taken straight from ingested data.

This matters when a report leaves your team. A reader can see which claims are
analyst assessments and which are machine-generated, without asking.

---

## 13. AI: what it does and what it will not do

ThreatLens routes AI work to a provider you configure. Supported: OpenAI,
Anthropic, Google Gemini, DeepSeek, Azure OpenAI, Perplexity, Kimi, and local
Ollama.

Six tasks can each be assigned to a different provider and model, with
per-provider tuning:

| Task | Used for |
|---|---|
| `osint_analysis` | Per-finding analysis |
| `osint_overview` | CIRT triage across a date range |
| `osint_chat` | The analyst chat assistant |
| `hunt_query` | Drafting detection logic |
| `threat_actor_enrichment` | Populating actor dossiers |
| `tap_portrait` | Actor portrait generation |

### Strict mode

With `THREATLENS_STRICT=1` (the default when `NODE_ENV=production`), a
misconfigured or unavailable provider returns a **real error** — HTTP 409 or 502
with the provider's message. It never silently falls back to mock output.

This is the right default for analysis work. Mock output that looks like
analysis is worse than no output, because it is indistinguishable from the real
thing in a report.

### Guardrails

- The **server owns the system prompt.** The API rejects a client-supplied
  `system` role outright, so a caller cannot rewrite the assistant's
  instructions through the chat endpoint.
- Conversations are bounded: 60 messages, 24,000 characters each, 50 attached
  findings. These are spend caps as much as safety caps.
- The chat assistant **declines software development requests.** Ask it to
  modify the application, write application code, or run repository commands and
  it refuses. Detection and hunt artifacts — Sigma, SPL, KQL, YARA — are
  explicitly exempt, because those are analyst deliverables.

### What you still have to do

AI output is a draft. Actor enrichment, per-finding analysis and generated hunt
queries are all starting points for review, not conclusions. The provenance
tagging exists precisely because the tool does not expect you to trust them
unreviewed.

---

## 14. Roles and permissions

Two roles ship. Permissions are capability-based, not role-string checks.

| Capability | Admin | Reviewer |
|---|:--:|:--:|
| View intel, actors, hunt queries | ✅ | ✅ |
| Task AI analysis | ✅ | ✅ |
| View jobs | ✅ | ✅ |
| Manage cases | ✅ | ✅ |
| Record hunt results | ✅ | ✅ |
| Export reports | ✅ | ✅ |
| Manage sources | ✅ | ❌ |
| Configure AI providers | ✅ | ❌ |
| Manage jobs | ✅ | ❌ |
| Upload documents | ✅ | ❌ |
| Manage platform users | ✅ | ❌ |

A reviewer can do the analytical work — own cases, record what a hunt found,
pull reports — but cannot change what the platform ingests, which models it
calls, or who can log in.

Sessions expire on both an absolute and an idle timer, tighter for admins
(12h absolute / 1h idle by default, versus 24h / 12h). All five limits are
configurable.

---

## 15. Job Control and automation

Long-running work — AI analysis, scans, reanalysis — runs as a **job**, not as a
blocking request.

Job Control shows active jobs, failures with diagnostics, recently completed
work and the audit log. Jobs can be cancelled while queued or running, and
cancellation is real: it propagates an `AbortSignal` through to the in-flight
HTTP request, rather than marking a row cancelled and letting the work continue.

**Automation** (Intel Inbox → Automation) is what keeps the workspace current
without anyone clicking. Two independent switches:

- **Auto-fetch** walks the catalog every `fetchIntervalMin` minutes over a
  rolling 3-day window and stores whatever is new. No AI, so it is cheap and
  fast — this is the one to turn on if you want the Intel Inbox to stay live.
- **Auto-analyse** runs per-finding AI analysis on newly ingested items, so a
  later deep dive is instant retrieval rather than a wait. This calls your
  provider once per finding: on a slow or metered model it is the expensive
  half, which is why it is separate.

Both are **off by default** and require the `manage_sources` capability.
Concurrency and per-tick caps are configurable. If a workspace has been idle a
while, run **Refresh all sources** once to backfill, then let auto-fetch keep
pace from there.

---

## 16. A worked week

A realistic loop for one analyst:

**Monday — intake.** Scan the catalog. Work the Review Desk queue: triage or
dismiss everything from the weekend. Escalate what is relevant to your
organisation's technology and sector.

**Tuesday — vulnerabilities.** Enrich the CVEs on escalated findings. Sort by
exploitation priority. Anything in KEV with an EPSS above 0.5 that touches your
estate is this week's patching conversation, whatever its CVSS says.

**Wednesday — investigate.** Open cases on the escalations that survived
Tuesday. Link the findings, CVEs and actor dossiers. Draft hunt queries for the
techniques involved.

**Thursday — hunt.** Run the queries in your SIEM or EDR. **Come back and record
the results.** Check ATT&CK coverage: anything still `drafted` is a query you
wrote and never ran.

**Friday — report.** Generate an `executive_brief` for management and a
`case_report` for each investigation. Check the SLA tab: if the backlog grew
across the week, next Monday starts earlier.

---

## 17. Troubleshooting

**A scan returns `count: 0`.** Usually correct — ingest deduplicates, so nothing
new means nothing new. Check the Sources tab for last-fetch times to confirm
feeds are actually being reached; the scan result also reports how many feeds
answered (`feedsOk` of `feedsTried`).

**The Intel Inbox looks frozen / the news is old.** Check Automation: if
auto-fetch is off, nothing refreshes on its own and the workspace only advances
when someone presses **Scan now**. Turn on auto-fetch, and run **Refresh all
sources** once to backfill the gap.

**A source never produces findings.** Check the URL is `https://` — plaintext is
refused outbound. Confirm the feed still exists and returns RSS/Atom/RDF or
JSON; publishers move and retire feeds regularly. An HTML page with no feed is
skipped unless a deep parser handles it.

**AI calls fail with 409 or 502.** That is strict mode working. The message
carries the provider's own error. Check the key, the base URL and the model name
in AI Setup — the provider test button reports the real failure.

**CVE enrichment returns nothing.** The cache may be empty on a new install.
Trigger enrichment explicitly for the CVEs you care about; background enrichment
is rate-limited to stay inside NVD's unauthenticated quota.

**Login shows no first-run credentials.** Expected once the passwords are
changed — the panel is meant to disappear. It is also hidden from non-loopback
clients unless `THREATLENS_SHOW_SEED_CREDENTIALS=1`.

**The UI is unreachable from another machine.** ThreatLens binds to
`127.0.0.1` by default. Set `THREATLENS_HOST=0.0.0.0`, and put TLS in front
before you do.
