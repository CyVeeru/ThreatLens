# Detection Library — plan

Goal: give SOC engineers three things in one place — fresh **named IoCs**, a
searchable library of **existing detection rules / IoAs**, and a **coverage
check** that tells them, for any news item, whether detections already exist or
a new rule is needed.

## Research summary (verified from the build host, Nov 2026)

| Need                  | Source                                                              | Access                                                       | Notes                                                                        |
| --------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| Named C2 IPs          | abuse.ch Feodo Tracker (`ipblocklist.json`)                         | open                                                         | malware family, port, status, first/last seen                                |
| Named C2 IPs          | C2IntelFeeds (`IPC2s-30day.csv`)                                    | open                                                         | framework name per IP (Cobalt Strike, etc.)                                  |
| Phishing URLs         | OpenPhish community feed                                            | open                                                         | URL only; name = "Phishing"                                                  |
| IoC firehose          | abuse.ch ThreatFox / URLhaus / MalwareBazaar                        | **now needs a free Auth-Key** (bulk exports return HTTP 410) | phase 2, opt-in via env key                                                  |
| Existing rules / IoAs | SigmaHQ release `sigma_core+.zip` (2.5 MB, ~3k rules)               | open                                                         | ATT&CK tags, logsource, level; license **DRL 1.1** (keep author attribution) |
| Behaviour catalogue   | MITRE ATT&CK STIX (55 MB)                                           | open                                                         | phase 2: technique descriptions + detection guidance                         |
| Other rule repos      | Elastic detection-rules (ELv2), Splunk security_content, YARA-Forge | open, **licence limits**                                     | phase 2, link-only unless licence permits redistribution                     |

Not available: no vendor publishes an open EDR rule repository (CrowdStrike
IOA, Defender, SentinelOne STAR, Cortex BIOC). The practical path is Sigma as the
source of truth, plus AI conversion to each EDR's native format (already built in
the hunt-query pipeline).

## Status

**Built**

- Named IoC library: Feodo Tracker, C2IntelFeeds, OpenPhish and the CIRCL OSINT
  feed (named reports with hashes, domains and IPs; automated daily dumps such as
  "Maltrail IOC for <date>" are filtered out). Hourly refresh. Export any threat,
  or selected findings, in CrowdStrike / Defender / SentinelOne / Cortex / Elastic /
  Splunk / plain formats.
- Rule library: SigmaHQ (2.6k rules, DRL 1.1) and ReversingLabs YARA (310 files,
  MIT). Weekly refresh. Search by text, CVE, ATT&CK technique, product, severity, source.
- MITRE ATT&CK Enterprise matrix with per-technique rule counts, MITRE detection
  strategies and analytics, and a jump from any technique to its rules.
- Sigma -> native conversion without AI for process-creation rules: Defender KQL,
  CrowdStrike CQL, SentinelOne Deep Visibility, Cortex XQL, Elastic EQL, Splunk SPL.
  Unsupported rules/fields are refused with the reason, never guessed.
- Coverage check per finding (covered / partial / gap) with text-based technique
  inference when AI analysis is off, and a one-click "Generate detection" that asks
  the configured AI for Sigma, an IoA, or an EDR-native rule.

**Not yet**

- abuse.ch ThreatFox / URLhaus / MalwareBazaar (need a free Auth-Key and POST support
  in the fetcher).
- Converting non-process-creation rules (network, file, registry, DNS) and Sigma
  correlation rules.
- Splunk security_content and Elastic detection-rules (licence / size).
- Rule lifecycle (draft -> reviewed -> deployed) and hunt-result feedback.

## Original scope (for reference)

**Phase 1 (this change)**

1. `ioc_intel` table + sync of Feodo, C2IntelFeeds, OpenPhish (hourly, on the
   existing scheduler). Search by value, name/family, type, source.
2. `rule_library` table + sync of SigmaHQ (weekly). Search by text, ATT&CK
   technique, product, severity. Raw YAML viewable and downloadable with the
   original author/licence.
3. Coverage check: for a finding, match its ATT&CK techniques and CVE ids to
   library rules and report **covered / partial / gap**.
4. "Detection Library" page and a coverage panel in the finding detail.

**Phase 2**

- abuse.ch ThreatFox/URLhaus with a user-supplied Auth-Key.
- ATT&CK technique pages with detection guidance; technique → rules view.
- One-click "convert this Sigma rule to CrowdStrike / Defender / S1 / Cortex /
  Elastic" using the configured AI provider, with syntax validation.
- Rule lifecycle: draft → reviewed → deployed, with hunt-result feedback.
- Elastic/Splunk rule indexes where the licence allows.

## Design rules

- Feeds are public intel, so tables are workspace-wide, not per tenant.
- Every feed is optional and isolated: one failing source never blocks others,
  and the last error is stored and shown.
- Rule text is stored verbatim with author and licence; ThreatLens never strips
  attribution.
- IoC values are validated and private/reserved ranges dropped before storing.
