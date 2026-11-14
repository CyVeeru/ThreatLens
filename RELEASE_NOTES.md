## ThreatLens v1.0.0

First public release of ThreatLens, a free, open-source (Apache-2.0) cyber threat intelligence workstation for SOC analysts, CTI analysts and detection engineers.

### Highlights

- **Intelligence Feed** with live OSINT findings, CIRT triage, deep dive and STIX preview.
- **My Organization**: tell ThreatLens what you run, then switch the feed and analyst queue between *Global* and *My organization*, ranked by KEV, EPSS, CVSS and asset criticality.
- **Detection Library**: named IoCs from open feeds, 2,600+ Sigma rules, YARA rules, a MITRE ATT&CK matrix coloured by detection coverage, and a per-finding coverage verdict (covered / partial / gap).
- **Export and generate for your EDR**: IoC export for CrowdStrike, Defender for Endpoint, SentinelOne, Cortex XDR, Elastic and Splunk; a rule-based Sigma-to-EDR converter; AI-generated IoAs and EDR rules (linted, always review before deploying).
- **Analyst Queue, Cases, Threat Actor Profiles**, hunt queries for seven platforms, ATT&CK Navigator layers and reports.
- Bring your own AI provider key; nothing is sent anywhere unless you configure it.

### Run it

```bash
git clone https://github.com/CyVeeru/ThreatLens.git
cd ThreatLens
npm install            # Node 20 or 22
npm run db:restore-public
npm run dev            # http://localhost:7099
```

On first boot ThreatLens generates its own admin account. See the README for details.

### Known limits

- The Sigma-to-EDR converter handles process-creation rules only.
- abuse.ch ThreatFox, URLhaus and MalwareBazaar are not integrated yet.
- EDR import formats follow vendor documentation; test them in your console before production use.
- AI-generated rules need human review.
- This release archive is unsigned. Verify it with `SHA256SUMS` (see VERIFYING.md).

Third-party rules and feeds are downloaded at runtime under their own licences and are not redistributed here. See NOTICE.
