/**
 * Lightweight, explainable ATT&CK technique inference from article text. Used
 * only when a finding has no AI-extracted techniques, so the rule coverage check
 * still works with AI analysis turned off. Results are always shown as
 * "inferred" in the UI — they are a starting point, not a verdict.
 */
const RULES: Array<{ id: string; name: string; re: RegExp }> = [
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    re: /\b(unauthenticated|pre-?auth)\b.{0,60}\b(rce|remote code|command injection|sql injection|deserializ|bypass)|exploit(?:ed|ation)?\b.{0,40}\b(vpn|firewall|gateway|sharepoint|exchange|citrix|netscaler|fortios|pan-os|web server)/i,
  },
  { id: "T1566", name: "Phishing", re: /\bphishing|spear-?phish|malicious (?:email|attachment)|credential harvest/i },
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    re: /\bransomware|encrypt(?:s|ed|ing)? (?:files|data|systems)|double extortion/i,
  },
  { id: "T1003", name: "OS Credential Dumping", re: /\bcredential dump|lsass|mimikatz|ntds\.dit|secretsdump/i },
  { id: "T1059.001", name: "PowerShell", re: /\bpowershell\b|\bpwsh\b|encoded command/i },
  { id: "T1059.003", name: "Windows Command Shell", re: /\bcmd\.exe\b|windows command shell/i },
  { id: "T1505.003", name: "Web Shell", re: /\bweb ?shell/i },
  { id: "T1574.002", name: "DLL Side-Loading", re: /\bdll side-?load|dll hijack/i },
  {
    id: "T1195",
    name: "Supply Chain Compromise",
    re: /\bsupply[- ]chain|malicious (?:npm|pypi|package)|compromised (?:package|update)/i,
  },
  { id: "T1110", name: "Brute Force", re: /\bbrute[- ]force|password spray|credential stuffing/i },
  {
    id: "T1071",
    name: "Application Layer Protocol (C2)",
    re: /\bc2\b|command[- ]and[- ]control|beacon(?:ing)?|cobalt ?strike/i,
  },
  { id: "T1021.001", name: "Remote Desktop Protocol", re: /\brdp\b|remote desktop/i },
  { id: "T1053.005", name: "Scheduled Task", re: /\bscheduled task|schtasks/i },
  {
    id: "T1547.001",
    name: "Registry Run Keys / Startup Folder",
    re: /\brun key|\\currentversion\\run|startup folder/i,
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    re: /\bdownloads? (?:and executes?|a payload|additional)|certutil .{0,20}urlcache|bitsadmin/i,
  },
  { id: "T1068", name: "Exploitation for Privilege Escalation", re: /\bprivilege escalation|local privilege|\blpe\b/i },
  { id: "T1055", name: "Process Injection", re: /\bprocess injection|process hollowing|inject(?:s|ed)? into/i },
  { id: "T1567", name: "Exfiltration Over Web Service", re: /\bexfiltrat/i },
  {
    id: "T1078",
    name: "Valid Accounts",
    re: /\bstolen credentials|compromised (?:accounts?|credentials)|valid accounts/i,
  },
  {
    id: "T1562",
    name: "Impair Defenses",
    re: /\bdisable(?:s|d)? (?:edr|antivirus|defender|security tools)|edr killer|tamper(?:s|ing)? with (?:security|defender)/i,
  },
];

export interface InferredTechnique {
  id: string;
  name: string;
}

export function inferTechniques(text: string, max = 8): InferredTechnique[] {
  const hay = String(text || "").slice(0, 20_000);
  const out: InferredTechnique[] = [];
  for (const r of RULES) {
    if (r.re.test(hay)) out.push({ id: r.id, name: r.name });
    if (out.length >= max) break;
  }
  return out;
}
