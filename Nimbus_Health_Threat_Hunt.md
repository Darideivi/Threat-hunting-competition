

# Threat Hunt: Nimbus Health — Valid Account Compromise & Cross-Department Data Collection

<p align="center">
  <em>Disproving an insider-access theory and reconstructing a hands-on-keyboard intrusion using Microsoft Sentinel and Defender for Endpoint</em>
</p>

---

## Incident Brief

| | |
|---|---|
| **Organization** | Nimbus Health |
| **Trigger** | Unusual activity flagged on a billing analyst account. Initial theory: an employee who retained access after changing roles. |
| **Platform** | Microsoft Sentinel / Microsoft Defender for Endpoint (MDE) |
| **Hosts Investigated** | `NH-WKS-BILL-01`, `NH-WKS-IT-01`, `NH-FS-01` |
| **Data Sources** | Microsoft Defender XDR Advanced Hunting — `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents` |
| **Investigation Window** | March 8 – March 18, 2026 |
| **Analyst** | David Pena |
| **Date Completed** | 07/11/2026 |

> Completed as part of a live-scored cyber range exercise ("Just Another Day: Compromised Account Investigation").

---

## Executive Summary

Nimbus Health requested a routine posture review after unusual activity surfaced on a billing analyst's account, initially suspected to be an employee with leftover access from a prior role. The investigation disproved that theory: the account, `j.morris`, was authenticating successfully from an external IP address and being operated hands-on-keyboard using entirely native Windows tools — no malware, no custom binaries. The attacker performed reconnaissance, moved to a second workstation (which turned out to be a red herring), enumerated permissions and shares, then crossed from the billing analyst's normal scope into HR and approved-invoice data, staged a payroll file under a disguised filename, and collected personnel records. The case demonstrates that a compromised valid account can look, at first glance, exactly like a policy violation — and that distinguishing the two requires correlating logon, process, and file telemetry rather than trusting any single signal.

---

## Hunt Objectives

- Determine whether the flagged activity represented an insider with leftover permissions, a compromised account, malware, or another intrusion type
- Reconstruct the full scope of attacker activity across authentication, process execution, and file access
- Map observed behavior to MITRE ATT&CK
- Document detection opportunities for a living-off-the-land, valid-account intrusion

---

## Investigation Timeline

### Phase 1 — Initial Access

**Finding:** Remote interactive logons to `j.morris`'s account originated from an external IP rather than from inside the clinic — immediately undercutting the leftover-access theory.

| Field | Value |
|---|---|
| Account | `j.morris` |
| Source | External IP `193.36.225.245` |
| Access Type | Remote Interactive (RDP) |

**Why it matters:** A successful logon under valid credentials from an unfamiliar external address is the first sign this isn't routine internal access. This finding reframes the entire investigation from a policy question to a compromise question.

**MITRE:** T1078 (Valid Accounts), T1021.001 (Remote Desktop Protocol)

---

### Phase 2 — Reconnaissance

**Finding:** The attacker relied entirely on native Windows commands to orient themselves on the host and the network — no custom tooling.

Commands observed:
```
whoami
hostname
net view
net view \\NH-FS-01
arp -a
whoami /groups
net share
```

#### Evidence — Q16: Checking Their Rights

**What to Hunt:** Process execution by the compromised account referencing `whoami` on the file server, to see whether the attacker checked their own permission level after landing.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-19))
| where DeviceName startswith "nh-fs-01"
| where InitiatingProcessAccountName == "j.morris"
| where ProcessCommandLine has "whoami"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

**Result:** `whoami.exe /groups` executed on `nh-fs-01` at 3/11/2026, 1:37:23 PM UTC.

<img width="828" height="492" alt="Q16-Checking-Rights" src="https://github.com/user-attachments/assets/366addcd-7e1f-46ce-baf3-c8eecd55c142" />


**Why it matters:** Running `/groups` specifically (rather than a bare `whoami`) shows the attacker was deliberately checking their access level on the file server before deciding what to access next — a clear sign of purposeful, hands-on-keyboard reconnaissance rather than an automated script.

**MITRE:** T1018 (Remote System Discovery), T1016 (Network Discovery), T1069 (Permission Groups Discovery), T1135 (Network Share Discovery)

---

### Phase 3 — Lateral Movement

**Finding:** The attacker's session touched `NH-WKS-IT-01` in addition to the billing workstation. Investigation showed only first-logon Windows initialization processes ran there — no attacker-driven activity. This host was a red herring rather than a genuine pivot point.

**Hosts reached:** `NH-WKS-IT-01`, `NH-FS-01`

**Why it matters:** Successful logon to a second host doesn't automatically mean it was operationally used. Distinguishing "touched" from "actively used" prevented over-scoping the incident to a workstation that was never actually leveraged.

**MITRE:** T1021.001

---

### Phase 4 — Unauthorized Access

**Finding:** Instead of remaining within the `Pending` claims scope expected for a billing analyst, the account accessed `Billing` and `Approved` — outside the account's normal business role.

#### Evidence — Q09: Out of Role

**What to Hunt:** File events initiated by `j.morris` where the folder path includes `Billing`, to check whether access stayed within the expected `Pending` claims workflow.

**KQL Query Used:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-19))
| where InitiatingProcessAccountName == "j.morris"
| where FolderPath has "Billing"
| project TimeGenerated, DeviceName, FolderPath, FileName
| order by TimeGenerated asc
```

**Result:** Multiple accesses across `nh-wks-bill-01` and `nh-fs-01`, including `billing_baseline_20260310.lnk`, a `Billing (nh-fs-01) - Shortcut.lnk`, and — notably — `\\NH-FS-01\Billing\2026-03\Pe...\pending_claim_CLM-898936_20260310.csv`, alongside a `billing-baseline.vbs` script.

<img width="1010" height="533" alt="Q09-Out-of-Role" src="https://github.com/user-attachments/assets/9cf0baad-174f-4d60-83d7-bf95e704301a" />


**Why it matters:** This confirms the account moved beyond its documented scope of work. Combined with the presence of a `.vbs` script alongside routine shortcuts, this is the point where "accessing files" starts to look like "staging for collection" rather than normal billing work.

**MITRE:** T1005 (Data from Local System)

---

### Phase 5 — Sensitive File Access

**Finding:** The account accessed and modified sensitive billing, audit, payroll, and HR records:

| File | Significance |
|---|---|
| `approved_pending_invoice_INV-664215_20260310.txt` | Invoice accessed outside the `Pending` scope |
| `review_audit_20260311.txt` | Audit trail modified |
| `payroll_exception_reference_20260311.txt.txt` | Payroll data staged under a disguised, double-extension filename |
| `quarterly_awards_shortlist_20260310.txt` | Additional HR file collected |
| `payroll_review_dpatel_20260311.txt` | Payroll review record collected |

**Why it matters:** The double file extension on the payroll file (`.txt.txt`) strongly suggests manual renaming to disguise the file as routine billing text rather than payroll data — a small but telling sign of deliberate, human-driven staging rather than an automated or careless action.

**MITRE:** T1074 (Data Staged)

---

### Phase 6 — Collection Scope

**Finding:** The attacker's collection spanned billing data, approved invoices, audit records, payroll information, and HR personnel records — not a single-department smash-and-grab, but abuse of `j.morris`'s legitimate permissions across multiple sensitive data domains.

**Why it matters:** Cross-department collection through one compromised identity shows the blast radius of a single valid-account compromise in an environment without tighter least-privilege boundaries between billing and HR data.

**MITRE:** T1005 (Data from Local System)

---

### Investigated and Ruled In for Follow-Up — Q04: Signal or Noise

**What to Hunt:** Process execution by `j.morris` across the `nh-*` host fleet involving `cmd.exe` or `powershell.exe`, to separate meaningful attacker action from background noise.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-19))
| where DeviceName startswith "nh-"
| where InitiatingProcessAccountName == "j.morris"
| where FileName in~ ("cmd.exe","powershell.exe")
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName
| order by TimeGenerated asc
```

**Result:** Repeated `cmd.exe /c del /q "C:\User..."` and `cmd.exe /c rmdir /s /q "C:\..."` executions on `nh-wks-bill-01`, starting 3/10/2026 9:55:52 AM UTC.

<img width="996" height="472" alt="Q04-Signal-or-Noise" src="https://github.com/user-attachments/assets/0313fe3e-5042-4911-9ec3-8f9262f078a1" />


**Why it matters:** This is flagged here rather than folded into the narrative above because the conclusion on it isn't settled yet — it could be routine cleanup (a scheduled script, temp-file housekeeping) or it could be the attacker clearing traces of staged files. Given the query title ("Signal or Noise"), this was the specific question under investigation; worth confirming which files were being deleted and whether the timing lines up with the staging activity in Phase 4–5 before calling it either way.

**MITRE (tentative, pending conclusion):** if confirmed as deliberate cleanup — T1070 (Indicator Removal); if ruled routine, no additional mapping needed.

---

## MITRE ATT&CK Summary

| Technique | Description |
|---|---|
| T1078 | Valid Accounts |
| T1021.001 | Remote Desktop Protocol |
| T1018 | Remote System Discovery |
| T1016 | Network Discovery |
| T1069 | Permission Groups Discovery |
| T1135 | Network Share Discovery |
| T1005 | Data from Local System |
| T1074 | Data Staged |
| T1070 * | Indicator Removal *(pending — see Q04 above)* |

---

## Key Findings

**External remote access.** The compromised account was driven end-to-end from an external IP over RDP.

**Living-off-the-land activity.** No custom tools or malware were observed at any stage — every action used native Windows binaries (`whoami`, `net`, `arp`, `cmd.exe`).

**Cross-department data collection.** The billing account reached into HR and audit data well outside its normal scope.

**Data staging.** Payroll information was renamed with a disguised double extension before collection — a deliberate, manual step.

**Red herring identified.** A second host (`NH-WKS-IT-01`) was touched but never operationally used; distinguishing this from genuine lateral movement kept the incident scope accurate.

---

## Detection Gaps & Recommendations

### Gaps Identified
- No alerting on successful RDP sessions originating from external IP addresses.
- Reconnaissance commands (`whoami`, `net view`, `arp -a`, `net share`) run in quick succession were not flagged.
- Access to HR and Billing shares by an account outside its expected role went undetected.
- Suspicious double file extensions (`.txt.txt`) were not caught as a staging/masquerading indicator.
- File deletion/cleanup activity (Q04) had no clear baseline to confirm it as routine vs. suspicious.

### Recommendations
- Alert on successful RDP logons from external or unexpected IP ranges, correlated against the account's normal access pattern.
- Build a Sentinel analytic for reconnaissance command clustering (multiple discovery commands from one account within a short window).
- Apply least-privilege share boundaries between Billing and HR data, and alert when an account crosses those boundaries.
- Detect double or mismatched file extensions as a masquerading indicator.
- Correlate RDP session activity with subsequent file access to identify hands-on-keyboard behavior versus automated processes.
- Establish a baseline for expected file deletion/cleanup activity per host so anomalous deletions are easier to distinguish from routine housekeeping.

---

## Lessons Learned

- A valid, compromised account can be more dangerous than malware — it blends into normal traffic entirely.
- Threat hunting requires correlating authentication, process execution, and file activity; no single data source tells the full story.
- The absence of malware is itself a data point, not a dead end — it points toward living-off-the-land technique rather than ruling out compromise.
- A successful logon alone doesn't prove attacker activity — process and file telemetry are what separate meaningful action from normal system initialization (as seen with the `NH-WKS-IT-01` red herring).
- Following the telemetry rather than the initial assumption turned a "routine posture review" into a confirmed external compromise.

---

## Final Assessment

This investigation disproved the initial insider-access theory and confirmed a valid-account compromise operated entirely through native Windows tooling. The attacker authenticated externally as `j.morris`, oriented themselves with standard reconnaissance commands, touched a second host without operationally using it, then moved beyond their expected role to collect billing, audit, payroll, and HR data — staging at least one file under a disguised filename before collection. No malware was deployed at any point, underscoring that detection here depends on behavioral and cross-telemetry correlation rather than signature-based tools. Immediate priorities: reset `j.morris`'s credentials, review the external IP against threat intel, audit exactly what was exfiltrated versus staged, and close the gap that allowed a billing account unrestricted reach into HR data.

---

## Analyst Notes

- Completed as part of a live-scored cyber range exercise ("Just Another Day: Compromised Account Investigation").
- The Q04 ("Signal or Noise") finding is included as an open thread rather than a settled conclusion — flagged above for follow-up rather than assumed either way.
- Evidence reproducible via Microsoft Defender XDR Advanced Hunting.
- Every phase mapped to at least one MITRE ATT&CK technique.
