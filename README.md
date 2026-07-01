# Threat Hunting Investigation: Full Attack Chain Reconstruction

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1000"
    alt="Threat Hunt Cover Image"
  />
</p>

<p align="center">
  <em>End-to-end reconstruction of a simulated intrusion using Microsoft Defender for Endpoint and Microsoft Sentinel</em>
</p>

---

## Executive Summary

This investigation reconstructs a complete attacker kill chain using Microsoft Defender for Endpoint (MDE) and Microsoft Sentinel. Twenty forensic artifacts were identified across the full attack lifecycle — from initial access via Remote Desktop Protocol (RDP) through credential dumping, persistence, command-and-control, data exfiltration, and lateral movement. Each stage was investigated with KQL queries and mapped to the MITRE ATT&CK framework to demonstrate how endpoint telemetry can be used to reconstruct a real-world intrusion.

**Key outcome:** the attacker moved from a single exposed RDP endpoint to full domain-adjacent compromise in under [X hours], evading initial detection via Defender exclusion tampering before being identified through [detection method].

---

## Hunt Objectives

- Investigate a complete simulated cyberattack using Microsoft Defender for Endpoint
- Build KQL queries to surface attacker activity across multiple telemetry tables
- Correlate evidence across endpoint logs to reconstruct a single coherent timeline
- Map attacker behavior to the MITRE ATT&CK framework
- Document findings and provide actionable defensive recommendations

---

## Environment & Scope

| | |
|---|---|
| **Platform** | Microsoft Defender for Endpoint (MDE) |
| **SIEM** | Microsoft Sentinel |
| **Query Engine** | Azure Log Analytics Workspace (KQL) |
| **Target** | Windows Endpoint |
| **Frameworks** | MITRE ATT&CK, NIST 800-61 Incident Response Lifecycle |

**Data sources used:**
`DeviceLogonEvents` · `DeviceProcessEvents` · `DeviceFileEvents` · `DeviceNetworkEvents` · `DeviceRegistryEvents`

**Skills demonstrated:** Threat Hunting · Incident Response · KQL · MITRE ATT&CK Mapping · Detection Engineering · Digital Forensics · Log Analysis

---

## Attack Chain Overview

```text
Internet
   │
   ▼
RDP Login ─────────────────► Initial Access
   │
   ▼
Network Discovery ─────────► Recon
   │
   ▼
Defender Exclusion Added ──► Defense Evasion
   │
   ▼
Malware Download (certutil) ► Execution
   │
   ▼
Scheduled Task ─────────────► Persistence
   │
   ▼
C2 Beacon ──────────────────► Command & Control
   │
   ▼
Mimikatz (LSASS Dump) ──────► Credential Access
   │
   ▼
Archive Sensitive Files ────► Collection
   │
   ▼
Discord Exfiltration ───────► Exfiltration
   │
   ▼
Clear Event Logs ───────────► Defense Evasion
   │
   ▼
Backdoor Local Account ─────► Persistence
   │
   ▼
RDP to Second Host ─────────► Lateral Movement
```

---

## MITRE ATT&CK Mapping

| # | Stage | Tactic | Technique | ID |
|---|-------|--------|-----------|-----|
| 1 | Initial Access | Initial Access | Remote Services (RDP) | T1021.001 |
| 2 | Network Discovery | Discovery | System Network Config Discovery | T1016 |
| 3 | Defender Exclusion | Defense Evasion | Modify Security Tools | T1562.001 |
| 4 | Malware Staging | Execution | PowerShell | T1059.001 |
| 5 | Malware Download | Command & Control | Ingress Tool Transfer | T1105 |
| 6 | Scheduled Task | Persistence | Scheduled Task/Job | T1053.005 |
| 7 | Credential Dumping | Credential Access | LSASS Memory | T1003.001 |
| 8 | Data Collection | Collection | Archive via Utility | T1560.001 |
| 9 | Exfiltration | Exfiltration | Exfiltration Over Web Service | T1567 |
| 10 | Log Clearing | Defense Evasion | Clear Windows Event Logs | T1070.001 |
| 11 | Backdoor Account | Persistence | Local Account | T1136.001 |
| 12 | Lateral Movement | Lateral Movement | Remote Desktop Protocol | T1021.001 |

---

## Table of Contents

- [Flag 1 — Initial Access via RDP](#flag-1--initial-access-via-rdp)
- [Flag 2 — Network Discovery](#flag-2)
- [Flag 3 — Defender Exclusion Added](#flag-3)
- [Flag 4 — Malware Staging Directory](#flag-4)
- [Flag 5 — Malware Download via certutil](#flag-5)
- [Flag 6 — Scheduled Task Persistence](#flag-6)
- [Flag 7 — Command & Control Beacon](#flag-7)
- [Flag 8 — Mimikatz Execution](#flag-8)
- [Flag 9 — LSASS Credential Dumping](#flag-9)
- [Flag 10 — Data Collection & Staging](#flag-10)
- [Flag 11 — Archive Creation](#flag-11)
- [Flag 12 — Discord Exfiltration](#flag-12)
- [Flag 13 — [Name TBD]](#flag-13)
- [Flag 14 — [Name TBD]](#flag-14)
- [Flag 15 — [Name TBD]](#flag-15)
- [Flag 16 — Event Log Clearing](#flag-16)
- [Flag 17 — [Name TBD]](#flag-17)
- [Flag 18 — Backdoor Admin Account Created](#flag-18)
- [Flag 19 — [Name TBD]](#flag-19)
- [Flag 20 — Lateral Movement via RDP](#flag-20)
- [Detection Gaps & Recommendations](#detection-gaps--recommendations)
- [Final Assessment](#final-assessment)

> Titles above are placeholders based on the attack chain order — rename once we fill in each flag's real technique.

---

## Flag Analysis

### Flag 1 — Initial Access via RDP

| | |
|---|---|
| **Tactic / Technique** | Initial Access — Remote Services (T1021.001) |
| **Source IP** | `88.97.178.12` |
| **Compromised Account** | `kenji.sato` |
| **Data Source** | `DeviceLogonEvents` |

**Findings**
The attacker authenticated to the endpoint over RDP using the compromised account `kenji.sato`, originating from external IP `88.97.178.12`.

**Why it matters**
_[1-2 sentences: what this tells us about attacker access level / exposure]_

**KQL Query**
```kql
// Add the query used to surface this event
```

**Screenshot**
`![Flag 1 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[Actionable hunting tip — e.g. alert on RDP logons from external/unexpected geolocations]_

---

### Flag 2
**Tactic / Technique:** Discovery — System Network Configuration Discovery (T1016)

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Command / Artifact** | _[fill in]_ |

**Findings**
_[what happened]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 2 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 3
**Tactic / Technique:** Defense Evasion — Modify Security Tools (T1562.001)

| | |
|---|---|
| **Data Source** | `DeviceRegistryEvents` |
| **Artifact** | _[fill in — e.g. exclusion path added]_ |

**Findings**
_[what happened]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 3 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 4
**Tactic / Technique:** _[fill in]_

| | |
|---|---|
| **Data Source** | _[fill in]_ |
| **Artifact** | _[fill in]_ |

**Findings**
_[what happened]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 4 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 5
**Tactic / Technique:** Command & Control — Ingress Tool Transfer (T1105)

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Tool Used** | `certutil.exe` |

**Findings**
_[what was downloaded, from where]_

**Why it matters**
_[impact — LOLBin abuse bypassing file download controls]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 5 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip — alert on certutil.exe with -urlcache or -decode flags]_

---

### Flag 6
**Tactic / Technique:** Persistence — Scheduled Task (T1053.005)

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Task Name** | _[fill in]_ |

**Findings**
_[what task was created, what it runs]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 6 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 7
**Tactic / Technique:** Command & Control — Beacon Activity

| | |
|---|---|
| **Data Source** | `DeviceNetworkEvents` |
| **C2 Server** | _[IP / domain]_ |

**Findings**
_[beacon interval, protocol, destination]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 7 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 8
**Tactic / Technique:** Credential Access — Mimikatz Execution

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Process Name** | _[renamed Mimikatz binary name]_ |

**Findings**
_[what was run, from where, under what account]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 8 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip — hash-based detection resists renaming]_

---

### Flag 9
**Tactic / Technique:** Credential Access — LSASS Memory (T1003.001)

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Target Process** | `lsass.exe` |

**Findings**
_[dump method, output file if any]_

**Why it matters**
_[impact — credential theft enabling lateral movement]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 9 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 10
**Tactic / Technique:** Collection — Data Staging

| | |
|---|---|
| **Data Source** | `DeviceFileEvents` |
| **Staging Path** | _[fill in]_ |

**Findings**
_[what files were collected]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 10 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 11
**Tactic / Technique:** Collection — Archive via Utility (T1560.001)

| | |
|---|---|
| **Data Source** | `DeviceFileEvents` |
| **Archive Name** | `export-data.zip` |

**Findings**
_[compression tool used, archive contents]_

**Why it matters**
_[impact]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 11 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip]_

---

### Flag 12
**Tactic / Technique:** Exfiltration — Exfiltration Over Web Service (T1567)

| | |
|---|---|
| **Data Source** | `DeviceNetworkEvents` |
| **Destination** | Discord (webhook/CDN) |

**Findings**
_[upload method, size, destination URL pattern]_

**Why it matters**
_[impact — legitimate SaaS abused to bypass egress filtering]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 12 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip — flag large outbound transfers to consumer collaboration apps]_

---

### Flag 13
**Tactic / Technique:** _[fill in]_

**Findings** · **Why it matters** · **KQL Query** · **Screenshot** · **Detection Recommendation**
_[fill in]_

---

### Flag 14
**Tactic / Technique:** _[fill in]_

**Findings** · **Why it matters** · **KQL Query** · **Screenshot** · **Detection Recommendation**
_[fill in]_

---

### Flag 15
**Tactic / Technique:** _[fill in]_

**Findings** · **Why it matters** · **KQL Query** · **Screenshot** · **Detection Recommendation**
_[fill in]_

---

### Flag 16
**Tactic / Technique:** Defense Evasion — Clear Windows Event Logs (T1070.001)

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Command Used** | _[e.g. wevtutil cl]_ |

**Findings**
_[which logs were cleared]_

**Why it matters**
_[impact — anti-forensics, evidence gap]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 16 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip — forward logs to SIEM before local clearing can erase them]_

---

### Flag 17
**Tactic / Technique:** _[fill in]_

**Findings** · **Why it matters** · **KQL Query** · **Screenshot** · **Detection Recommendation**
_[fill in]_

---

### Flag 18
**Tactic / Technique:** Persistence — Local Account (T1136.001)

| | |
|---|---|
| **Data Source** | `DeviceProcessEvents` |
| **Account Created** | _[fill in]_ |

**Findings**
_[account name, admin group added to]_

**Why it matters**
_[impact — durable access surviving credential rotation]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 18 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip — alert on new local admin account creation]_

---

### Flag 19
**Tactic / Technique:** _[fill in]_

**Findings** · **Why it matters** · **KQL Query** · **Screenshot** · **Detection Recommendation**
_[fill in]_

---

### Flag 20
**Tactic / Technique:** Lateral Movement — Remote Desktop Protocol (T1021.001)

| | |
|---|---|
| **Data Source** | `DeviceLogonEvents` |
| **Target Host** | _[second internal system]_ |

**Findings**
_[account used, source-to-target hop]_

**Why it matters**
_[impact — pivot beyond patient zero]_

**KQL Query**
```kql

```

**Screenshot**
`![Flag 20 evidence](path/to/screenshot.png)`

**Detection Recommendation**
_[tip — alert on internal RDP from a host that itself was an RDP ingress point]_

---

## Detection Gaps & Recommendations

### Gaps Identified
- Public RDP exposure significantly increased the attack surface.
- Defender exclusions allowed malicious files to bypass antivirus scanning.
- Scheduled task creation was not flagged in near-real-time.
- Credential dumping occurred before automated containment triggered.
- Event log clearing reduced available forensic evidence for later stages.

### Recommendations
- Restrict RDP exposure using Azure NSGs or Azure Bastion; disable direct internet-facing RDP.
- Alert on any modification to Defender exclusion lists.
- Detect LOLBin abuse (`certutil.exe`, PowerShell, `rundll32.exe`, etc.) used for downloads.
- Monitor for LSASS access patterns consistent with credential dumping tools.
- Build Sentinel analytics rules for: scheduled task creation, local account creation, and Windows event log clearing.
- Forward logs to a central SIEM continuously so local log-clearing can't destroy evidence.

---

## Final Assessment

This investigation reconstructed the complete attack lifecycle using Microsoft Defender for Endpoint and Microsoft Sentinel — from initial RDP access through credential theft, persistence, data collection, exfiltration, and lateral movement, with defense evasion techniques layered throughout. Mapping each stage to MITRE ATT&CK provided a structured view of attacker behavior and surfaced concrete opportunities to strengthen detection engineering and defensive controls.

---

## Analyst Notes

- Report structured for interview and portfolio review.
- Evidence reproducible via Defender advanced hunting.
- Techniques mapped directly to MITRE ATT&CK.
