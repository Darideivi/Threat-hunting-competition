# Threat Hunt Report: Port of Entry

<p align="center">
  <img width="518" height="777" alt="image" src="https://github.com/user-attachments/assets/09b44f4a-1670-4804-8009-5287751e7e8d" />
</p>

<p align="center">
  <em>Reconstructing a full intrusion chain — from RDP foothold to data exfiltration — using Microsoft Defender for Endpoint</em>
</p>

---

## Incident Brief

| | |
|---|---|
| **Company** | Azuki Import/Export Trading Co. (梓貿易株式会社) — 23 employees, shipping logistics, Japan/SE Asia |
| **Trigger** | A competitor undercut a 6-year shipping contract by exactly 3%. Supplier contracts and pricing data later surfaced on underground forums. |
| **Evidence Source** | Microsoft Defender for Endpoint logs (Azure) |
| **Host Investigated** | `azuki-sl` |
| **Incident Window** | November 18–21, 2025 (primary activity Nov 20, ~01:37–02:11 AM) |
| **Analyst** | Fredrick Wilson |
| **Date Completed** | 11/25/2025 |



---

## Scenario Overview

A 6-year shipping contract was underbid by a competitor at a suspiciously precise margin, and the pricing data behind that contract turned up for sale on underground forums. That pointed to a targeted data theft rather than a generic malware infection — the hunt was framed around finding how an attacker got in, what they took, and where they tried to go next.

**Starting query:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
```

---

## Chronological Timeline

| Time (approx.) | Flag | Stage | Action Observed |
|---|---|---|---|
| 11/18–11/21 | 1 | Initial Access | RDP connection from external IP `88.97.178.12` |
| 11/18–11/21 | 2 | Initial Access | Successful logon using compromised account `kenji.sato` |
| 11/19–11/21 | 3 | Discovery | `arp -a` executed to enumerate the local network |
| 11/20 01:37 AM | 18 | Execution | PowerShell script `wupdate.ps1` executed to kick off the attack chain |
| 11/20 01:37 AM | 10 | Command & Control | Outbound beacon from `svchost.exe` to C2 IP `78.141.196.6` on port 443 |
| 11/19–11/21 | 11 | Command & Control | C2 traffic persists over port 443 |
| 11/20 ~02:05 AM | 4 | Defense Evasion | Hidden staging directory `C:\ProgramData\WindowsCache` created |
| 11/19–11/21 | 5 | Defense Evasion | 3 file extensions added to Defender exclusions |
| 11/19–11/21 | 6 | Defense Evasion | Defender exclusion added for the Temp folder |
| 11/20 02:06 AM | 7 | Defense Evasion | `certutil.exe` used to download the malicious payload |
| 11/20 02:07 AM | 12 | Credential Access | Renamed Mimikatz (`mm.exe`) downloaded and staged |
| 11/20 02:07 AM | 8 | Persistence | Scheduled task `Windows Update Check` created |
| 11/20 02:07 AM | 9 | Persistence | Task configured to run `C:\ProgramData\WindowsCache\svchost.exe` |
| 11/20 02:08 AM | 13 | Credential Access | `mm.exe` executed with `privilege::debug sekurlsa::logonpasswords exit` |
| 11/20 ~02:08 AM | 14 | Collection | `export-data.zip` and other archives staged |
| 11/20 02:09 AM | 15 | Exfiltration | `curl.exe` uploads `export-data.zip` to Discord over HTTPS |
| 11/20 02:10 AM | 19 | Lateral Movement | RDP attempted to internal host `10.1.0.188` |
| 11/20 02:10 AM | 20 | Lateral Movement | `mstsc.exe` launched to reach `10.1.0.188` |
| 11/20 02:11 AM | 16 | Anti-Forensics | `wevtutil.exe` clears the Security log |
| Post-activity | 17 | Impact / Persistence | Hidden local admin account `support` created |

---

## MITRE ATT&CK Mapping

| Flag | Tactic | Technique | ID |
|---|---|---|---|
| 1 | Initial Access | External Remote Services | T1133 |
| 2 | Initial Access | Valid Accounts | T1078 |
| 3 | Discovery | Remote System Discovery | T1018 |
| 4 | Defense Evasion | Hide Artifacts | T1564 |
| 5, 6 | Defense Evasion | Impair Defenses: Disable/Modify Tools | T1562.001 |
| 7 | Defense Evasion / C2 | Ingress Tool Transfer | T1105 |
| 8, 9 | Persistence | Scheduled Task | T1053.005 |
| 10 | Command & Control | Application Layer Protocol | T1071 |
| 11 | Command & Control | Non-Standard Port / HTTPS blending | T1571 |
| 12 | Credential Access | OS Credential Dumping | T1003 |
| 13 | Credential Access | LSASS Memory | T1003.001 |
| 14 | Collection | Archive Collected Data | T1560 |
| 15 | Exfiltration | Exfiltration Over Web Service | T1567 |
| 16 | Defense Evasion | Clear Windows Event Logs | T1070.001 |
| 17 | Persistence / Impact | Account Manipulation | T1098 |
| 18 | Execution | PowerShell | T1059.001 |
| 19, 20 | Lateral Movement | Remote Services / RDP | T1021, T1021.001 |

---

## Attack Chain

```text
External IP (88.97.178.12)
        │  RDP logon as kenji.sato
        ▼
Network Recon (arp -a)
        │
        ▼
wupdate.ps1 executed ──► C2 beacon to 78.141.196.6:443
        │
        ▼
Hidden staging dir: C:\ProgramData\WindowsCache
        │
        ▼
Defender exclusions added (3 extensions + Temp folder)
        │
        ▼
certutil.exe downloads payload
        │
        ▼
mm.exe (renamed Mimikatz) staged ──► scheduled task "Windows Update Check"
        │                                   │
        ▼                                   ▼
LSASS dump (sekurlsa::logonpasswords)   runs svchost.exe from staging dir
        │
        ▼
export-data.zip staged
        │
        ▼
Exfil via curl.exe → Discord (HTTPS)
        │
        ▼
Security log cleared (wevtutil)
        │
        ▼
Hidden admin account "support" created
        │
        ▼
RDP/mstsc.exe → 10.1.0.188 (lateral movement attempt)
```

---

## Flag Analysis

### Flag 1 — Initial Access: Remote Access Source
**Tactic/Technique:** Initial Access — External Remote Services (T1133)

**Findings:** `88.97.178.12` is the source IP of the RDP connection into `azuki-sl`.

**Why it matters:** This is the attacker's entry point. Pinpointing it lets defenders block the IP at the firewall, check threat intel for known-bad attribution, and correlate against other incidents — the external source is the fastest lead toward "who's behind this."

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
| where RemoteIP contains "."
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, AccountName, RemoteIP, RemoteIPType, RemoteDeviceName
| order by Timestamp asc
```
<img width="1739" alt="Flag 1 evidence" src="https://github.com/user-attachments/assets/0a155b6a-d56c-477c-9cf5-6f8f08e15e52" />

**Detection recommendation:** Alert on interactive logons from external/unexpected geolocations, and disable direct internet-facing RDP where possible.

---

### Flag 2 — Initial Access: Compromised User Account
**Tactic/Technique:** Initial Access — Valid Accounts (T1078)

**Findings:** The account `kenji.sato` authenticated successfully during the RDP session identified in Flag 1.

**Why it matters:** This is the compromised credential itself — the attacker's foothold. It should be disabled/reset immediately, and the compromise vector (phishing, credential reuse, etc.) needs investigating before trust is restored.

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
| where RemoteIP contains "."
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, AccountName, RemoteIP, RemoteIPType, RemoteDeviceName
| order by Timestamp asc
```
<img width="1739" alt="Flag 2 evidence" src="https://github.com/user-attachments/assets/346167c5-d6b6-4374-a139-d1db62b494b6" />

**Detection recommendation:** Flag first-time successful RDP logons paired with an external source IP as high-priority for review.

---

### Flag 3 — Discovery: Network Reconnaissance
**Tactic/Technique:** Discovery — Remote System Discovery (T1018)

**Findings:** `ARP.EXE -a` was run to enumerate devices on the local network segment.

**Why it matters:** This is the attacker mapping out lateral movement targets. Catching recon commands this early gives defenders a head start on which internal systems to watch more closely.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1709" alt="Flag 3 evidence" src="https://github.com/user-attachments/assets/2321e140-cf3b-4c28-ae5a-91a90feb3a6c" />

**Detection recommendation:** Alert on `arp.exe`, `net.exe`, or similar enumeration tools launched shortly after a new interactive logon.

---

### Flag 4 — Defense Evasion: Malware Staging Directory
**Tactic/Technique:** Defense Evasion — Hide Artifacts (T1564)

**Findings:** A hidden directory, `C:\ProgramData\WindowsCache`, was created at 2:05:30 AM to stage tools and payloads.

**Why it matters:** Using a `ProgramData` path makes the folder look semi-legitimate to a casual review. Flagging non-standard directory creation under system paths surfaces staging locations before the payloads inside them execute.

```kql
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName contains "powershell"
```
<img width="1679" alt="Flag 4 evidence" src="https://github.com/user-attachments/assets/1dd10cdd-be4d-4e5c-af6d-463cdd687371" />

**Detection recommendation:** Alert on new directory creation under `ProgramData` or similar system paths by non-standard parent processes (e.g., PowerShell).

---

### Flag 5 — Defense Evasion: File Extension Exclusions
**Tactic/Technique:** Defense Evasion — Impair Defenses: Disable or Modify Tools (T1562.001)

**Findings:** 3 file extensions were added to the Windows Defender `Exclusions\Extensions` registry key during the attack window.

**Why it matters:** Excluding specific extensions gives downloaded malware of that type a guaranteed pass through AV scanning — a direct weakening of endpoint protection that should trigger an alert the moment it happens.

```kql
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessParentFileName contains "sense"
```
<img width="1668" alt="Flag 5 evidence 1" src="https://github.com/user-attachments/assets/e4227628-f81c-4c71-8509-d8867114398e" />
<img width="1678" alt="Flag 5 evidence 2" src="https://github.com/user-attachments/assets/d86c2602-327d-4996-a572-65bb1b582930" />

**Detection recommendation:** Alert on any write to Defender's exclusion registry keys (`Exclusions\Extensions`, `Exclusions\Paths`), regardless of initiating process.

---

### Flag 6 — Defense Evasion: Temporary Folder Exclusion
**Tactic/Technique:** Defense Evasion — Impair Defenses (T1562.001)

**Findings:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp` was added to Defender's `Exclusions\Paths`.

**Why it matters:** Excluding Temp lets short-lived payloads execute there without ever being scanned — a common tactic for staged, single-use tools.

```kql
DeviceRegistryEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
```
<img width="1677" alt="Flag 6 evidence" src="https://github.com/user-attachments/assets/d19ed60a-9ddb-45e7-84b9-1641deef37f7" />

**Detection recommendation:** Treat Temp-folder or user-writable-path exclusions as high severity — legitimate business need for this is rare.

---

### Flag 7 — Defense Evasion: Download Utility Abuse
**Tactic/Technique:** Defense Evasion / C2 — Ingress Tool Transfer (T1105)

**Findings:** `certutil.exe` was used at 2:06:58 AM to download the malicious payload.

**Why it matters:** Certutil is a signed, native Windows tool — using it to pull files avoids the scrutiny a third-party downloader would draw. This is a textbook living-off-the-land technique.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "//"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="555" alt="Flag 7 evidence" src="https://github.com/user-attachments/assets/e2690950-e773-44b1-b292-40d35f1b3920" />

**Detection recommendation:** Alert on `certutil.exe` invoked with `-urlcache` or `-decode` — these flags are almost never used legitimately outside cert management workflows.

---

### Flag 8 — Persistence: Scheduled Task Name
**Tactic/Technique:** Persistence — Scheduled Task (T1053.005)

**Findings:** A scheduled task named `Windows Update Check` was created at 2:07:46 AM.

**Why it matters:** Naming the task to mimic legitimate Windows maintenance helps it survive casual review by an admin scanning the Task Scheduler list.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "schtasks"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="545" alt="Flag 8 evidence" src="https://github.com/user-attachments/assets/6d53958a-2f9e-4841-bb1d-8ee5676b99c7" />

**Detection recommendation:** Baseline expected scheduled task names per fleet image; alert on new tasks with generic "Windows"-branded names created outside patch windows.

---

### Flag 9 — Persistence: Scheduled Task Target
**Tactic/Technique:** Persistence — Scheduled Task (T1053.005)

**Findings:** The task's `/tr` action points to `C:\ProgramData\WindowsCache\svchost.exe` — a copy of `svchost.exe` living outside its legitimate `System32` path.

**Why it matters:** This confirms the exact persistence payload and its location, enabling precise cleanup and giving defenders a specific anomalous-binary signature to hunt for elsewhere in the environment.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "schtasks"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="839" alt="Flag 9 evidence" src="https://github.com/user-attachments/assets/b8e1a986-c3c3-4d61-b6e4-f59b5ab802b3" />

**Detection recommendation:** Alert on any process named `svchost.exe` running from a path other than `C:\Windows\System32`.

---

### Flag 10 — Command & Control: C2 Server Address
**Tactic/Technique:** Command & Control — Application Layer Protocol (T1071)

**Findings:** The malicious process beaconed out to `78.141.196.6` on port 443 at 1:37:26 AM.

**Why it matters:** This IP is the attacker's infrastructure. Blocking it at the network edge cuts off further instructions and any additional payload delivery — a high-priority containment action.

```kql
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
```
<img width="1703" alt="Flag 10 evidence" src="https://github.com/user-attachments/assets/5cd5847a-c4fb-4805-978c-697945ae0897" />

**Detection recommendation:** Cross-reference outbound IPs against threat intel feeds automatically; alert on connections from newly-created or renamed processes to previously unseen external IPs.

---

### Flag 11 — Command & Control: Communication Port
**Tactic/Technique:** Command & Control — Non-Standard Port / Protocol Blending (T1571)

**Findings:** All observed C2 traffic used port 443, blending with normal HTTPS.

**Why it matters:** Port-based firewall rules alone won't catch this — the traffic looks identical to routine web browsing at the port level, which pushes detection toward TLS inspection and behavioral analysis instead.

```kql
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
```
<img width="1672" alt="Flag 11 evidence" src="https://github.com/user-attachments/assets/b0ef8b80-d0df-406c-ab5b-0bc61d8560a8" />

**Detection recommendation:** Deploy TLS inspection or JA3/JA3S fingerprinting where feasible; flag beaconing patterns (regular interval connections) regardless of destination port.

---

### Flag 12 — Credential Access: Credential Theft Tool
**Tactic/Technique:** Credential Access — OS Credential Dumping (T1003)

**Findings:** A renamed Mimikatz binary, `mm.exe`, was downloaded and staged in `WindowsCache` at 2:07:22 AM.

**Why it matters:** Downloading a credential-dumping tool signals clear intent — the presence of this file is the moment to assume credential compromise is imminent and prepare for reactive rotation.

```kql
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FolderPath contains "cache"
```
<img width="1692" alt="Flag 12 evidence" src="https://github.com/user-attachments/assets/8a4cf6e5-233d-4a59-858a-76f01b04313c" />

**Detection recommendation:** Use hash- and behavior-based detection for known credential-dumping tools — renaming defeats filename-based rules but not hash or memory-access-pattern detection.

---

### Flag 13 — Credential Access: Memory Extraction Command
**Tactic/Technique:** Credential Access — LSASS Memory (T1003.001)

**Findings:** `mm.exe` was executed with `privilege::debug sekurlsa::logonpasswords exit` at 2:08:26 AM.

**Why it matters:** This confirms successful clear-text credential extraction from LSASS memory — not just an attempt. This finding alone justifies an enterprise-wide password reset and a push toward Credential Guard / LSA protection.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where FileName contains "mm.exe"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1713" alt="Flag 13 evidence" src="https://github.com/user-attachments/assets/36b8ab65-61e3-4963-956e-604ebc04d23f" />

**Detection recommendation:** Alert on any process accessing `lsass.exe` memory outside of trusted security tooling; enable Credential Guard where hardware supports it.

---

### Flag 14 — Collection: Data Staging Archive
**Tactic/Technique:** Collection — Archive Collected Data (T1560)

**Findings:** `export-data.zip` and related archives (e.g., `VMAgentLogs.zip`) were created in the staging directory.

**Why it matters:** The archive is the direct evidence of what was taken. Naming and contents here define the scope of the breach for legal/regulatory notification and customer-impact assessment.

```kql
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FileName contains ".zip"
```
<img width="1096" alt="Flag 14 evidence" src="https://github.com/user-attachments/assets/79729a8a-c67f-4b52-89b3-68067296c30b" />

**Detection recommendation:** Alert on archive creation in non-standard system directories, especially shortly after credential-dumping tool execution.

---

### Flag 15 — Exfiltration: Channel
**Tactic/Technique:** Exfiltration — Exfiltration Over Web Service (T1567)

**Findings:** `curl.exe` uploaded `export-data.zip` to Discord over HTTPS at 2:09:21 AM.

**Why it matters:** Discord is a trusted, commonly-allowed consumer service — abusing it for exfiltration bypasses most egress filtering built around known-bad or unusual destinations, and highlights the case for DLP on approved SaaS tools too.

```kql
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
```
<img width="624" alt="Flag 15 evidence" src="https://github.com/user-attachments/assets/f56ec8bb-3736-4c01-aa1d-553952a05961" />

**Detection recommendation:** Flag large outbound POST/upload traffic to consumer collaboration platforms (Discord, Telegram, etc.) originating from server or non-user-facing hosts.

---

### Flag 16 — Anti-Forensics: Log Tampering
**Tactic/Technique:** Defense Evasion — Clear Windows Event Logs (T1070.001)

**Findings:** `wevtutil.exe` cleared the Security log at 2:11:39 AM.

**Why it matters:** Clearing Security first removes the authentication and privilege-use trail — a deliberate, sequenced anti-forensics move that argues strongly for centralized, real-time log forwarding so local clearing can't erase the evidence.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "wev"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1641" alt="Flag 16 evidence 1" src="https://github.com/user-attachments/assets/ed10b702-1075-4e29-8990-331d3b900ba8" />
<img width="1677" alt="Flag 16 evidence 2" src="https://github.com/user-attachments/assets/182dccd6-c8af-47c5-b89a-318df8f1c4a4" />

**Detection recommendation:** Alert immediately on any `wevtutil cl` (clear-log) execution — there's almost no legitimate reason for this outside controlled maintenance.

---

### Flag 17 — Persistence / Impact: Backdoor Account
**Tactic/Technique:** Persistence — Account Manipulation (T1098)

**Findings:** A hidden local administrator account named `support` was created and added to the Administrators group.

**Why it matters:** This is the attacker's fallback access — durable even after `kenji.sato`'s credentials are reset. Removing it and auditing all local admin group membership is a required containment step.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "add"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1678" alt="Flag 17 evidence" src="https://github.com/user-attachments/assets/656c2f22-51e3-44be-90d7-dee068d70c56" />

**Detection recommendation:** Alert on any local account creation followed immediately by addition to the Administrators group.

---

### Flag 18 — Execution: Malicious Script
**Tactic/Technique:** Execution — PowerShell (T1059.001)

**Findings:** `wupdate.ps1` executed at 1:37:40 AM, kicking off the observed attack chain.

**Why it matters:** This script is effectively the attacker's playbook in automated form — recovering and analyzing it (where possible) reveals the full intended sequence and supports building detection signatures for reuse elsewhere.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "add"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1678" alt="Flag 18 evidence" src="https://github.com/user-attachments/assets/656c2f22-51e3-44be-90d7-dee068d70c56" />

**Detection recommendation:** Alert on PowerShell scripts executed from Temp or user-profile directories immediately following a new remote logon.

---

### Flag 19 — Lateral Movement: Secondary Target
**Tactic/Technique:** Lateral Movement — Remote Services (T1021)

**Findings:** An RDP connection was attempted toward internal IP `10.1.0.188` at 2:10:41 AM.

**Why it matters:** This is the attacker's next objective — likely a system with elevated privileges or more sensitive data. Identifying the intended target early lets defenders prioritize isolating that specific host.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "mstsc"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1670" alt="Flag 19 evidence" src="https://github.com/user-attachments/assets/4381ab9d-2771-4b70-9a8f-e29989b3e882" />

**Detection recommendation:** Alert on outbound RDP attempts from a host that was itself an inbound RDP ingress point — a strong signal of a pivot in progress.

---

### Flag 20 — Lateral Movement: Remote Access Tool
**Tactic/Technique:** Lateral Movement — Remote Desktop Protocol (T1021.001)

**Findings:** `mstsc.exe` was launched with `10.1.0.188` as the target, at 2:10:41 AM.

**Why it matters:** Using the native RDP client makes the pivot attempt look like ordinary IT administration — this blending is exactly why internal RDP needs tighter logging and network segmentation, not just perimeter controls.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "mstsc"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1699" alt="Flag 20 evidence" src="https://github.com/user-attachments/assets/d0d87a69-2271-4ccb-b649-47e96ebb6bdb" />

**Detection recommendation:** Restrict internal RDP with network segmentation; alert on `mstsc.exe` launched from a host that received an external RDP session within the same session window.

---

## Intrusion Narrative

A condensed walk through how each finding connects to the next:

1. **External RDP access** from `88.97.178.12` established the initial foothold.
2. That session authenticated as **`kenji.sato`** — a valid, compromised account.
3. The attacker ran **`arp -a`** to map the local network.
4. **`wupdate.ps1`** executed, automating the rest of the chain, and immediately triggered a **C2 beacon** to `78.141.196.6:443`.
5. A **hidden staging directory** (`WindowsCache`) was created, and **Defender exclusions** (3 extensions + Temp folder) were added to blind AV to what came next.
6. **`certutil.exe`** pulled down the payload; a renamed **Mimikatz (`mm.exe`)** was staged alongside it.
7. A **scheduled task** ("Windows Update Check") was created to relaunch `svchost.exe` from the staging directory on every reboot — persistence secured.
8. Mimikatz ran with **`sekurlsa::logonpasswords`**, dumping credentials from LSASS memory.
9. Stolen data was **archived** (`export-data.zip`) and **exfiltrated to Discord** via `curl.exe` over HTTPS.
10. The **Security log was cleared** to erase the authentication trail, and a **hidden admin account ("support")** was planted for future access.
11. Finally, the attacker attempted to **pivot via RDP** to a second internal host (`10.1.0.188`) using the native `mstsc.exe` client.

---

## Detection Gaps & Recommendations

### Gaps identified
- RDP was reachable and authenticated with a single compromised account — no MFA or conditional access appears to have stopped it.
- Defender exclusion changes went unnoticed in real time, giving the attacker's tools a clean run.
- LOLBins (`certutil.exe`, `wevtutil.exe`, `mstsc.exe`) were used throughout specifically because they blend with normal admin activity.
- Local log clearing removed evidence before it could be reviewed.
- No alert appears to have fired on new local admin account creation.

### Recommendations
- Require MFA on all RDP/remote access, and move RDP behind a bastion host or VPN rather than exposing it directly.
- Alert in real time on any modification to Defender's exclusion registry keys.
- Build detections for LOLBin abuse patterns: `certutil -urlcache`, `wevtutil cl`, unexpected `mstsc.exe` chains.
- Forward all event logs to a centralized, write-protected SIEM so local clearing can't destroy evidence.
- Alert on local account creation followed by Administrators group membership.
- Add DLP or anomaly detection for large uploads to consumer platforms (Discord, Telegram, etc.) from non-user hosts.

---

## Final Assessment

The investigation traced a complete intrusion on `azuki-sl` — from an externally-sourced RDP logon using a valid but compromised account, through network reconnaissance, Defender evasion, LOLBin-based payload delivery, scheduled-task persistence, LSASS credential dumping, data staging, and exfiltration via Discord — followed by anti-forensic log clearing, a planted backdoor account, and an attempted pivot to a second internal host. The timeline and MITRE ATT&CK mapping give Azuki's team a clear containment and remediation sequence: rotate `kenji.sato`'s credentials, remove the `support` account, block the identified C2 IP, and close the RDP exposure that started the chain.

---

## Analyst Notes

- One of my first end-to-end threat hunts.
- All findings reproducible via Defender Advanced Hunting on `azuki-sl`.
- Every flag ties directly to a MITRE ATT&CK technique for structured storytelling in a portfolio review.
