# AD Threat Detection Lab

*Simulating and detecting real-world attack techniques in a self-built Active Directory environment*

---

## Executive Summary

This lab is a self-hosted Security Operations Center (SOC) environment built to simulate an enterprise Active Directory network, ingest telemetry into a centralized SIEM, and validate detection coverage against real MITRE ATT&CK techniques. The environment includes a Windows Server 2022 Domain Controller populated with a realistic (BadBlood-generated) AD structure, a domain-joined Windows 10 endpoint, a pfSense gateway/firewall, and a Splunk Enterprise deployment for log aggregation and detection engineering.

Using Atomic Red Team, I simulated multiple MITRE ATT&CK techniques against the environment and built Splunk detection queries to identify each one from raw telemetry — covering the full chain from attack execution to log source to search query to investigative findings.

**Note for whoever is building this site (Claude Code):** This document is a content/structure brief, not final polished prose. Please build out an MkDocs project (`mkdocs.yml` + `docs/` folder) using this as the source content, organized into the page structure outlined below. Feel free to expand the prose, but keep all technical details (commands, queries, field names, findings) exactly as specified — these are accurate to what was actually run and observed in the lab.

---

## Suggested MkDocs Site Structure

```
docs/
  index.md                     <- Executive Summary + lab overview
  architecture.md              <- Section 1
  splunk-pipeline.md           <- Section 2
  techniques/
    kerberoasting.md           <- Section 3, technique 1
    credential-dumping.md      <- Section 3, technique 2
  findings.md                  <- Section 4
  next-steps.md                <- Section 5
```

Use Material for MkDocs theme if available, with a dark/terminal-style aesthetic to match the existing portfolio site (yaoamebe.web.app) and SANS Holiday Hack write-up site.

---

## Section 1: Architecture

### Environment Components

- **Windows Server 2022** — Active Directory Domain Controller
  - AD populated using **BadBlood** to simulate a realistic enterprise directory structure (users, groups, OUs, service accounts) rather than a bare default domain
- **Windows 10** — domain-joined endpoint, used as the primary target for atomic test execution
- **Sysmon** — installed on both DC and Win10, configured with a MITRE ATT&CK-mapped ruleset (rule names include `technique_id` and `technique_name` fields directly, e.g. `technique_id=T1055.001,technique_name=Dynamic-link Library Injection`)
- **Splunk Enterprise** — deployed on a dedicated Ubuntu Server VM, acting as the central log aggregator / SIEM
- **pfSense** — firewall/router with WAN and LAN interfaces; all Windows VMs route internet access through it; also provides DNS resolution for the LAN segment
- **CrowdSec** — installed on the DC (integration into the detection pipeline is a planned next step, not yet validated — see Next Steps)

### Design Rationale

- All lab hosts sit on an isolated LAN behind pfSense, allowing offensive tooling (Atomic Red Team) to be run safely without exposing the host network
- BadBlood was used specifically to avoid testing detections against a trivially empty/default AD — a populated directory with realistic groups and service accounts makes techniques like Kerberoasting meaningfully testable (real SPNs to target, real account noise to filter through)

### Diagram

*[Insert network topology diagram here: pfSense (WAN/LAN) → LAN switch → Windows Server 2022 DC, Windows 10, Ubuntu Splunk VM]*

---

## Section 2: Splunk Deployment & Log Pipeline

### Forwarder-Side Configuration

- Splunk Universal Forwarder installed via `.msi` on both the DC and Win10
- `outputs.conf` configured to point to the Splunk indexer's IP on port `9997`
- `inputs.conf` configured to monitor:
  - `WinEventLog://Security` → routed to `wineventlog` index
  - `WinEventLog://Microsoft-Windows-Sysmon/Operational` → routed to `sysmon` index

```ini
[WinEventLog://Security]
index = wineventlog
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
disabled = false
renderXml = true
```

### Windows Audit Policy Changes Required

By default, Windows does not log several event categories needed for credential-attack detection. The following were enabled via `auditpol` on the DC:

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

This enabled Event IDs:
- **4769** — Kerberos Service Ticket Operations (required for Kerberoasting detection)
- **4768** — Kerberos Authentication Service (TGT requests)
- **4688** — Process Creation

### Server-Side Configuration

- Splunk Enterprise installed on Ubuntu Server via `.deb` package
- Started and enabled for boot-start via:
  ```bash
  sudo /opt/splunk/bin/splunk start --accept-license
  sudo /opt/splunk/bin/splunk enable boot-start
  ```
- Receiving port `9997` enabled under `Settings > Forwarding and receiving > Configure receiving`
- Custom indexes created: `wineventlog`, `sysmon`
- **Splunk Add-on for Microsoft Windows (TA-windows)** installed — required for field-level extraction (`EventCode`, `Account_Name`, etc.). Without this add-on, raw Windows event data is indexed but not parsed into searchable fields.

### Lessons Learned (Setup)

- **Config filenames are exact-match** — a file named `input.conf` instead of `inputs.conf` is silently ignored by Splunk, with no error raised. This caused an extended period of "connection is active but no data arrives" before being caught by manually confirming the file's exact name.
- **Field extraction requires the Windows TA even when raw data is indexed.** Data being visible in raw text search (`index=* "4624"`) does not guarantee `EventCode=4624` will return results — TA-windows must be installed on the indexer for structured field search to work.
- **Windows does not log Kerberos ticket or process creation events by default**, even on a domain-joined system. Explicit Advanced Audit Policy configuration is required before techniques like Kerberoasting produce any usable telemetry at all.
- **DNS/DHCP dependencies matter for indexer stability.** The Ubuntu Splunk host initially had no upstream DNS server configured (pfSense DHCP was not advertising one), which didn't block Splunk itself but did block package/add-on installation until resolved via netplan configuration.

---

## Section 3: Attack Simulation & Detection

Each technique below follows the same structure: technique, simulation method, expected telemetry, detection query, and findings.

### Technique 1: Kerberoasting (T1558.003)

**Simulation:**
```powershell
Invoke-AtomicTest T1558.003
```

**Expected telemetry:** Security Event ID 4769 (Kerberos Service Ticket Operations), specifically service ticket requests using RC4 encryption (`0x17`) rather than modern AES (`0x11`/`0x12`) — RC4 usage for a service ticket is a well-known Kerberoasting fingerprint since legitimate modern tickets default to AES.

**Detection query:**
```spl
index=wineventlog EventCode=4769 host=<DC-hostname> earliest=-60m
| table _time, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type
| sort -_time
```

Refined to isolate suspicious activity specifically:
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 host=<DC-hostname> earliest=-24h
| stats count values(Service_Name) as targeted_SPNs by Account_Name, Client_Address
| where count > 3
```

**Findings:** Successfully detected 4769 events generated by the atomic test after enabling the required audit policy. [Insert specific screenshot/results of Account_Name, Service_Name, Ticket_Encryption_Type observed during your test run.]

---

### Technique 2: Credential Dumping (T1003)

**Simulation:**
```powershell
Invoke-AtomicTest T1003
```

**Expected telemetry:** Sysmon Event ID 10 (ProcessAccess) — a process requesting a memory-access handle to a credential-storing process, most commonly `lsass.exe`.

**Detection query:**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe*" host=<hostname> earliest=-30m
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace
```

**Findings — two distinct outcomes observed:**

1. **Successful chain (against `svchost.exe`):** The atomic test run produced a clear three-stage chain, Sysmon-tagged directly via `technique_id` fields in the rule name:
   - `powershell.exe` → injected into `rundll32.exe` (tagged `T1055.001`, DLL Injection), `GrantedAccess=0x1fffff`
   - `rundll32.exe` → accessed `svchost.exe` (tagged `T1003`, Credential Dumping), `GrantedAccess=0x1fffff`, running as `NT AUTHORITY\SYSTEM`
   - This matches the known **comsvcs.dll MiniDump technique** (`rundll32.exe` invoking `comsvcs.dll`'s MiniDump export against a target process) — a widely used LSASS-dumping method, demonstrated here against a substitute process.
   - Note: the atomic test targeted `svchost.exe` rather than `lsass.exe` directly — worth investigating/documenting whether this is an intentional test-safety substitution in the atomic test definition, or a configuration artifact.

2. **Blocked attempt (against `lsass.exe` directly):** A separate run explicitly targeting `lsass.exe` was intercepted by Windows Defender before completion ("access denied" errors returned to PowerShell). This demonstrates a second, equally valid detection layer:
   - Windows Defender's built-in LSASS protection blocked the access attempt outright
   - Sysmon still has the opportunity to log the attempted access (with a reduced/denied `GrantedAccess` value rather than full access) — confirms detection visibility exists even when prevention succeeds first
   - Recommended follow-up query for the Defender-side detection:
     ```spl
     index=* sourcetype="WinEventLog:Microsoft-Windows-Windows Defender/Operational" earliest=-15m
     ```
     Looking for Event ID 1116 (threat detected) or 5007 (configuration change).

**Takeaway for this technique:** the lab surfaced two layers of defense working together — prevention (Defender blocking direct LSASS access) and detection (Sysmon capturing the attempted access and, in the substitute-process run, capturing a fully successful simulated dumping technique). This is a realistic SOC scenario: many real intrusion attempts are stopped by endpoint protection before a SOC analyst needs to intervene, and demonstrating visibility into both outcomes is stronger than a single clean "attack succeeded, detection fired" narrative.

---

## Section 4: Findings & Lessons Learned (Lab-Wide)

- Default Windows logging is insufficient for meaningful detection engineering — nearly every technique required explicit audit policy changes before relevant telemetry existed at all.
- Field extraction (via Technology Add-ons) is a distinct requirement from log ingestion — data can be fully indexed and still be unsearchable by field name without the correct TA installed.
- Endpoint protection (Windows Defender) and SIEM-based detection are complementary, not redundant — the LSASS-direct test demonstrated prevention stopping an attack while Sysmon still retained visibility into the attempt.
- Building the pipeline end-to-end (audit policy → Sysmon/WinEventLog → Universal Forwarder → indexer → field-extracted search) surfaced multiple non-obvious configuration issues (exact config filenames, missing TAs, DNS/DHCP dependencies) that mirror real-world SIEM onboarding challenges.

---

## Section 5: Next Steps

- **T1070 (log/artifact clearing)** — validate Event ID 1102 detection for Windows Security log clearing
- **T1021.002 (SMB lateral movement)** — correlate DC ↔ Win10 authentication events with network-layer visibility once Suricata is enabled on pfSense
- **T1059.001 (encoded PowerShell execution)** — test Sysmon/PowerShell Operational log visibility into obfuscated command execution
- **CrowdSec integration** — validate that CrowdSec alerts/decisions are actually flowing into Splunk (not yet confirmed) before including it in the detection pipeline narrative
- **Suricata on pfSense** — enable network IDS layer to add network-based detection alongside existing endpoint/AD telemetry
