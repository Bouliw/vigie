# Vigie report

Generated on 2026-09-28 15:17:49Z by Vigie 0.1.0. Alerts are mapped to MITRE ATT&CK 19.2. All times are UTC.

## Summary

| | |
|---|---|
| Events analyzed | 368 |
| Time range | 2020-09-04 07:07:19Z to 2025-01-01 00:00:09Z |
| Files read | 33 |
| Rules loaded | 23 |
| Alerts shown | 35 (level low and above) |

| Severity | Alerts |
|---|---|
| critical | 0 |
| high | 12 |
| medium | 20 |
| low | 3 |

16 alert(s) below the "low" level are not shown (informational: 16). Run with `--min-level informational` to include them.

## MITRE ATT&CK

| Tactic | Alerts | Techniques |
|---|---|---|
| [Initial Access](https://attack.mitre.org/tactics/TA0001) (TA0001) | 3 | [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts |
| [Execution](https://attack.mitre.org/tactics/TA0002) (TA0002) | 9 | [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task/Job: Scheduled Task<br>[T1059.001](https://attack.mitre.org/techniques/T1059/001) Command and Scripting Interpreter: PowerShell<br>[T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs<br>[T1569.002](https://attack.mitre.org/techniques/T1569/002) System Services: Service Execution |
| [Persistence](https://attack.mitre.org/tactics/TA0003) (TA0003) | 11 | [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task/Job: Scheduled Task<br>[T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts<br>[T1136.001](https://attack.mitre.org/techniques/T1136/001) Create Account: Local Account<br>[T1136.002](https://attack.mitre.org/techniques/T1136/002) Create Account: Domain Account<br>[T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs<br>[T1543.003](https://attack.mitre.org/techniques/T1543/003) Create or Modify System Process: Windows Service |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) (TA0004) | 9 | [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task/Job: Scheduled Task<br>[T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts<br>[T1543.003](https://attack.mitre.org/techniques/T1543/003) Create or Modify System Process: Windows Service<br>[T1548.003](https://attack.mitre.org/techniques/T1548/003) Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| [Stealth](https://attack.mitre.org/tactics/TA0005) (TA0005) | 7 | [T1027.010](https://attack.mitre.org/techniques/T1027/010) Obfuscated Files or Information: Command Obfuscation<br>[T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts<br>[T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs |
| [Defense Impairment](https://attack.mitre.org/tactics/TA0112) (TA0112) | 3 | [T1685.005](https://attack.mitre.org/techniques/T1685/005) Disable or Modify Tools: Clear Windows Event Logs |
| [Credential Access](https://attack.mitre.org/tactics/TA0006) (TA0006) | 19 | [T1003.001](https://attack.mitre.org/techniques/T1003/001) OS Credential Dumping: LSASS Memory<br>[T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing<br>[T1110.003](https://attack.mitre.org/techniques/T1110/003) Brute Force: Password Spraying |
| [Command and Control](https://attack.mitre.org/tactics/TA0011) (TA0011) | 2 | [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer |

## Alerts

| Severity | Rule | Alerts | First seen | Last seen |
|---|---|---|---|---|
| high | LSASS Memory Access With Credential Dumping Rights | 4 | 2020-09-22 08:38:29Z | 2020-10-18 23:50:06Z |
| high | SSH Login After Brute Force | 3 | 2024-03-10 09:05:42Z | 2024-06-04 08:05:30Z |
| high | Security Event Log Cleared | 2 | 2020-10-18 02:17:00Z | 2020-10-21 11:28:08Z |
| high | Suspicious Service Installed | 2 | 2020-09-20 16:16:58Z | 2021-06-11 09:07:41Z |
| high | Important Windows Event Log Cleared | 1 | 2020-10-21 11:28:08Z | 2020-10-21 11:28:08Z |
| medium | SSH Brute Force | 9 | 2024-03-10 09:05:42Z | 2024-07-08 03:12:20Z |
| medium | File Download Via Bitsadmin | 2 | 2020-10-23 06:36:43Z | 2020-10-23 06:36:43Z |
| medium | PowerShell Encoded Command Execution | 2 | 2020-09-20 06:57:49Z | 2020-09-20 06:57:49Z |
| medium | SSH Password Spraying | 2 | 2024-03-10 09:05:42Z | 2024-06-03 14:39:50Z |
| medium | Suspicious Scheduled Task Created | 2 | 2020-09-21 07:15:47Z | 2020-12-19 07:00:22Z |
| medium | Local User Account Created | 1 | 2024-03-10 09:08:12Z | 2024-03-10 09:08:12Z |
| medium | PsExec-Like Service Installed | 1 | 2020-10-19 03:30:46Z | 2020-10-19 03:30:46Z |
| medium | Windows Logon Brute Force From Single Source | 1 | 2020-10-22 08:29:55Z | 2020-10-22 08:29:55Z |
| low | Sudo Authentication Failure | 2 | 2024-03-10 09:09:30Z | 2024-06-04 08:07:12Z |
| low | User Account Created | 1 | 2020-09-14 12:06:03Z | 2020-09-14 12:06:03Z |

### 1. Suspicious Service Installed (high)

- **When:** 2020-09-20 16:16:58Z
- **Hosts:** WORKSTATION6.theshire.local
- **ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003) Create or Modify System Process: Windows Service; [T1569.002](https://attack.mitre.org/techniques/T1569/002) System Services: Service Execution (Execution, Persistence, Privilege Escalation)
- **Rule:** Suspicious Service Installed, `6d03b054-8230-47ba-a957-6b59a2d71c33`
- **Author:** pH-T (Nextron Systems), Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Ecco, oscd.community, Natalia Shornikova (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects a new Windows service (System event 7045) whose command line runs a shell, a script host or a LOLBin, writes into a named pipe, starts a program from an admin share or a temporary or user folder, or names a program without its folder. Attackers install such services to run code as SYSTEM, to move laterally (Impacket, Cobalt Strike, Empire, sc.exe) or to escalate privileges with the named pipe "getsystem" trick.
- **Possible false positives:** Installers or updaters that register a temporary service from C:\\Windows\\Temp or a user folder; Administrators or management tools that wrap a script in a service with cmd.exe or PowerShell; Deployment or scanning tools that copy their agent through the ADMIN$ share and start it as a service

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-20 16:16:58Z | WORKSTATION6.theshire.local | empire\_psexec\_dcerpc\_tcp\_svcctl\_service\_excerpt.json:2 | ServiceName=Updater ImagePath=%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBFAHIAUwBpAE8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AYQBqAG8AcgAgAC0ARwBFACAAMwApAHsAJ… |

### 2. LSASS Memory Access With Credential Dumping Rights (high)

- **When:** 2020-09-22 08:38:29Z
- **Hosts:** WORKSTATION5.theshire.local
- **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) OS Credential Dumping: LSASS Memory (Credential Access)
- **Rule:** LSASS Memory Access With Credential Dumping Rights, `cbea5c72-bafb-4200-b58d-fa251eeef003`
- **Author:** Samir Bousseaden, Michael Haag, Florian Roth (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects a process opening LSASS (Sysmon event 10) with the access rights that Mimikatz, ProcDump, comsvcs.dll MiniDump, Task Manager dumps and similar tools request to read or patch its memory. LSASS memory holds the password hashes, Kerberos tickets and sometimes clear-text passwords of logged-on users.
- **Possible false positives:** Antivirus, EDR, backup or monitoring agents that inspect LSASS (add their exact paths as filters); Process inspection that reads module or handle details of every process, such as Process Explorer or PowerShell Get-Process output serialized over WinRM (0x1410, 0x1f3fff); Administrators dumping LSASS on purpose for troubleshooting with ProcDump or Task Manager; Windows installed on a drive other than C:, where the filters do not apply

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-22 08:38:29Z | WORKSTATION5.theshire.local | rdp\_interactive\_taskmanager\_lsass\_dump\_excerpt.json:7 | SourceImage=C:\\windows\\system32\\taskmgr.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1fffff |

### 3. LSASS Memory Access With Credential Dumping Rights (high)

- **When:** 2020-09-22 08:38:29Z
- **Hosts:** WORKSTATION5.theshire.local
- **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) OS Credential Dumping: LSASS Memory (Credential Access)
- **Rule:** LSASS Memory Access With Credential Dumping Rights, `cbea5c72-bafb-4200-b58d-fa251eeef003`
- **Author:** Samir Bousseaden, Michael Haag, Florian Roth (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects a process opening LSASS (Sysmon event 10) with the access rights that Mimikatz, ProcDump, comsvcs.dll MiniDump, Task Manager dumps and similar tools request to read or patch its memory. LSASS memory holds the password hashes, Kerberos tickets and sometimes clear-text passwords of logged-on users.
- **Possible false positives:** Antivirus, EDR, backup or monitoring agents that inspect LSASS (add their exact paths as filters); Process inspection that reads module or handle details of every process, such as Process Explorer or PowerShell Get-Process output serialized over WinRM (0x1410, 0x1f3fff); Administrators dumping LSASS on purpose for troubleshooting with ProcDump or Task Manager; Windows installed on a drive other than C:, where the filters do not apply

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-22 08:38:29Z | WORKSTATION5.theshire.local | rdp\_interactive\_taskmanager\_lsass\_dump\_excerpt.json:8 | SourceImage=C:\\windows\\system32\\taskmgr.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1fffff |

### 4. Security Event Log Cleared (high)

- **When:** 2020-10-18 02:17:00Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1685.005](https://attack.mitre.org/techniques/T1685/005) Disable or Modify Tools: Clear Windows Event Logs (Defense Impairment)
- **Rule:** Security Event Log Cleared, `bbb4b441-8965-4e18-8efe-12bec2b08423`
- **Author:** Florian Roth (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects the clearing of the Windows Security audit log (event 1102), e.g. with "wevtutil cl Security" or Clear-EventLog. Attackers clear it to erase the record of their logons and actions.
- **Possible false positives:** Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation); Lab and test machines whose logs are cleared before each capture

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-18 02:17:00Z | WORKSTATION5 | wmic\_remote\_xsl\_jscript\_excerpt.json:2 | The audit log was cleared. Subject: Security ID: S-1-5-21-3940915590-64593676-1414006259-500 Account Name: wardog Domain Name: WORKSTATION5 Logon ID: 0x13899EA |

### 5. LSASS Memory Access With Credential Dumping Rights (high)

- **When:** 2020-10-18 23:50:06Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) OS Credential Dumping: LSASS Memory (Credential Access)
- **Rule:** LSASS Memory Access With Credential Dumping Rights, `cbea5c72-bafb-4200-b58d-fa251eeef003`
- **Author:** Samir Bousseaden, Michael Haag, Florian Roth (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects a process opening LSASS (Sysmon event 10) with the access rights that Mimikatz, ProcDump, comsvcs.dll MiniDump, Task Manager dumps and similar tools request to read or patch its memory. LSASS memory holds the password hashes, Kerberos tickets and sometimes clear-text passwords of logged-on users.
- **Possible false positives:** Antivirus, EDR, backup or monitoring agents that inspect LSASS (add their exact paths as filters); Process inspection that reads module or handle details of every process, such as Process Explorer or PowerShell Get-Process output serialized over WinRM (0x1410, 0x1f3fff); Administrators dumping LSASS on purpose for troubleshooting with ProcDump or Task Manager; Windows installed on a drive other than C:, where the filters do not apply

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-18 23:50:06Z | WORKSTATION5 | psh\_lsass\_memory\_dump\_comsvcs\_excerpt.json:2 | SourceImage=C:\\Windows\\System32\\rundll32.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1410 |

### 6. LSASS Memory Access With Credential Dumping Rights (high)

- **When:** 2020-10-18 23:50:06Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) OS Credential Dumping: LSASS Memory (Credential Access)
- **Rule:** LSASS Memory Access With Credential Dumping Rights, `cbea5c72-bafb-4200-b58d-fa251eeef003`
- **Author:** Samir Bousseaden, Michael Haag, Florian Roth (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects a process opening LSASS (Sysmon event 10) with the access rights that Mimikatz, ProcDump, comsvcs.dll MiniDump, Task Manager dumps and similar tools request to read or patch its memory. LSASS memory holds the password hashes, Kerberos tickets and sometimes clear-text passwords of logged-on users.
- **Possible false positives:** Antivirus, EDR, backup or monitoring agents that inspect LSASS (add their exact paths as filters); Process inspection that reads module or handle details of every process, such as Process Explorer or PowerShell Get-Process output serialized over WinRM (0x1410, 0x1f3fff); Administrators dumping LSASS on purpose for troubleshooting with ProcDump or Task Manager; Windows installed on a drive other than C:, where the filters do not apply

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-18 23:50:06Z | WORKSTATION5 | psh\_lsass\_memory\_dump\_comsvcs\_excerpt.json:1 | SourceImage=C:\\Windows\\System32\\rundll32.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1fffff |

### 7. Security Event Log Cleared (high)

- **When:** 2020-10-21 11:28:08Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1685.005](https://attack.mitre.org/techniques/T1685/005) Disable or Modify Tools: Clear Windows Event Logs (Defense Impairment)
- **Rule:** Security Event Log Cleared, `bbb4b441-8965-4e18-8efe-12bec2b08423`
- **Author:** Florian Roth (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects the clearing of the Windows Security audit log (event 1102), e.g. with "wevtutil cl Security" or Clear-EventLog. Attackers clear it to erase the record of their logons and actions.
- **Possible false positives:** Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation); Lab and test machines whose logs are cleared before each capture

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-21 11:28:08Z | WORKSTATION5 | cmd\_discover\_iexplorer\_version\_registry\_excerpt.json:1 | The audit log was cleared. Subject: Security ID: S-1-5-21-3940915590-64593676-1414006259-500 Account Name: wardog Domain Name: WORKSTATION5 Logon ID: 0xC61D9 |

### 8. Important Windows Event Log Cleared (high)

- **When:** 2020-10-21 11:28:08Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1685.005](https://attack.mitre.org/techniques/T1685/005) Disable or Modify Tools: Clear Windows Event Logs (Defense Impairment)
- **Rule:** Important Windows Event Log Cleared, `e28d89fc-b094-4869-be4d-63c90efcdd22`
- **Author:** Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects the clearing of a core Windows event log (System, Security, Sysmon or PowerShell) reported by the Eventlog service as System event 104; clearing the Security log is normally reported as Security event 1102, covered by the Security Event Log Cleared rule. Attackers clear these logs to hide their tracks.
- **Possible false positives:** Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation); Lab and test machines whose logs are cleared before each capture

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-21 11:28:08Z | WORKSTATION5 | cmd\_discover\_iexplorer\_version\_registry\_excerpt.json:2 | The System log file was cleared. |

### 9. Suspicious Service Installed (high)

- **When:** 2021-06-11 09:07:41Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003) Create or Modify System Process: Windows Service; [T1569.002](https://attack.mitre.org/techniques/T1569/002) System Services: Service Execution (Execution, Persistence, Privilege Escalation)
- **Rule:** Suspicious Service Installed, `6d03b054-8230-47ba-a957-6b59a2d71c33`
- **Author:** pH-T (Nextron Systems), Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Ecco, oscd.community, Natalia Shornikova (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects a new Windows service (System event 7045) whose command line runs a shell, a script host or a LOLBin, writes into a named pipe, starts a program from an admin share or a temporary or user folder, or names a program without its folder. Attackers install such services to run code as SYSTEM, to move laterally (Impacket, Cobalt Strike, Empire, sc.exe) or to escalate privileges with the named pipe "getsystem" trick.
- **Possible false positives:** Installers or updaters that register a temporary service from C:\\Windows\\Temp or a user folder; Administrators or management tools that wrap a script in a service with cmd.exe or PowerShell; Deployment or scanning tools that copy their agent through the ADMIN$ share and start it as a service

| Time | Host | Origin | Event |
|---|---|---|---|
| 2021-06-11 09:07:41Z | WORKSTATION5 | aptsimulator\_cobaltstrike\_service\_excerpt.json:2 | ServiceName=tbbd05 ImagePath=%COMSPEC% echo /c b6a1458f396 \> \\\\.\\pipe\\334485 |

### 10. SSH Login After Brute Force (high)

- **When:** 2024-03-10 09:05:42Z to 2024-03-10 09:07:05Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.45
- **ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts; [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Initial Access, Persistence, Privilege Escalation, Stealth, Credential Access)
- **Rule:** SSH Login After Brute Force, `156d0b6d-aea1-479c-91ce-eaf6c08cfa67`, correlation
- **Author:** Bouliw
- **What it means:** A successful SSH login from an address whose SSH brute force alert fired in the previous 10 minutes. The attacker has most likely guessed a valid password.
- **Possible false positives:** A legitimate user who retried many times before remembering the password; A login from an address shared with a host that retries a stale password (NAT gateway, jump host, backup server)

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-03-10 09:05:42Z | web01 | auth.log:6 | Failed password for invalid user oracle from 203.0.113.45 port 40022 ssh2 |
| 2024-03-10 09:05:49Z | web01 | auth.log:7 | Failed password for root from 203.0.113.45 port 40030 ssh2 |
| 2024-03-10 09:05:56Z | web01 | auth.log:8 | Failed password for root from 203.0.113.45 port 40038 ssh2 |
| 2024-03-10 09:06:03Z | web01 | auth.log:9 | Failed password for invalid user admin from 203.0.113.45 port 40046 ssh2 |
| 2024-03-10 09:06:10Z | web01 | auth.log:10 | Failed password for invalid user admin from 203.0.113.45 port 40054 ssh2 |
| 2024-03-10 09:06:17Z | web01 | auth.log:11 | Failed password for invalid user test from 203.0.113.45 port 40062 ssh2 |
| 2024-03-10 09:06:24Z | web01 | auth.log:12 | Failed password for root from 203.0.113.45 port 40070 ssh2 |
| 2024-03-10 09:06:31Z | web01 | auth.log:13 | Failed password for opsadmin from 203.0.113.45 port 40078 ssh2 |
| 2024-03-10 09:06:38Z | web01 | auth.log:14 | Failed password for opsadmin from 203.0.113.45 port 40086 ssh2 |
| 2024-03-10 09:07:05Z | web01 | auth.log:18 | Accepted password for opsadmin from 203.0.113.45 port 40188 ssh2 |

1 event(s) between the first 9 and the last one are not shown.

### 11. SSH Login After Brute Force (high)

- **When:** 2024-06-03 08:00:00Z to 2024-06-03 08:10:00Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.77
- **ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts; [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Initial Access, Persistence, Privilege Escalation, Stealth, Credential Access)
- **Rule:** SSH Login After Brute Force, `156d0b6d-aea1-479c-91ce-eaf6c08cfa67`, correlation
- **Author:** Bouliw
- **What it means:** A successful SSH login from an address whose SSH brute force alert fired in the previous 10 minutes. The attacker has most likely guessed a valid password.
- **Possible false positives:** A legitimate user who retried many times before remembering the password; A login from an address shared with a host that retries a stale password (NAT gateway, jump host, backup server)

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 08:00:00Z | web01 | auth\_bruteforce\_timing.log:1 | Failed password for root from 203.0.113.77 port 41000 ssh2 |
| 2024-06-03 08:00:33Z | web01 | auth\_bruteforce\_timing.log:2 | Failed password for root from 203.0.113.77 port 41001 ssh2 |
| 2024-06-03 08:01:06Z | web01 | auth\_bruteforce\_timing.log:3 | Failed password for root from 203.0.113.77 port 41002 ssh2 |
| 2024-06-03 08:01:39Z | web01 | auth\_bruteforce\_timing.log:4 | Failed password for root from 203.0.113.77 port 41003 ssh2 |
| 2024-06-03 08:02:12Z | web01 | auth\_bruteforce\_timing.log:5 | Failed password for root from 203.0.113.77 port 41004 ssh2 |
| 2024-06-03 08:02:45Z | web01 | auth\_bruteforce\_timing.log:6 | Failed password for root from 203.0.113.77 port 41005 ssh2 |
| 2024-06-03 08:03:18Z | web01 | auth\_bruteforce\_timing.log:7 | Failed password for root from 203.0.113.77 port 41006 ssh2 |
| 2024-06-03 08:03:51Z | web01 | auth\_bruteforce\_timing.log:8 | Failed password for root from 203.0.113.77 port 41007 ssh2 |
| 2024-06-03 08:04:24Z | web01 | auth\_bruteforce\_timing.log:9 | Failed password for root from 203.0.113.77 port 41008 ssh2 |
| 2024-06-03 08:10:00Z | web01 | auth\_bruteforce\_timing.log:20 | Accepted password for root from 203.0.113.77 port 41100 ssh2 |

1 event(s) between the first 9 and the last one are not shown.

### 12. SSH Login After Brute Force (high)

- **When:** 2024-06-04 08:05:00Z to 2024-06-04 08:05:30Z
- **Hosts:** deb13
- **Grouped by:** src\_ip = 203.0.113.90
- **ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts; [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Initial Access, Persistence, Privilege Escalation, Stealth, Credential Access)
- **Rule:** SSH Login After Brute Force, `156d0b6d-aea1-479c-91ce-eaf6c08cfa67`, correlation
- **Author:** Bouliw
- **What it means:** A successful SSH login from an address whose SSH brute force alert fired in the previous 10 minutes. The attacker has most likely guessed a valid password.
- **Possible false positives:** A legitimate user who retried many times before remembering the password; A login from an address shared with a host that retries a stale password (NAT gateway, jump host, backup server)

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-04 08:05:00Z | deb13 | auth\_openssh10.log:3 | Failed password for root from 203.0.113.90 port 51000 ssh2 |
| 2024-06-04 08:05:02Z | deb13 | auth\_openssh10.log:4 | Failed password for root from 203.0.113.90 port 51001 ssh2 |
| 2024-06-04 08:05:04Z | deb13 | auth\_openssh10.log:5 | Failed password for root from 203.0.113.90 port 51002 ssh2 |
| 2024-06-04 08:05:06Z | deb13 | auth\_openssh10.log:6 | Failed password for root from 203.0.113.90 port 51003 ssh2 |
| 2024-06-04 08:05:08Z | deb13 | auth\_openssh10.log:7 | Failed password for root from 203.0.113.90 port 51004 ssh2 |
| 2024-06-04 08:05:10Z | deb13 | auth\_openssh10.log:8 | Failed password for root from 203.0.113.90 port 51005 ssh2 |
| 2024-06-04 08:05:12Z | deb13 | auth\_openssh10.log:9 | Failed password for root from 203.0.113.90 port 51006 ssh2 |
| 2024-06-04 08:05:14Z | deb13 | auth\_openssh10.log:10 | Failed password for root from 203.0.113.90 port 51007 ssh2 |
| 2024-06-04 08:05:16Z | deb13 | auth\_openssh10.log:11 | Failed password for root from 203.0.113.90 port 51008 ssh2 |
| 2024-06-04 08:05:30Z | deb13 | auth\_openssh10.log:13 | Accepted password for root from 203.0.113.90 port 51100 ssh2 |

1 event(s) between the first 9 and the last one are not shown.

### 13. PowerShell Encoded Command Execution (medium)

- **When:** 2020-09-20 06:57:49Z
- **Hosts:** WORKSTATION6.theshire.local
- **ATT&CK:** [T1027.010](https://attack.mitre.org/techniques/T1027/010) Obfuscated Files or Information: Command Obfuscation; [T1059.001](https://attack.mitre.org/techniques/T1059/001) Command and Scripting Interpreter: PowerShell (Execution, Stealth)
- **Rule:** PowerShell Encoded Command Execution, `6a55e742-68fb-4b56-8a9d-3364684fe986`
- **Author:** frack113 (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects PowerShell (powershell.exe or pwsh.exe, or a renamed copy when Sysmon records its OriginalFileName) started with -EncodedCommand or one of its abbreviations such as -e, -enc or -ec. Attackers pass Base64 encoded scripts this way to hide the real command from analysts and command-line signatures (Empire and Metasploit launchers, Emotet droppers...).
- **Possible false positives:** Management and deployment agents that pass scripts as encoded commands (SCCM, Intune, RMM tools, some installers); A -Command script or -File script arguments containing a standalone -e, -en or -ec, or /e, /en or /ec (for example robocopy /E or xcopy /E run through powershell -Command)

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-20 06:57:49Z | WORKSTATION6.theshire.local | empire\_smbexec\_dcerpc\_smb\_svcctl\_excerpt.json:5 | CommandLine=C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAcwBpAG8ATgBUAGEAQgBMAEUALgBQAFMAVgBFAHIAcwBJAE8AbgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApAHsAJAA2ADgANgA2AD0AWwBSAEUAZgBdAC4AQQBzAHMAZ… |

### 14. PowerShell Encoded Command Execution (medium)

- **When:** 2020-09-20 06:57:49Z
- **Hosts:** WORKSTATION6.theshire.local
- **ATT&CK:** [T1027.010](https://attack.mitre.org/techniques/T1027/010) Obfuscated Files or Information: Command Obfuscation; [T1059.001](https://attack.mitre.org/techniques/T1059/001) Command and Scripting Interpreter: PowerShell (Execution, Stealth)
- **Rule:** PowerShell Encoded Command Execution, `6a55e742-68fb-4b56-8a9d-3364684fe986`
- **Author:** frack113 (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects PowerShell (powershell.exe or pwsh.exe, or a renamed copy when Sysmon records its OriginalFileName) started with -EncodedCommand or one of its abbreviations such as -e, -enc or -ec. Attackers pass Base64 encoded scripts this way to hide the real command from analysts and command-line signatures (Empire and Metasploit launchers, Emotet droppers...).
- **Possible false positives:** Management and deployment agents that pass scripts as encoded commands (SCCM, Intune, RMM tools, some installers); A -Command script or -File script arguments containing a standalone -e, -en or -ec, or /e, /en or /ec (for example robocopy /E or xcopy /E run through powershell -Command)

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-20 06:57:49Z | WORKSTATION6.theshire.local | empire\_smbexec\_dcerpc\_smb\_svcctl\_excerpt.json:6 | CommandLine=C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAcwBpAG8ATgBUAGEAQgBMAEUALgBQAFMAVgBFAHIAcwBJAE8AbgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApAHsAJAA2ADgANgA2AD0AWwBSAEUAZgBdAC4AQQBzAHMAZ… |

### 15. Suspicious Scheduled Task Created (medium)

- **When:** 2020-09-21 07:15:47Z
- **Hosts:** WORKSTATION5.theshire.local
- **ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation)
- **Rule:** Suspicious Scheduled Task Created, `b2f53816-dce1-4a25-82ba-f9879e134928`
- **Author:** Nasreddine Bencherchali (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects the creation of a scheduled task (event 4698) whose action runs a command interpreter, script host or LOLBin (cmd, PowerShell, rundll32, regsvr32, mshta, wscript, cscript...) or a program stored in a user-writable staging folder (Temp, Public, Roaming, Desktop, Downloads, ProgramData...). Attackers register such tasks for persistence, privilege escalation and remote execution (e.g. Impacket atexec, Empire).
- **Possible false positives:** Administration scripts, deployment tools and GPO-deployed tasks that run cmd.exe or PowerShell (baseline them by TaskName and Author); Software installers or updaters that register a task running from a Temp or ProgramData folder; Windows servicing re-registering built-in tasks whose action is rundll32.exe or cmd.exe

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-21 07:15:47Z | WORKSTATION5.theshire.local | empire\_schtasks\_creation\_standard\_user\_excerpt.json:1 | TaskName=\\MordorSchtask SubjectUserName=pgustavo |

### 16. PsExec-Like Service Installed (medium)

- **When:** 2020-10-19 03:30:46Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002) System Services: Service Execution (Execution)
- **Rule:** PsExec-Like Service Installed, `4d9d8b96-f9b9-4454-86d2-5dc723e625bb`
- **Author:** Thomas Patzke, Nasreddine Bencherchali (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects the installation (System event 7045) of the helper service of PsExec (PSEXESVC) or of a similar remote execution tool (PAExec, RemCom, CSExec). These tools run commands as SYSTEM, locally or on a remote host over SMB; administrators use them, and so do attackers to move laterally.
- **Possible false positives:** Administrators and IT tools that use PsExec or PAExec for remote maintenance

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-19 03:30:46Z | WORKSTATION5 | cmd\_psexec\_lsa\_secrets\_dump\_service\_excerpt.json:2 | ServiceName=PSEXESVC ImagePath=%SystemRoot%\\PSEXESVC.exe |

### 17. Windows Logon Brute Force From Single Source (medium)

- **When:** 2020-10-22 08:29:55Z to 2020-10-22 08:29:55Z
- **Hosts:** WORKSTATION5.theshire.local
- **Grouped by:** IpAddress = -, WorkstationName = WORKSTATION5
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing; [T1110.003](https://attack.mitre.org/techniques/T1110/003) Brute Force: Password Spraying (Credential Access)
- **Rule:** Windows Logon Brute Force From Single Source, `6cf25939-c0a0-43f8-bb43-34d254f459cb`, correlation
- **Author:** Bouliw
- **What it means:** At least 5 failed Windows logons (wrong password, unknown user name or locked-out account) from the same source within 1 minute, the source being the client IP address and workstation name. Password guessing and password spraying tools produce such bursts, far faster than a person retyping a password.
- **Possible false positives:** A service, scheduled task, mapped drive or mobile device retrying an outdated password in a loop; A shared host (terminal server, jump host, NAT gateway) where several users mistype their passwords at the same time

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | purplesharp\_ad\_playbook\_I\_excerpt.json:1 | SubjectUserName=pgustavo TargetUserName=lrodriguez IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | purplesharp\_ad\_playbook\_I\_excerpt.json:2 | SubjectUserName=pgustavo TargetUserName=pgustavo IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | purplesharp\_ad\_playbook\_I\_excerpt.json:3 | SubjectUserName=pgustavo TargetUserName=sysmonsvc IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | purplesharp\_ad\_playbook\_I\_excerpt.json:4 | SubjectUserName=pgustavo TargetUserName=sbeavers IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | purplesharp\_ad\_playbook\_I\_excerpt.json:5 | SubjectUserName=pgustavo TargetUserName=mscott IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a |

### 18. File Download Via Bitsadmin (medium)

- **When:** 2020-10-23 06:36:43Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer; [T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs (Execution, Persistence, Stealth, Command and Control)
- **Rule:** File Download Via Bitsadmin, `32b87f74-31c8-401e-9efe-288445b0431b`
- **Author:** Michael Haag, FPT.EagleEye (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects bitsadmin.exe running a BITS transfer with /transfer, or adding an http(s) URL to a job with /addfile. The download is then performed by the BITS service itself, can survive reboots and blends with Windows Update traffic, which makes bitsadmin a classic way to bring attacker tools onto a host.
- **Possible false positives:** Installers, update agents or administrator scripts that still download files with bitsadmin instead of the BITS PowerShell cmdlets

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-23 06:36:43Z | WORKSTATION5 | cmd\_bitsadmin\_download\_psh\_script\_excerpt.json:1 | CommandLine=bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\\Users\\wardog\\AppData\\Local\\Temp\\bitsadmin1\_flag.ps1 NewProcessName=C:\\Windows… |

### 19. File Download Via Bitsadmin (medium)

- **When:** 2020-10-23 06:36:43Z
- **Hosts:** WORKSTATION5
- **ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer; [T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs (Execution, Persistence, Stealth, Command and Control)
- **Rule:** File Download Via Bitsadmin, `32b87f74-31c8-401e-9efe-288445b0431b`
- **Author:** Michael Haag, FPT.EagleEye (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects bitsadmin.exe running a BITS transfer with /transfer, or adding an http(s) URL to a job with /addfile. The download is then performed by the BITS service itself, can survive reboots and blends with Windows Update traffic, which makes bitsadmin a classic way to bring attacker tools onto a host.
- **Possible false positives:** Installers, update agents or administrator scripts that still download files with bitsadmin instead of the BITS PowerShell cmdlets

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-10-23 06:36:43Z | WORKSTATION5 | cmd\_bitsadmin\_download\_psh\_script\_excerpt.json:5 | CommandLine=bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\\Users\\wardog\\AppData\\Local\\Temp\\bitsadmin1\_flag.ps1 Image=C:\\Windows\\System32… |

### 20. Suspicious Scheduled Task Created (medium)

- **When:** 2020-12-19 07:00:22Z
- **Hosts:** WORKSTATION6.theshire.local
- **ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation)
- **Rule:** Suspicious Scheduled Task Created, `b2f53816-dce1-4a25-82ba-f9879e134928`
- **Author:** Nasreddine Bencherchali (Nextron Systems) (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** Detects the creation of a scheduled task (event 4698) whose action runs a command interpreter, script host or LOLBin (cmd, PowerShell, rundll32, regsvr32, mshta, wscript, cscript...) or a program stored in a user-writable staging folder (Temp, Public, Roaming, Desktop, Downloads, ProgramData...). Attackers register such tasks for persistence, privilege escalation and remote execution (e.g. Impacket atexec, Empire).
- **Possible false positives:** Administration scripts, deployment tools and GPO-deployed tasks that run cmd.exe or PowerShell (baseline them by TaskName and Author); Software installers or updaters that register a task running from a Temp or ProgramData folder; Windows servicing re-registering built-in tasks whose action is rundll32.exe or cmd.exe

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-12-19 07:00:22Z | WORKSTATION6.theshire.local | schtask\_create\_excerpt.json:1 | TaskName=\\Microsoft\\Windows\\SoftwareProtectionPlatform\\EventCacheManager SubjectUserName=pgustavo |

### 21. SSH Brute Force (medium)

- **When:** 2024-03-10 09:05:42Z to 2024-03-10 09:06:45Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.45
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-03-10 09:05:42Z | web01 | auth.log:6 | Failed password for invalid user oracle from 203.0.113.45 port 40022 ssh2 |
| 2024-03-10 09:05:49Z | web01 | auth.log:7 | Failed password for root from 203.0.113.45 port 40030 ssh2 |
| 2024-03-10 09:05:56Z | web01 | auth.log:8 | Failed password for root from 203.0.113.45 port 40038 ssh2 |
| 2024-03-10 09:06:03Z | web01 | auth.log:9 | Failed password for invalid user admin from 203.0.113.45 port 40046 ssh2 |
| 2024-03-10 09:06:10Z | web01 | auth.log:10 | Failed password for invalid user admin from 203.0.113.45 port 40054 ssh2 |
| 2024-03-10 09:06:17Z | web01 | auth.log:11 | Failed password for invalid user test from 203.0.113.45 port 40062 ssh2 |
| 2024-03-10 09:06:24Z | web01 | auth.log:12 | Failed password for root from 203.0.113.45 port 40070 ssh2 |
| 2024-03-10 09:06:31Z | web01 | auth.log:13 | Failed password for opsadmin from 203.0.113.45 port 40078 ssh2 |
| 2024-03-10 09:06:38Z | web01 | auth.log:14 | Failed password for opsadmin from 203.0.113.45 port 40086 ssh2 |
| 2024-03-10 09:06:45Z | web01 | auth.log:15 | Failed password for invalid user ubuntu from 203.0.113.45 port 40094 ssh2 |

### 22. SSH Password Spraying (medium)

- **When:** 2024-03-10 09:05:42Z to 2024-03-10 09:06:31Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.45
- **ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003) Brute Force: Password Spraying (Credential Access)
- **Rule:** SSH Password Spraying, `a5668195-278b-4b24-aaf9-53ee8ff41701`, correlation
- **Author:** Bouliw
- **What it means:** Failed SSH password attempts against at least 5 different user names from the same source address within 10 minutes. Trying many accounts with a few common passwords avoids per-account lockouts.
- **Possible false positives:** A shared jump host where several users mistype their passwords in a short time

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-03-10 09:05:42Z | web01 | auth.log:6 | Failed password for invalid user oracle from 203.0.113.45 port 40022 ssh2 |
| 2024-03-10 09:05:49Z | web01 | auth.log:7 | Failed password for root from 203.0.113.45 port 40030 ssh2 |
| 2024-03-10 09:05:56Z | web01 | auth.log:8 | Failed password for root from 203.0.113.45 port 40038 ssh2 |
| 2024-03-10 09:06:03Z | web01 | auth.log:9 | Failed password for invalid user admin from 203.0.113.45 port 40046 ssh2 |
| 2024-03-10 09:06:10Z | web01 | auth.log:10 | Failed password for invalid user admin from 203.0.113.45 port 40054 ssh2 |
| 2024-03-10 09:06:17Z | web01 | auth.log:11 | Failed password for invalid user test from 203.0.113.45 port 40062 ssh2 |
| 2024-03-10 09:06:24Z | web01 | auth.log:12 | Failed password for root from 203.0.113.45 port 40070 ssh2 |
| 2024-03-10 09:06:31Z | web01 | auth.log:13 | Failed password for opsadmin from 203.0.113.45 port 40078 ssh2 |

### 23. Local User Account Created (medium)

- **When:** 2024-03-10 09:08:12Z
- **Hosts:** web01
- **ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001) Create Account: Local Account (Persistence)
- **Rule:** Local User Account Created, `30bda398-aea5-47d4-bc2c-0a7a01d09698`
- **Author:** Bouliw
- **What it means:** A local user account was created with useradd. Attackers create accounts to keep access to a compromised host.
- **Possible false positives:** Administrators creating accounts; Package installations that create service accounts

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-03-10 09:08:12Z | web01 | auth.log:23 | new user: name=svc\_update, UID=1003, GID=1003, home=/home/svc\_update, shell=/bin/bash, from=/dev/pts/1 |

### 24. SSH Brute Force (medium)

- **When:** 2024-04-03 02:00:05Z to 2024-04-03 02:01:08Z
- **Hosts:** backup01
- **Grouped by:** src\_ip = 192.0.2.50
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-04-03 02:00:05Z | backup01 | auth\_retry\_storm.log:2 | Failed password for backup from 192.0.2.50 port 40000 ssh2 |
| 2024-04-03 02:00:12Z | backup01 | auth\_retry\_storm.log:3 | Failed password for backup from 192.0.2.50 port 40001 ssh2 |
| 2024-04-03 02:00:19Z | backup01 | auth\_retry\_storm.log:4 | Failed password for backup from 192.0.2.50 port 40002 ssh2 |
| 2024-04-03 02:00:26Z | backup01 | auth\_retry\_storm.log:5 | Failed password for backup from 192.0.2.50 port 40003 ssh2 |
| 2024-04-03 02:00:33Z | backup01 | auth\_retry\_storm.log:6 | Failed password for backup from 192.0.2.50 port 40004 ssh2 |
| 2024-04-03 02:00:40Z | backup01 | auth\_retry\_storm.log:7 | Failed password for backup from 192.0.2.50 port 40005 ssh2 |
| 2024-04-03 02:00:47Z | backup01 | auth\_retry\_storm.log:8 | Failed password for backup from 192.0.2.50 port 40006 ssh2 |
| 2024-04-03 02:00:54Z | backup01 | auth\_retry\_storm.log:9 | Failed password for backup from 192.0.2.50 port 40007 ssh2 |
| 2024-04-03 02:01:01Z | backup01 | auth\_retry\_storm.log:10 | Failed password for backup from 192.0.2.50 port 40008 ssh2 |
| 2024-04-03 02:01:08Z | backup01 | auth\_retry\_storm.log:11 | Failed password for backup from 192.0.2.50 port 40009 ssh2 |

### 25. SSH Brute Force (medium)

- **When:** 2024-06-03 08:00:00Z to 2024-06-03 08:04:57Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.77
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 08:00:00Z | web01 | auth\_bruteforce\_timing.log:1 | Failed password for root from 203.0.113.77 port 41000 ssh2 |
| 2024-06-03 08:00:33Z | web01 | auth\_bruteforce\_timing.log:2 | Failed password for root from 203.0.113.77 port 41001 ssh2 |
| 2024-06-03 08:01:06Z | web01 | auth\_bruteforce\_timing.log:3 | Failed password for root from 203.0.113.77 port 41002 ssh2 |
| 2024-06-03 08:01:39Z | web01 | auth\_bruteforce\_timing.log:4 | Failed password for root from 203.0.113.77 port 41003 ssh2 |
| 2024-06-03 08:02:12Z | web01 | auth\_bruteforce\_timing.log:5 | Failed password for root from 203.0.113.77 port 41004 ssh2 |
| 2024-06-03 08:02:45Z | web01 | auth\_bruteforce\_timing.log:6 | Failed password for root from 203.0.113.77 port 41005 ssh2 |
| 2024-06-03 08:03:18Z | web01 | auth\_bruteforce\_timing.log:7 | Failed password for root from 203.0.113.77 port 41006 ssh2 |
| 2024-06-03 08:03:51Z | web01 | auth\_bruteforce\_timing.log:8 | Failed password for root from 203.0.113.77 port 41007 ssh2 |
| 2024-06-03 08:04:24Z | web01 | auth\_bruteforce\_timing.log:9 | Failed password for root from 203.0.113.77 port 41008 ssh2 |
| 2024-06-03 08:04:57Z | web01 | auth\_bruteforce\_timing.log:10 | Failed password for root from 203.0.113.77 port 41009 ssh2 |

### 26. SSH Brute Force (medium)

- **When:** 2024-06-03 09:00:00Z to 2024-06-03 09:00:27Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.78
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 09:00:00Z | web01 | auth\_bruteforce\_timing.log:21 | Failed password for root from 203.0.113.78 port 42000 ssh2 |
| 2024-06-03 09:00:03Z | web01 | auth\_bruteforce\_timing.log:22 | Failed password for root from 203.0.113.78 port 42001 ssh2 |
| 2024-06-03 09:00:06Z | web01 | auth\_bruteforce\_timing.log:23 | Failed password for root from 203.0.113.78 port 42002 ssh2 |
| 2024-06-03 09:00:09Z | web01 | auth\_bruteforce\_timing.log:24 | Failed password for root from 203.0.113.78 port 42003 ssh2 |
| 2024-06-03 09:00:12Z | web01 | auth\_bruteforce\_timing.log:25 | Failed password for root from 203.0.113.78 port 42004 ssh2 |
| 2024-06-03 09:00:15Z | web01 | auth\_bruteforce\_timing.log:26 | Failed password for root from 203.0.113.78 port 42005 ssh2 |
| 2024-06-03 09:00:18Z | web01 | auth\_bruteforce\_timing.log:27 | Failed password for root from 203.0.113.78 port 42006 ssh2 |
| 2024-06-03 09:00:21Z | web01 | auth\_bruteforce\_timing.log:28 | Failed password for root from 203.0.113.78 port 42007 ssh2 |
| 2024-06-03 09:00:24Z | web01 | auth\_bruteforce\_timing.log:29 | Failed password for root from 203.0.113.78 port 42008 ssh2 |
| 2024-06-03 09:00:27Z | web01 | auth\_bruteforce\_timing.log:30 | Failed password for root from 203.0.113.78 port 42009 ssh2 |

### 27. SSH Brute Force (medium)

- **When:** 2024-06-03 10:00:10Z to 2024-06-03 10:00:37Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.79
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 10:00:10Z | web01 | auth\_bruteforce\_timing.log:33 | Failed password for root from 203.0.113.79 port 43001 ssh2 |
| 2024-06-03 10:00:13Z | web01 | auth\_bruteforce\_timing.log:34 | Failed password for root from 203.0.113.79 port 43002 ssh2 |
| 2024-06-03 10:00:16Z | web01 | auth\_bruteforce\_timing.log:35 | Failed password for root from 203.0.113.79 port 43003 ssh2 |
| 2024-06-03 10:00:19Z | web01 | auth\_bruteforce\_timing.log:36 | Failed password for root from 203.0.113.79 port 43004 ssh2 |
| 2024-06-03 10:00:22Z | web01 | auth\_bruteforce\_timing.log:37 | Failed password for root from 203.0.113.79 port 43005 ssh2 |
| 2024-06-03 10:00:25Z | web01 | auth\_bruteforce\_timing.log:38 | Failed password for root from 203.0.113.79 port 43006 ssh2 |
| 2024-06-03 10:00:28Z | web01 | auth\_bruteforce\_timing.log:39 | Failed password for root from 203.0.113.79 port 43007 ssh2 |
| 2024-06-03 10:00:31Z | web01 | auth\_bruteforce\_timing.log:40 | Failed password for root from 203.0.113.79 port 43008 ssh2 |
| 2024-06-03 10:00:34Z | web01 | auth\_bruteforce\_timing.log:41 | Failed password for root from 203.0.113.79 port 43009 ssh2 |
| 2024-06-03 10:00:37Z | web01 | auth\_bruteforce\_timing.log:42 | Failed password for root from 203.0.113.79 port 43010 ssh2 |

### 28. SSH Brute Force (medium)

- **When:** 2024-06-03 11:00:00Z to 2024-06-03 11:00:27Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 203.0.113.80
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 11:00:00Z | web01 | auth\_bruteforce\_timing.log:43 | Failed password for root from 203.0.113.80 port 44000 ssh2 |
| 2024-06-03 11:00:03Z | web01 | auth\_bruteforce\_timing.log:44 | Failed password for root from 203.0.113.80 port 44001 ssh2 |
| 2024-06-03 11:00:06Z | web01 | auth\_bruteforce\_timing.log:45 | Failed password for root from 203.0.113.80 port 44002 ssh2 |
| 2024-06-03 11:00:09Z | web01 | auth\_bruteforce\_timing.log:46 | Failed password for root from 203.0.113.80 port 44003 ssh2 |
| 2024-06-03 11:00:12Z | web01 | auth\_bruteforce\_timing.log:47 | Failed password for root from 203.0.113.80 port 44004 ssh2 |
| 2024-06-03 11:00:15Z | web01 | auth\_bruteforce\_timing.log:48 | Failed password for root from 203.0.113.80 port 44005 ssh2 |
| 2024-06-03 11:00:18Z | web01 | auth\_bruteforce\_timing.log:49 | Failed password for root from 203.0.113.80 port 44006 ssh2 |
| 2024-06-03 11:00:21Z | web01 | auth\_bruteforce\_timing.log:50 | Failed password for root from 203.0.113.80 port 44007 ssh2 |
| 2024-06-03 11:00:24Z | web01 | auth\_bruteforce\_timing.log:51 | Failed password for root from 203.0.113.80 port 44008 ssh2 |
| 2024-06-03 11:00:27Z | web01 | auth\_bruteforce\_timing.log:52 | Failed password for root from 203.0.113.80 port 44009 ssh2 |

### 29. SSH Password Spraying (medium)

- **When:** 2024-06-03 14:30:00Z to 2024-06-03 14:39:50Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 198.51.100.85
- **ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003) Brute Force: Password Spraying (Credential Access)
- **Rule:** SSH Password Spraying, `a5668195-278b-4b24-aaf9-53ee8ff41701`, correlation
- **Author:** Bouliw
- **What it means:** Failed SSH password attempts against at least 5 different user names from the same source address within 10 minutes. Trying many accounts with a few common passwords avoids per-account lockouts.
- **Possible false positives:** A shared jump host where several users mistype their passwords in a short time

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 14:30:00Z | web01 | auth\_bruteforce\_timing.log:82 | Failed password for invalid user admin from 198.51.100.85 port 49000 ssh2 |
| 2024-06-03 14:32:27Z | web01 | auth\_bruteforce\_timing.log:83 | Failed password for invalid user postgres from 198.51.100.85 port 49001 ssh2 |
| 2024-06-03 14:34:54Z | web01 | auth\_bruteforce\_timing.log:84 | Failed password for invalid user git from 198.51.100.85 port 49002 ssh2 |
| 2024-06-03 14:37:21Z | web01 | auth\_bruteforce\_timing.log:85 | Failed password for invalid user pi from 198.51.100.85 port 49003 ssh2 |
| 2024-06-03 14:39:50Z | web01 | auth\_bruteforce\_timing.log:86 | Failed password for invalid user user from 198.51.100.85 port 49004 ssh2 |

### 30. SSH Brute Force (medium)

- **When:** 2024-06-03 16:00:00Z to 2024-06-03 16:00:45Z
- **Hosts:** web01
- **Grouped by:** src\_ip = 198.51.100.66
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-03 16:00:00Z | web01 | auth\_bruteforce\_timing.log:98 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53000 ssh2 |
| 2024-06-03 16:00:05Z | web01 | auth\_bruteforce\_timing.log:99 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53001 ssh2 |
| 2024-06-03 16:00:10Z | web01 | auth\_bruteforce\_timing.log:100 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53002 ssh2 |
| 2024-06-03 16:00:15Z | web01 | auth\_bruteforce\_timing.log:101 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53003 ssh2 |
| 2024-06-03 16:00:20Z | web01 | auth\_bruteforce\_timing.log:102 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53004 ssh2 |
| 2024-06-03 16:00:25Z | web01 | auth\_bruteforce\_timing.log:103 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53005 ssh2 |
| 2024-06-03 16:00:30Z | web01 | auth\_bruteforce\_timing.log:104 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53006 ssh2 |
| 2024-06-03 16:00:35Z | web01 | auth\_bruteforce\_timing.log:105 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53007 ssh2 |
| 2024-06-03 16:00:40Z | web01 | auth\_bruteforce\_timing.log:106 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53008 ssh2 |
| 2024-06-03 16:00:45Z | web01 | auth\_bruteforce\_timing.log:107 | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53009 ssh2 |

### 31. SSH Brute Force (medium)

- **When:** 2024-06-04 08:05:00Z to 2024-06-04 08:05:18Z
- **Hosts:** deb13
- **Grouped by:** src\_ip = 203.0.113.90
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-04 08:05:00Z | deb13 | auth\_openssh10.log:3 | Failed password for root from 203.0.113.90 port 51000 ssh2 |
| 2024-06-04 08:05:02Z | deb13 | auth\_openssh10.log:4 | Failed password for root from 203.0.113.90 port 51001 ssh2 |
| 2024-06-04 08:05:04Z | deb13 | auth\_openssh10.log:5 | Failed password for root from 203.0.113.90 port 51002 ssh2 |
| 2024-06-04 08:05:06Z | deb13 | auth\_openssh10.log:6 | Failed password for root from 203.0.113.90 port 51003 ssh2 |
| 2024-06-04 08:05:08Z | deb13 | auth\_openssh10.log:7 | Failed password for root from 203.0.113.90 port 51004 ssh2 |
| 2024-06-04 08:05:10Z | deb13 | auth\_openssh10.log:8 | Failed password for root from 203.0.113.90 port 51005 ssh2 |
| 2024-06-04 08:05:12Z | deb13 | auth\_openssh10.log:9 | Failed password for root from 203.0.113.90 port 51006 ssh2 |
| 2024-06-04 08:05:14Z | deb13 | auth\_openssh10.log:10 | Failed password for root from 203.0.113.90 port 51007 ssh2 |
| 2024-06-04 08:05:16Z | deb13 | auth\_openssh10.log:11 | Failed password for root from 203.0.113.90 port 51008 ssh2 |
| 2024-06-04 08:05:18Z | deb13 | auth\_openssh10.log:12 | Failed password for root from 203.0.113.90 port 51009 ssh2 |

### 32. SSH Brute Force (medium)

- **When:** 2024-07-08 03:12:01Z to 2024-07-08 03:12:20Z
- **Hosts:** web04
- **Grouped by:** src\_ip = 203.0.113.120
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing (Credential Access)
- **Rule:** SSH Brute Force, `44043ef0-67f0-4380-9c98-b348be632e58`, correlation
- **Author:** Bouliw
- **What it means:** At least 10 failed SSH password attempts from the same source address within 5 minutes, the signature of an automated password guessing attack.
- **Possible false positives:** A misconfigured script or service retrying an outdated password; Vulnerability scanners run by the security team

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-07-08 03:12:01Z | web04 | auth\_rsyslog\_repeated.log:1 | Failed password for root from 203.0.113.120 port 55010 ssh2 |
| 2024-07-08 03:12:09Z | web04 | auth\_rsyslog\_repeated.log:2 (repeat 1/5) | Failed password for root from 203.0.113.120 port 55010 ssh2 |
| 2024-07-08 03:12:09Z | web04 | auth\_rsyslog\_repeated.log:2 (repeat 2/5) | Failed password for root from 203.0.113.120 port 55010 ssh2 |
| 2024-07-08 03:12:09Z | web04 | auth\_rsyslog\_repeated.log:2 (repeat 3/5) | Failed password for root from 203.0.113.120 port 55010 ssh2 |
| 2024-07-08 03:12:09Z | web04 | auth\_rsyslog\_repeated.log:2 (repeat 4/5) | Failed password for root from 203.0.113.120 port 55010 ssh2 |
| 2024-07-08 03:12:09Z | web04 | auth\_rsyslog\_repeated.log:2 (repeat 5/5) | Failed password for root from 203.0.113.120 port 55010 ssh2 |
| 2024-07-08 03:12:12Z | web04 | auth\_rsyslog\_repeated.log:6 | Failed password for root from 203.0.113.120 port 55020 ssh2 |
| 2024-07-08 03:12:20Z | web04 | auth\_rsyslog\_repeated.log:7 (repeat 1/5) | Failed password for root from 203.0.113.120 port 55020 ssh2 |
| 2024-07-08 03:12:20Z | web04 | auth\_rsyslog\_repeated.log:7 (repeat 2/5) | Failed password for root from 203.0.113.120 port 55020 ssh2 |
| 2024-07-08 03:12:20Z | web04 | auth\_rsyslog\_repeated.log:7 (repeat 3/5) | Failed password for root from 203.0.113.120 port 55020 ssh2 |

### 33. User Account Created (low)

- **When:** 2020-09-14 12:06:03Z
- **Hosts:** WORKSTATION6.theshire.local
- **ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001) Create Account: Local Account; [T1136.002](https://attack.mitre.org/techniques/T1136/002) Create Account: Domain Account (Persistence)
- **Rule:** User Account Created, `87270cf5-a164-4eb4-bd0b-f92d2ef57c1c`
- **Author:** Patrick Bareiss (SigmaHQ), adapted by Bouliw (rule licensed under DRL-1.1)
- **What it means:** A user account was created, in the local SAM database of a workstation or server, or in Active Directory when logged by a domain controller (Security event 4720). Attackers create accounts to keep access to a compromised host or domain.
- **Possible false positives:** Administrators or help desk staff creating accounts, which is routine in domain controller logs; Local accounts managed by privileged account management tools

| Time | Host | Origin | Event |
|---|---|---|---|
| 2020-09-14 12:06:03Z | WORKSTATION6.theshire.local | empire\_wmic\_add\_user\_backdoor\_excerpt.json:5 | SubjectUserName=pgustavo TargetUserName=backdoor |

### 34. Sudo Authentication Failure (low)

- **When:** 2024-03-10 09:09:30Z
- **Hosts:** web01
- **ATT&CK:** [T1548.003](https://attack.mitre.org/techniques/T1548/003) Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation)
- **Rule:** Sudo Authentication Failure, `87c54c54-38eb-4d79-88a8-714dbb6a656d`
- **Author:** Bouliw
- **What it means:** A user failed to authenticate to sudo. Repeated failures can reveal someone trying to guess a password to gain root privileges.
- **Possible false positives:** Users mistyping their password

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-03-10 09:09:30Z | web01 | auth.log:24 | deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/bin/bash |

### 35. Sudo Authentication Failure (low)

- **When:** 2024-06-04 08:07:12Z
- **Hosts:** deb13
- **ATT&CK:** [T1548.003](https://attack.mitre.org/techniques/T1548/003) Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation)
- **Rule:** Sudo Authentication Failure, `87c54c54-38eb-4d79-88a8-714dbb6a656d`
- **Author:** Bouliw
- **What it means:** A user failed to authenticate to sudo. Repeated failures can reveal someone trying to guess a password to gain root privileges.
- **Possible false positives:** Users mistyping their password

| Time | Host | Origin | Event |
|---|---|---|---|
| 2024-06-04 08:07:12Z | deb13 | auth\_openssh10.log:16 | deploy : 3 incorrect password attempts ; HOST=deb13 ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash |

## Timeline

Events behind the alerts above, in time order.

| Time | Host | Source | ID | Event | Alerts |
|---|---|---|---|---|---|
| 2020-09-14 12:06:03Z | WORKSTATION6.theshire.local | security | 4720 | SubjectUserName=pgustavo TargetUserName=backdoor | User Account Created |
| 2020-09-20 06:57:49Z | WORKSTATION6.theshire.local | security | 4688 | CommandLine=C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAcwBpAG8ATgBUAGEAQgBMAEUALgBQAFMAVgBFAHIAcwBJAE8AbgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApAHsAJAA2ADgANgA2AD0AWwBSAEUAZgBdAC4AQQBzAHMAZ… | PowerShell Encoded Command Execution |
| 2020-09-20 06:57:49Z | WORKSTATION6.theshire.local | sysmon | 1 | CommandLine=C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAcwBpAG8ATgBUAGEAQgBMAEUALgBQAFMAVgBFAHIAcwBJAE8AbgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApAHsAJAA2ADgANgA2AD0AWwBSAEUAZgBdAC4AQQBzAHMAZ… | PowerShell Encoded Command Execution |
| 2020-09-20 16:16:58Z | WORKSTATION6.theshire.local | system | 7045 | ServiceName=Updater ImagePath=%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBFAHIAUwBpAE8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AYQBqAG8AcgAgAC0ARwBFACAAMwApAHsAJ… | Suspicious Service Installed |
| 2020-09-21 07:15:47Z | WORKSTATION5.theshire.local | security | 4698 | TaskName=\\MordorSchtask SubjectUserName=pgustavo | Suspicious Scheduled Task Created |
| 2020-09-22 08:38:29Z | WORKSTATION5.theshire.local | sysmon | 10 | SourceImage=C:\\windows\\system32\\taskmgr.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1fffff | LSASS Memory Access With Credential Dumping Rights |
| 2020-09-22 08:38:29Z | WORKSTATION5.theshire.local | sysmon | 10 | SourceImage=C:\\windows\\system32\\taskmgr.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1fffff | LSASS Memory Access With Credential Dumping Rights |
| 2020-10-18 02:17:00Z | WORKSTATION5 | security | 1102 | The audit log was cleared. Subject: Security ID: S-1-5-21-3940915590-64593676-1414006259-500 Account Name: wardog Domain Name: WORKSTATION5 Logon ID: 0x13899EA | Security Event Log Cleared |
| 2020-10-18 23:50:06Z | WORKSTATION5 | sysmon | 10 | SourceImage=C:\\Windows\\System32\\rundll32.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1410 | LSASS Memory Access With Credential Dumping Rights |
| 2020-10-18 23:50:06Z | WORKSTATION5 | sysmon | 10 | SourceImage=C:\\Windows\\System32\\rundll32.exe TargetImage=C:\\windows\\system32\\lsass.exe GrantedAccess=0x1fffff | LSASS Memory Access With Credential Dumping Rights |
| 2020-10-19 03:30:46Z | WORKSTATION5 | system | 7045 | ServiceName=PSEXESVC ImagePath=%SystemRoot%\\PSEXESVC.exe | PsExec-Like Service Installed |
| 2020-10-21 11:28:08Z | WORKSTATION5 | security | 1102 | The audit log was cleared. Subject: Security ID: S-1-5-21-3940915590-64593676-1414006259-500 Account Name: wardog Domain Name: WORKSTATION5 Logon ID: 0xC61D9 | Security Event Log Cleared |
| 2020-10-21 11:28:08Z | WORKSTATION5 | system | 104 | The System log file was cleared. | Important Windows Event Log Cleared |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | security | 4625 | SubjectUserName=pgustavo TargetUserName=lrodriguez IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a | Windows Logon Brute Force From Single Source |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | security | 4625 | SubjectUserName=pgustavo TargetUserName=pgustavo IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a | Windows Logon Brute Force From Single Source |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | security | 4625 | SubjectUserName=pgustavo TargetUserName=sysmonsvc IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a | Windows Logon Brute Force From Single Source |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | security | 4625 | SubjectUserName=pgustavo TargetUserName=sbeavers IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a | Windows Logon Brute Force From Single Source |
| 2020-10-22 08:29:55Z | WORKSTATION5.theshire.local | security | 4625 | SubjectUserName=pgustavo TargetUserName=mscott IpAddress=- WorkstationName=WORKSTATION5 Status=0xc000006d SubStatus=0xc000006a | Windows Logon Brute Force From Single Source |
| 2020-10-23 06:36:43Z | WORKSTATION5 | security | 4688 | CommandLine=bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\\Users\\wardog\\AppData\\Local\\Temp\\bitsadmin1\_flag.ps1 NewProcessName=C:\\Windows… | File Download Via Bitsadmin |
| 2020-10-23 06:36:43Z | WORKSTATION5 | sysmon | 1 | CommandLine=bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\\Users\\wardog\\AppData\\Local\\Temp\\bitsadmin1\_flag.ps1 Image=C:\\Windows\\System32… | File Download Via Bitsadmin |
| 2020-12-19 07:00:22Z | WORKSTATION6.theshire.local | security | 4698 | TaskName=\\Microsoft\\Windows\\SoftwareProtectionPlatform\\EventCacheManager SubjectUserName=pgustavo | Suspicious Scheduled Task Created |
| 2021-06-11 09:07:41Z | WORKSTATION5 | system | 7045 | ServiceName=tbbd05 ImagePath=%COMSPEC% echo /c b6a1458f396 \> \\\\.\\pipe\\334485 | Suspicious Service Installed |
| 2024-03-10 09:05:42Z | web01 | auth | - | Failed password for invalid user oracle from 203.0.113.45 port 40022 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:05:49Z | web01 | auth | - | Failed password for root from 203.0.113.45 port 40030 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:05:56Z | web01 | auth | - | Failed password for root from 203.0.113.45 port 40038 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:06:03Z | web01 | auth | - | Failed password for invalid user admin from 203.0.113.45 port 40046 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:06:10Z | web01 | auth | - | Failed password for invalid user admin from 203.0.113.45 port 40054 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:06:17Z | web01 | auth | - | Failed password for invalid user test from 203.0.113.45 port 40062 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:06:24Z | web01 | auth | - | Failed password for root from 203.0.113.45 port 40070 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:06:31Z | web01 | auth | - | Failed password for opsadmin from 203.0.113.45 port 40078 ssh2 | SSH Login After Brute Force; SSH Brute Force; SSH Password Spraying |
| 2024-03-10 09:06:38Z | web01 | auth | - | Failed password for opsadmin from 203.0.113.45 port 40086 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-03-10 09:06:45Z | web01 | auth | - | Failed password for invalid user ubuntu from 203.0.113.45 port 40094 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-03-10 09:07:05Z | web01 | auth | - | Accepted password for opsadmin from 203.0.113.45 port 40188 ssh2 | SSH Login After Brute Force |
| 2024-03-10 09:08:12Z | web01 | auth | - | new user: name=svc\_update, UID=1003, GID=1003, home=/home/svc\_update, shell=/bin/bash, from=/dev/pts/1 | Local User Account Created |
| 2024-03-10 09:09:30Z | web01 | auth | - | deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/bin/bash | Sudo Authentication Failure |
| 2024-04-03 02:00:05Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40000 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:12Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40001 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:19Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40002 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:26Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40003 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:33Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40004 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:40Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40005 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:47Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40006 ssh2 | SSH Brute Force |
| 2024-04-03 02:00:54Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40007 ssh2 | SSH Brute Force |
| 2024-04-03 02:01:01Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40008 ssh2 | SSH Brute Force |
| 2024-04-03 02:01:08Z | backup01 | auth | - | Failed password for backup from 192.0.2.50 port 40009 ssh2 | SSH Brute Force |
| 2024-06-03 08:00:00Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41000 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:00:33Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41001 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:01:06Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41002 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:01:39Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41003 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:02:12Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41004 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:02:45Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41005 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:03:18Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41006 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:03:51Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41007 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:04:24Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41008 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:04:57Z | web01 | auth | - | Failed password for root from 203.0.113.77 port 41009 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-03 08:10:00Z | web01 | auth | - | Accepted password for root from 203.0.113.77 port 41100 ssh2 | SSH Login After Brute Force |
| 2024-06-03 09:00:00Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42000 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:03Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42001 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:06Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42002 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:09Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42003 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:12Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42004 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:15Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42005 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:18Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42006 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:21Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42007 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:24Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42008 ssh2 | SSH Brute Force |
| 2024-06-03 09:00:27Z | web01 | auth | - | Failed password for root from 203.0.113.78 port 42009 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:10Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43001 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:13Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43002 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:16Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43003 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:19Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43004 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:22Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43005 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:25Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43006 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:28Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43007 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:31Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43008 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:34Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43009 ssh2 | SSH Brute Force |
| 2024-06-03 10:00:37Z | web01 | auth | - | Failed password for root from 203.0.113.79 port 43010 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:00Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44000 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:03Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44001 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:06Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44002 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:09Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44003 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:12Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44004 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:15Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44005 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:18Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44006 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:21Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44007 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:24Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44008 ssh2 | SSH Brute Force |
| 2024-06-03 11:00:27Z | web01 | auth | - | Failed password for root from 203.0.113.80 port 44009 ssh2 | SSH Brute Force |
| 2024-06-03 14:30:00Z | web01 | auth | - | Failed password for invalid user admin from 198.51.100.85 port 49000 ssh2 | SSH Password Spraying |
| 2024-06-03 14:32:27Z | web01 | auth | - | Failed password for invalid user postgres from 198.51.100.85 port 49001 ssh2 | SSH Password Spraying |
| 2024-06-03 14:34:54Z | web01 | auth | - | Failed password for invalid user git from 198.51.100.85 port 49002 ssh2 | SSH Password Spraying |
| 2024-06-03 14:37:21Z | web01 | auth | - | Failed password for invalid user pi from 198.51.100.85 port 49003 ssh2 | SSH Password Spraying |
| 2024-06-03 14:39:50Z | web01 | auth | - | Failed password for invalid user user from 198.51.100.85 port 49004 ssh2 | SSH Password Spraying |
| 2024-06-03 16:00:00Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53000 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:05Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53001 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:10Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53002 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:15Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53003 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:20Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53004 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:25Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53005 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:30Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53006 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:35Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53007 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:40Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53008 ssh2 | SSH Brute Force |
| 2024-06-03 16:00:45Z | web01 | auth | - | Failed password for invalid user x from 192.0.2.10 port 1 from 198.51.100.66 port 53009 ssh2 | SSH Brute Force |
| 2024-06-04 08:05:00Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51000 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:02Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51001 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:04Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51002 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:06Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51003 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:08Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51004 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:10Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51005 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:12Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51006 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:14Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51007 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:16Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51008 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:18Z | deb13 | auth | - | Failed password for root from 203.0.113.90 port 51009 ssh2 | SSH Login After Brute Force; SSH Brute Force |
| 2024-06-04 08:05:30Z | deb13 | auth | - | Accepted password for root from 203.0.113.90 port 51100 ssh2 | SSH Login After Brute Force |
| 2024-06-04 08:07:12Z | deb13 | auth | - | deploy : 3 incorrect password attempts ; HOST=deb13 ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash | Sudo Authentication Failure |
| 2024-07-08 03:12:01Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55010 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:09Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55010 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:09Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55010 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:09Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55010 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:09Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55010 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:09Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55010 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:12Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55020 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:20Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55020 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:20Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55020 ssh2 | SSH Brute Force |
| 2024-07-08 03:12:20Z | web04 | auth | - | Failed password for root from 203.0.113.120 port 55020 ssh2 | SSH Brute Force |

## Inputs

| File | Format | Events | Warnings |
|---|---|---|---|
| aptsimulator\_cobaltstrike\_service\_excerpt.json | winjson | 4 | 0 |
| authlog/auth.log | authlog | 29 | 1 |
| authlog/auth\_benign.log | authlog | 27 | 0 |
| authlog/auth\_bruteforce\_timing.log | authlog | 108 | 0 |
| authlog/auth\_openssh10.log | authlog | 17 | 0 |
| authlog/auth\_retry\_storm.log | authlog | 16 | 0 |
| authlog/auth\_rfc3339.log | authlog | 3 | 0 |
| authlog/auth\_rollover.log | authlog | 3 | 0 |
| authlog/auth\_rsyslog\_repeated.log | authlog | 18 | 0 |
| authlog/auth\_sessions.log | authlog | 8 | 0 |
| cmd\_bitsadmin\_download\_psh\_script\_excerpt.json | winjson | 10 | 1 |
| cmd\_discover\_iexplorer\_version\_registry\_excerpt.json | winjson | 2 | 0 |
| cmd\_mshta\_vbscript\_execute\_psh\_excerpt.json | winjson | 4 | 1 |
| cmd\_psexec\_lsa\_secrets\_dump\_service\_excerpt.json | winjson | 2 | 0 |
| cmd\_psh\_stop\_netprofm\_eventlog\_before\_reboot\_excerpt.json | winjson | 8 | 0 |
| covenant\_dcom\_executeexcel4macro\_allowed\_excerpt.json | winjson | 1 | 0 |
| empire\_persistence\_registry\_modification\_run\_keys\_standard\_user\_certutil\_excerpt.json | winjson | 10 | 0 |
| empire\_persistence\_registry\_modification\_run\_keys\_standard\_user\_excerpt.json | winjson | 9 | 0 |
| empire\_psexec\_dcerpc\_tcp\_svcctl\_service\_excerpt.json | winjson | 4 | 0 |
| empire\_schtasks\_creation\_execution\_elevated\_user\_service\_excerpt.json | winjson | 6 | 0 |
| empire\_schtasks\_creation\_standard\_user\_excerpt.json | winjson | 1 | 0 |
| empire\_shell\_rubeus\_asktgt\_createnetonly\_excerpt.json | winjson | 4 | 0 |
| empire\_smbexec\_dcerpc\_smb\_svcctl\_excerpt.json | winjson | 6 | 0 |
| empire\_wmi\_local\_event\_subscriptions\_elevated\_user\_excerpt.json | winjson | 8 | 0 |
| empire\_wmi\_local\_event\_subscriptions\_elevated\_user\_lsass\_excerpt.json | winjson | 16 | 0 |
| empire\_wmic\_add\_user\_backdoor\_excerpt.json | winjson | 8 | 0 |
| psh\_disable\_eventlog\_service\_startuptype\_modification\_excerpt.json | winjson | 5 | 0 |
| psh\_lsass\_memory\_dump\_comsvcs\_excerpt.json | winjson | 2 | 1 |
| purplesharp\_ad\_playbook\_I\_excerpt.json | winjson | 14 | 0 |
| rdp\_interactive\_taskmanager\_lsass\_dump\_excerpt.json | winjson | 8 | 0 |
| schtask\_create\_excerpt.json | winjson | 1 | 0 |
| wmic\_remote\_xsl\_jscript\_excerpt.json | winjson | 2 | 0 |
| wmic\_remote\_xsl\_jscript\_lsass\_excerpt.json | winjson | 4 | 1 |

Parser warnings:

- auth.log:30: unrecognized syslog line
- cmd\_bitsadmin\_download\_psh\_script\_excerpt.json: timestamps shifted by +04:00 to match Sysmon UtcTime (local time labeled as UTC)
- cmd\_mshta\_vbscript\_execute\_psh\_excerpt.json: timestamps shifted by +04:00 to match Sysmon UtcTime (local time labeled as UTC)
- psh\_lsass\_memory\_dump\_comsvcs\_excerpt.json: timestamps shifted by +16:00 to match Sysmon UtcTime (local time labeled as UTC)
- wmic\_remote\_xsl\_jscript\_lsass\_excerpt.json: timestamps shifted by +04:00 to match Sysmon UtcTime (local time labeled as UTC)

---

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. Rules adapted from SigmaHQ are licensed under the Detection Rule License 1.1; their authors are credited in each alert.
