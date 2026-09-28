# Vigie report

Generated on 2026-09-28 12:00:00Z by Vigie 0.1.0.dev0. Alerts are mapped to MITRE ATT&CK 19.2. All times are UTC.

## Summary

| | |
|---|---|
| Events analyzed | 29 |
| Time range | 2024-03-10 08:58:01Z to 2024-03-10 09:15:00Z |
| Files read | 1 |
| Rules loaded | 23 |
| Alerts shown | 5 (level low and above) |

| Severity | Alerts |
|---|---|
| critical | 0 |
| high | 1 |
| medium | 3 |
| low | 1 |

3 alert(s) below the "low" level are not shown (informational: 3). Run with `--min-level informational` to include them.

## MITRE ATT&CK

| Tactic | Alerts | Techniques |
|---|---|---|
| [Initial Access](https://attack.mitre.org/tactics/TA0001) (TA0001) | 1 | [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts |
| [Persistence](https://attack.mitre.org/tactics/TA0003) (TA0003) | 2 | [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts<br>[T1136.001](https://attack.mitre.org/techniques/T1136/001) Create Account: Local Account |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) (TA0004) | 2 | [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts<br>[T1548.003](https://attack.mitre.org/techniques/T1548/003) Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| [Stealth](https://attack.mitre.org/tactics/TA0005) (TA0005) | 1 | [T1078.003](https://attack.mitre.org/techniques/T1078/003) Valid Accounts: Local Accounts |
| [Credential Access](https://attack.mitre.org/tactics/TA0006) (TA0006) | 3 | [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing<br>[T1110.003](https://attack.mitre.org/techniques/T1110/003) Brute Force: Password Spraying |

## Alerts

| Severity | Rule | Alerts | First seen | Last seen |
|---|---|---|---|---|
| high | SSH Login After Brute Force | 1 | 2024-03-10 09:05:42Z | 2024-03-10 09:07:05Z |
| medium | Local User Account Created | 1 | 2024-03-10 09:08:12Z | 2024-03-10 09:08:12Z |
| medium | SSH Brute Force | 1 | 2024-03-10 09:05:42Z | 2024-03-10 09:06:45Z |
| medium | SSH Password Spraying | 1 | 2024-03-10 09:05:42Z | 2024-03-10 09:06:31Z |
| low | Sudo Authentication Failure | 1 | 2024-03-10 09:09:30Z | 2024-03-10 09:09:30Z |

### 1. SSH Login After Brute Force (high)

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

### 2. SSH Brute Force (medium)

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

### 3. SSH Password Spraying (medium)

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

### 4. Local User Account Created (medium)

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

### 5. Sudo Authentication Failure (low)

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

## Timeline

Events behind the alerts above, in time order.

| Time | Host | Source | ID | Event | Alerts |
|---|---|---|---|---|---|
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

## Inputs

| File | Format | Events | Warnings |
|---|---|---|---|
| authlog/auth.log | authlog | 29 | 1 |

Parser warnings:

- auth.log:30: unrecognized syslog line

---

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. Rules adapted from SigmaHQ are licensed under the Detection Rule License 1.1; their authors are credited in each alert.
