# Test fixtures

Small log samples used by the test suite. No file here comes from a real
company or a real person: they are either public research datasets, used
under their license, or synthetic files written for Vigie.

| Directory | Origin | License |
|---|---|---|
| `authlog/` | Synthetic, written for Vigie | MIT (project license) |
| `evtx/` | EVTX-ATTACK-SAMPLES, unmodified | GPL-3.0, see [`evtx/README.md`](evtx/README.md) |
| `winjson/` | OTRF Security-Datasets, excerpt | MIT, see below |

## `authlog/`: synthetic

| File | Content |
|---|---|
| `auth.log` | Classic syslog format. Normal logins, an SSH brute force (12 failures in about 80 seconds) followed by a successful login, `sudo` usage, a user created with `useradd`, `su` to root, one malformed line. |
| `auth_rollover.log` | Classic syslog lines crossing from December 31 to January 1, to test year inference. |
| `auth_rfc3339.log` | RFC 3339 timestamps, the rsyslog default on recent Debian and Ubuntu. |
| `auth_benign.log` | A routine day: key-based logins, two password typos then a success, `sudo` with a PAM failure line, `groupadd` and `passwd`, and a slow scanner (8 attempts over 21 minutes). Negative case for most Linux rules. |
| `auth_retry_storm.log` | A backup job retrying a stale password for one account (15 failures in 2 minutes): a brute-force pattern with a single user. |
| `auth_sessions.log` | SSH sessions without any password failure: key-based login, invalid user and pre-authentication disconnects. |
| `auth_bruteforce_timing.log` | Near misses around the SSH correlation thresholds (10 failures in 306 s, 9 in 24 s, 4 names in 2 minutes, 5 names in 604 s), steady and burst brute forces with successes at different delays, failed public keys, and user names that embed a fake source address. |
| `auth_openssh10.log` | RFC 3339 lines from OpenSSH 9.8+ (`sshd-session`, `sshd-auth`) and `sudo` with the `HOST=` field. |
| `auth_rsyslog_repeated.log` | A brute force folded by rsyslog into "message repeated 5 times" lines (2 connections, 12 password failures). |

These files are **synthetic**: written by hand for Vigie, not captured on any
system. They follow the real OpenSSH, sudo, su and shadow-utils message
formats, and use only:

- IPv4 documentation ranges (RFC 5737): `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`;
- fictitious host names (`web01`, `web02`, `app01`, `backup01`, `bastion`,
  `db01`, `deb13`, `web04`) and account names (`deploy`, `opsadmin`, `svc_update`, `backup`),
  plus usernames commonly tried by SSH scanners (`root`, `admin`, `oracle`...).

They are covered by the project's MIT license.

## `winjson/`: OTRF Security-Datasets (excerpts)

Each file holds a few whole lines of one dataset from **Security-Datasets** by
the Open Threat Research Forge:

- Repository: https://github.com/OTRF/Security-Datasets
- Commit: `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`
- License: MIT, full text in [`winjson/LICENSE.MIT`](winjson/LICENSE.MIT)

Modification: only the listed lines of the upstream JSON file were kept (line
numbers are 1-based, in the file inside the zip). Each kept line is
byte-for-byte identical to the original, including its line ending (CRLF or
LF, as upstream). Some excerpts come from the same dataset but keep different
lines for different rules.

| File | Upstream zip (under `datasets/atomic/windows/`) | Member | Kept lines |
|---|---|---|---|
| `cmd_bitsadmin_download_psh_script_excerpt.json` | `defense_evasion/host/cmd_bitsadmin_download_psh_script.zip` | `cmd_bitsadmin_download_psh_script_2020-10-2302365189.json` | 3, 18, 24, 90, 118, 149, 311, 375, 376, 378 |
| `aptsimulator_cobaltstrike_service_excerpt.json` | `other/aptsimulator_cobaltstrike.zip` | `aptsimulator_cobaltstrike_2021-06-11T21081492.json` | 2501, 2609, 2610, 2611 |
| `cmd_discover_iexplorer_version_registry_excerpt.json` | `discovery/host/cmd_discover_iexplorer_version_registry.zip` | `cmd_discover_iexplorer_version_registry_2020-10-2123281491.json` | 1, 68 |
| `cmd_mshta_vbscript_execute_psh_excerpt.json` | `defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip` | `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` | 4, 30, 275, 398 |
| `cmd_psexec_lsa_secrets_dump_service_excerpt.json` | `credential_access/host/cmd_psexec_lsa_secrets_dump.zip` | `cmd_psexec_lsa_secrets_dump_2020-10-1903305471.json` | 10, 286 |
| `cmd_psh_stop_netprofm_eventlog_before_reboot_excerpt.json` | `defense_evasion/host/cmd_psh_stop_netprofm_eventlog_before_reboot.zip` | `cmd_psh_stop_netprofm_eventlog_before_reboot.json` | 35, 36, 37, 63, 64, 65, 66, 68 |
| `covenant_dcom_executeexcel4macro_allowed_excerpt.json` | `lateral_movement/host/covenant_dcom_executeexcel4macro_allowed.zip` | `covenant_dcom_executeexcel4macro_allowed_2020-09-17174542.json` | 3031 |
| `empire_persistence_registry_modification_run_keys_standard_user_certutil_excerpt.json` | `persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip` | `empire_persistence_registry_modification_run_keys_standard_user_2020-09-04030609.json` | 31072, 31095, 31113, 31140, 31158, 31211, 31231, 31272, 31289, 31312 |
| `empire_persistence_registry_modification_run_keys_standard_user_excerpt.json` | `persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip` | `empire_persistence_registry_modification_run_keys_standard_user_2020-09-04030609.json` | 6134, 7398, 7447, 7467, 7472, 7476, 7834, 8289, 8316 |
| `empire_psexec_dcerpc_tcp_svcctl_service_excerpt.json` | `lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip` | `empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json` | 1213, 1251, 1253, 1254 |
| `empire_schtasks_creation_execution_elevated_user_service_excerpt.json` | `persistence/host/empire_schtasks_creation_execution_elevated_user.zip` | `empire_schtasks_creation_execution_elevated_user_2020-09-21175806.json` | 17252, 18104, 18113, 32698, 37108, 41904 |
| `empire_schtasks_creation_standard_user_excerpt.json` | `persistence/host/empire_schtasks_creation_standard_user.zip` | `empire_schtasks_creation_standard_user_2020-09-21031526.json` | 334 |
| `empire_shell_rubeus_asktgt_createnetonly_excerpt.json` | `credential_access/host/empire_shell_rubeus_asktgt_createnetonly.zip` | `empire_shell_rubeus_asktgt_createnetonly_2020-09-21230246.json` | 1331, 1985, 1989, 2510 |
| `empire_smbexec_dcerpc_smb_svcctl_excerpt.json` | `lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip` | `empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json` | 772, 812, 844, 851, 912, 1029 |
| `empire_wmi_local_event_subscriptions_elevated_user_excerpt.json` | `persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip` | `empire_wmi_local_event_subscriptions_elevated_user_2020-09-04164306.json` | 2296, 5119, 5122, 5141, 5145, 5146, 6182, 8398 |
| `empire_wmi_local_event_subscriptions_elevated_user_lsass_excerpt.json` | `persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip` | `empire_wmi_local_event_subscriptions_elevated_user_2020-09-04164306.json` | 206, 439, 4794, 4795, 6235, 12187, 12189, 12191, 12289, 14992, 17947, 56835, 58903, 61129, 65880, 67071 |
| `empire_wmic_add_user_backdoor_excerpt.json` | `defense_evasion/host/empire_wmic_add_user_backdoor.zip` | `empire_wmic_add_user_backdoor_2020-09-14080546.json` | 634, 696, 763, 778, 781, 784, 786, 787 |
| `psh_disable_eventlog_service_startuptype_modification_excerpt.json` | `defense_evasion/host/psh_disable_eventlog_service_startuptype_modification.zip` | `psh_disable_eventlog_service_startuptype_modification.json` | 43, 44, 45, 46, 48 |
| `psh_lsass_memory_dump_comsvcs_excerpt.json` | `credential_access/host/psh_lsass_memory_dump_comsvcs.zip` | `psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json` | 74, 76 |
| `purplesharp_ad_playbook_I_excerpt.json` | `lateral_movement/host/purplesharp_ad_playbook_I.zip` | `purplesharp_ad_playbook_I_2020-10-22042947.json` | 788, 790, 792, 794, 796, 798, 803, 1020, 1046, 1048, 1051, 1072, 1074, 1077 |
| `rdp_interactive_taskmanager_lsass_dump_excerpt.json` | `credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip` | `rdp_interactive_taskmanager_lsass_dump_2020-09-22043748.json` | 3986, 3987, 3988, 3989, 3990, 4704, 4927, 4937 |
| `schtask_create_excerpt.json` | `lateral_movement/host/schtask_create.zip` | `schtask_create_2020-12-1907003032.json` | 579 |
| `wmic_remote_xsl_jscript_excerpt.json` | `defense_evasion/host/wmic_remote_xsl_jscript.zip` | `wmic_remote_xsl_jscript_2020-10-1802171958.json` | 183, 190 |
| `wmic_remote_xsl_jscript_lsass_excerpt.json` | `defense_evasion/host/wmic_remote_xsl_jscript.zip` | `wmic_remote_xsl_jscript_2020-10-1802171958.json` | 373, 1201, 1206, 1257 |

Host, domain and account names (`WORKSTATION5`, `MORDORDC`, `PEDRO01`,
`theshire.local`, `wardog`, `pgustavo`, `sbeavers`...) belong to the OTRF lab.
Some excerpts contain inert attack payloads from the datasets (for example an
Empire Base64 PowerShell stager in a service command line), which security
scanners may flag.

An excerpt without Sysmon events cannot get the clock correction described in
`src/vigie/parsers/winjson.py`, so its timestamps keep the lab's local time.
