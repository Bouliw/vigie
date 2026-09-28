# EVTX samples (GPL-3.0)

The `.evtx` files in this directory are unmodified copies of files from
**EVTX-ATTACK-SAMPLES** by Samir Bousseaden:

- Repository: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- License: GNU General Public License v3.0, full text in [`LICENSE.GPL`](LICENSE.GPL)

They are distributed here under the GPL-3.0, **not** under the MIT license
that covers the rest of Vigie. They are test data only: Vigie's code does
not include, link to or depend on them.

| File | Upstream path | SHA-256 |
|---|---|---|
| `CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | `75f199b68d473172705bf874720b01820317fdd7aa4843545c98720dd6de197f` |
| `DE_104_system_log_cleared.evtx` | `Defense Evasion/DE_104_system_log_cleared.evtx` | `5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af` |
| `DE_1102_security_log_cleared.evtx` | `Defense Evasion/DE_1102_security_log_cleared.evtx` | `a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8` |
| `DE_Fake_ComputerAccount_4720.evtx` | `Defense Evasion/DE_Fake_ComputerAccount_4720.evtx` | `8b0c2b1998bbd6292fbd23c2fbd954ed2a0db5ae38f39493e718262b215b4da9` |
| `kerberos_pwd_spray_4771.evtx` | `Credential Access/kerberos_pwd_spray_4771.evtx` | `4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d` |
| `LM_Remote_Service02_7045.evtx` | `Lateral Movement/LM_Remote_Service02_7045.evtx` | `af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458` |
| `lm_sysmon_18_remshell_over_namedpipe.evtx` | `Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx` | `efdb2b2f2dd0864e82dabb693d38b44aea93e43c7df490ca3c94a4084da5c173` |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | `Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx` | `18ffdda9c24e593d6b1414b6e05c7f7a5dbffb8588a387c165431b61ab52d76f` |
| `panache_sysmon_vs_EDRTestingScript.evtx` | `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` | `9c1371a0632de15095b6ffe2e38991b764d4beaddb1722178e93aa476f83f52f` |
| `PanacheSysmon_vs_AtomicRedTeam01.evtx` | `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` | `6903dff9f218fa027c704c8c445b74e08b952c8d71be79bd0327f1e792d4aa01` |
| `PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx` | `Privilege Escalation/PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx` | `d6840c8618b24ef671a9810daad60cbd1e12dafe35fba300f5bc54d71a94156a` |
| `samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx` | `Privilege Escalation/samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx` | `d3cf4940a0400a615e7e848a16de8d957bd12ccb99f7c9ce247b17a72a55d212` |
| `sysmon_10_11_lsass_memdump.evtx` | `Credential Access/sysmon_10_11_lsass_memdump.evtx` | `915f0859251552b6c33efc32f6184d2c25419c5859852124a7f14ed6ec1a3723` |
| `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | `Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | `9a1689574ed08c1fb18e7ff3f3bed612109aedcb7bf8efbf3537d756e669e96f` |
| `sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx` | `Execution/sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx` | `f63ea09964ad1b6cc1d1dab6d8203a96f4eae71dd4cddc5408719afdc6e861af` |
| `sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` | `Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` | `f2ac975c8dd1671a66ddbff5d9d59aa76f6577956d8c394970cbe11020837f78` |
| `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | `Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` | `59c28ff11e4b9b329ee6b0859a5514f772913e95ef9ba8f94c46e02c4d78be17` |
| `System_7045_namedpipe_privesc.evtx` | `Privilege Escalation/System_7045_namedpipe_privesc.evtx` | `21a62694861beff246ea9fb357b908541b4acefaefdb7ecd6281b64df96cb187` |
| `temp_scheduled_task_4698_4699.evtx` | `Execution/temp_scheduled_task_4698_4699.evtx` | `a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70` |

The host, domain and account names inside these files come from the
author's lab machines (`example.corp`, `threebeesco.com`, `IEUser`,
`a-jbrown`...), not from a real organization. Several samples start with the
lab clearing the Security log before the capture, which is why the
log-cleared rule fires on them too.
