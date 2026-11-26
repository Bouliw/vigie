# Sample organization (demo)

86 of 86 controls answered, on a 0-5 scale. Made with Vigie 0.6.0 on 2026-11-26 14:44 UTC.

## MITRE ATT&CK 19.2 (Enterprise)

Exposure index: 41/100. Facilitated: 15, No preventive control: 61, Partly hindered: 111, Hindered: 35, Not assessed: 0.

Nothing blocks the easiest path.

| Stage | Easiest technique | Status |
|---|---|---|
| Reconnaissance | T1595 Active Scanning | Facilitated |
| Resource Development | T1588 Obtain Capabilities | No preventive control |
| Initial Access | T1200 Hardware Additions | Facilitated |
| Execution | T1129 Shared Modules | Facilitated |
| Persistence | T1653 Power Settings | Facilitated |
| Privilege Escalation | T1037 Boot or Logon Initialization Scripts | Partly hindered |
| Stealth | T1220 XSL Script Processing | Facilitated |
| Defense Impairment | T1222 File and Directory Permissions Modification | Facilitated |
| Credential Access | T1056 Input Capture | Partly hindered |
| Discovery | T1482 Domain Trust Discovery | Facilitated |
| Lateral Movement | T1534 Internal Spearphishing | No preventive control |
| Collection | T1005 Data from Local System | Facilitated |
| Command and Control | T1665 Hide Infrastructure | No preventive control |
| Exfiltration | T1052 Exfiltration Over Physical Medium | Facilitated |
| Impact | T1529 System Shutdown/Reboot | No preventive control |

## MITRE ATLAS 2026.10 (AI systems)

Exposure index: 71/100. Facilitated: 46, No preventive control: 23, Partly hindered: 60, Hindered: 0, Not assessed: 0.

Nothing blocks the easiest path.

| Stage | Easiest technique | Status |
|---|---|---|
| Reconnaissance | AML.T0000 Search Open Technical Databases | Facilitated |
| Resource Development | AML.T0008 Acquire Infrastructure | Facilitated |
| AI Attack Adaptation | AML.T0088 Generate Deepfakes | Facilitated |
| Initial Access | AML.T0093 Prompt Infiltration via Public-Facing Application | Facilitated |
| AI Model Access | AML.T0041 Physical Environment Access | Facilitated |
| Execution | AML.T0050 Command and Scripting Interpreter | Facilitated |
| Persistence | AML.T0093 Prompt Infiltration via Public-Facing Application | Facilitated |
| Privilege Escalation | AML.T0105 Escape to Host | No preventive control |
| Defense Evasion | AML.T0081 Modify AI Agent Configuration | Facilitated |
| Credential Access | AML.T0098 AI Agent Tool Credential Harvesting | Facilitated |
| Discovery | AML.T0133 Discover AI Agent Runtime Capabilities | Facilitated |
| Lateral Movement | AML.T0122 Exploitation of Remote Services | Facilitated |
| Collection | AML.T0135 Outputs from AI Models | Facilitated |
| Command and Control | AML.T0072 Cyber Communication Channel | Facilitated |
| Exfiltration | AML.T0136 Exfiltration via AI User Interface | No preventive control |
| Impact | AML.T0031 Erode AI Model Integrity | Facilitated |

## What to raise first

1. **AML.M0011 Restrict Library Loading**: 1 → 4, stops 5 techniques from being facilitated, 1 on the easiest path, 1 seen in the logs.
2. **AML.M0039 AI Honeypots**: 0 → 4, stops 9 techniques from being facilitated, 4 on the easiest path.
3. **AML.M0042 Threat Intelligence Program**: 1 → 4, stops 10 techniques from being facilitated, 1 on the easiest path.
4. **M1057 Data Loss Prevention**: 1 → 4, stops 3 techniques from being facilitated, 2 on the easiest path.
5. **M1047 Audit**: 1 → 4, stops 5 techniques from being facilitated, 2 on the easiest path.
6. **AML.M0043 AI Agent External Resource Lifecycle Management**: 0 → 4, stops 7 techniques from being facilitated, 2 on the easiest path.
7. **AML.M0032 Segmentation of AI Agent Components**: 1 → 4, stops 4 techniques from being facilitated, 1 on the easiest path, 1 seen in the logs.
8. **AML.M0000 Limit Public Release of Information**: 1 → 4, stops 8 techniques from being facilitated, 2 on the easiest path.
9. **AML.M0016 Vulnerability Scanning**: 1 → 4, stops 6 techniques from being facilitated, 1 on the easiest path.
10. **M1038 Execution Prevention**: 1 → 4, stops 3 techniques from being facilitated, 2 on the easiest path.
11. **M1026 Privileged Account Management**: 1 → 4, stops 3 techniques from being facilitated, 1 on the easiest path.
12. **AML.M0009 Predictive AI Multi-Sensor Fusion**: 0 → 4, stops 3 techniques from being facilitated, 2 on the easiest path.

## Seen in the logs and left open

- AML.T0136 Exfiltration via AI User Interface: 3 alerts, no preventive control
- AML.T0055 Unsecured Credentials: 2 alerts, no preventive control
- AML.T0050 Command and Scripting Interpreter: 1 alert, facilitated
- AML.T0098 AI Agent Tool Credential Harvesting: 1 alert, facilitated

Facilitated means that a control gap leaves a known technique without its main counter-measure, as MITRE maps them; it is not a probability of attack.
