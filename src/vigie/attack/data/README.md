# MITRE ATT&CK extract

`enterprise_attack.json` is a reduced copy of the Enterprise ATT&CK STIX
bundle: for each tactic and technique, only the id, name, tactics and URL are
kept, plus the list of revoked technique ids and their replacements.

- Source: https://github.com/mitre-attack/attack-stix-data
  (`enterprise-attack/enterprise-attack-19.2.json`)
- Generated with `python tools/build_attack_data.py --version 19.2`
- License: ATT&CK Terms of Use, reproduced in [`LICENSE-ATTACK.txt`](LICENSE-ATTACK.txt)

© 2026 The MITRE Corporation. This work is reproduced and distributed with
the permission of The MITRE Corporation.

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
