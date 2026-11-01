# Third-party notices

Vigie's own code is released under the [MIT License](LICENSE). It uses or
redistributes the following third-party work.

## Runtime dependencies (installed by pip, not included in this repository)

| Package | Use | License |
|---|---|---|
| [evtx](https://github.com/omerbenamram/pyevtx-rs) | Decoding Windows `.evtx` files | MIT or Apache-2.0 |
| [PyYAML](https://github.com/yaml/pyyaml) | Reading Sigma rules | MIT |
| [Jinja2](https://github.com/pallets/jinja) | Rendering the HTML and Markdown reports | BSD-3-Clause |
| [MarkupSafe](https://github.com/pallets/markupsafe) (Jinja2 dependency) | HTML escaping | BSD-3-Clause |

## In the standalone apps

The apps of the GitHub releases (`Vigie-windows.zip`, `Vigie-macos.zip`) are
built with [PyInstaller](https://pyinstaller.org) from `packaging/vigie.spec`.
Besides Vigie, its data and the runtime dependencies above, they include:

| Component | License |
|---|---|
| [Python](https://www.python.org) and the libraries its standard library uses | PSF License Agreement and the licenses of those libraries, in the app's `python-license` folder |
| [tzdata](https://github.com/python/tzdata) (Windows app) | Apache-2.0 |
| PyInstaller's bootloader | GPL-2.0, with an exception that allows distributing the programs built with it |

This file and Vigie's license are inside the apps too.

## Detection rules adapted from SigmaHQ

The rules in `src/vigie/rules/` that carry `license: DRL-1.1` are adapted from
the [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma) at commit
`07ec293a51695cb1131a2e05260247872b31e1e1`. They are distributed under the
[Detection Rule License 1.1](src/vigie/rules/LICENSE.DRL-1.1.md). Each file
keeps the original authors in its `author` field, links the original rule in
`references` and lists its id under `related`. Vigie's report shows the author
of the rule in every alert, as the license requires.

## MITRE ATT&CK

`src/vigie/attack/data/enterprise_attack.json` is a reduced copy of the
Enterprise ATT&CK 19.2 STIX bundle from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation. The ATT&CK Terms of Use are reproduced in
[`src/vigie/attack/data/LICENSE-ATTACK.txt`](src/vigie/attack/data/LICENSE-ATTACK.txt).
MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.

## MITRE ATLAS

`src/vigie/atlas/data/atlas.json` is a reduced copy of the MITRE ATLAS data,
content release 2026.10, from
[mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data)
(`dist/v6/ATLAS-2026.10.yaml`). Only the ids, names, tactics and URLs of the
tactics and techniques are kept.

Copyright 2021-2026 MITRE. Licensed under the Apache License, Version 2.0,
reproduced in [`src/vigie/atlas/data/LICENSE-ATLAS.txt`](src/vigie/atlas/data/LICENSE-ATLAS.txt).
MITRE ATLAS™ is a trademark of The MITRE Corporation.

## OWASP Top 10 for LLM and Agentic Applications

`src/vigie/owasp/mapping.py` lists the ids, names and links of the entries of
the OWASP Top 10 for LLM Applications 2025 and the OWASP Top 10 for Agentic
Applications 2026, from [genai.owasp.org](https://genai.owasp.org). Content of
the OWASP GenAI Security Project, licensed under the Creative Commons
Attribution-ShareAlike 4.0 license
([CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)).

## Test data

| Folder | Source | License |
|---|---|---|
| `tests/fixtures/evtx/` | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden, unmodified files | GPL-3.0, text in [`tests/fixtures/evtx/LICENSE.GPL`](tests/fixtures/evtx/LICENSE.GPL) |
| `tests/fixtures/winjson/` | [Security-Datasets](https://github.com/OTRF/Security-Datasets) by the Open Threat Research Forge, whole-line excerpts | MIT, text in [`tests/fixtures/winjson/LICENSE.MIT`](tests/fixtures/winjson/LICENSE.MIT) |
| `tests/fixtures/authlog/` | Synthetic, written for Vigie | MIT (Vigie's license) |
| `tests/fixtures/agentlog/` | Synthetic, written for Vigie | MIT (Vigie's license) |

The test data is not part of the installed package. Upstream paths, commits,
SHA-256 hashes and kept lines are listed in
[`tests/fixtures/README.md`](tests/fixtures/README.md) and
[`tests/fixtures/evtx/README.md`](tests/fixtures/evtx/README.md).

`docs/example-report.*` and `docs/report-preview.png` were produced by Vigie
from the synthetic auth.log files and the OTRF excerpts only.
`docs/example-report-ai.*` was produced by Vigie from the synthetic agent logs
of `tests/fixtures/agentlog` only.
