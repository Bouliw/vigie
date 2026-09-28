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

## Test data

| Folder | Source | License |
|---|---|---|
| `tests/fixtures/evtx/` | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden, unmodified files | GPL-3.0, text in [`tests/fixtures/evtx/LICENSE.GPL`](tests/fixtures/evtx/LICENSE.GPL) |
| `tests/fixtures/winjson/` | [Security-Datasets](https://github.com/OTRF/Security-Datasets) by the Open Threat Research Forge, whole-line excerpts | MIT, text in [`tests/fixtures/winjson/LICENSE.MIT`](tests/fixtures/winjson/LICENSE.MIT) |
| `tests/fixtures/authlog/` | Synthetic, written for Vigie | MIT (Vigie's license) |

The test data is not part of the installed package. Upstream paths, commits,
SHA-256 hashes and kept lines are listed in
[`tests/fixtures/README.md`](tests/fixtures/README.md) and
[`tests/fixtures/evtx/README.md`](tests/fixtures/evtx/README.md).

`docs/example-report.*` and `docs/report-preview.png` were produced by Vigie
from the synthetic auth.log files and the OTRF excerpts only.
