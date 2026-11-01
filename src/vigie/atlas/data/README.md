# MITRE ATLAS extract

`atlas.json` is a reduced copy of the MITRE ATLAS data: for each tactic and
technique, only the id, name, tactics, URL and the first sentences of the
description (at most 320 characters, as plain text) are kept. Tactics are listed in
the order of the ATLAS matrix, and each one gets a tag name made from its
name (`AI Model Access` becomes `ai-model-access`).

- Source: https://github.com/mitre-atlas/atlas-data
  (`dist/v6/ATLAS-2026.10.yaml`, data format 6.1.0, content release 2026.10)
- Generated with `python tools/build_atlas_data.py --version 2026.10`
- License: Apache License 2.0, reproduced in [`LICENSE-ATLAS.txt`](LICENSE-ATLAS.txt)

Copyright 2021-2026 MITRE. Modified by Vigie: only the fields listed above
are kept, descriptions are shortened to their first sentences; mitigations,
case studies and the other relationships are left out.

MITRE ATLAS™ is a trademark of The MITRE Corporation.
