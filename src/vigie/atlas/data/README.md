# MITRE ATLAS extract

`atlas.json` is a reduced copy of the MITRE ATLAS data.

- Tactics: id, name, URL and the first sentences of the description (at most
  320 characters), in the order of the ATLAS matrix. Each one gets a tag name
  made from its name (`AI Model Access` becomes `ai-model-access`).
- Techniques: id, name, tactics, URL, that summary, the full description as
  plain text, the maturity (Feasible, Demonstrated or Realized), the
  mitigations that address it with what each one does, the case studies that
  employ it (newest first) and the related techniques (parent, sub-techniques,
  and the techniques most often employed in the same case studies).
- Mitigations and case studies: id, name, URL and summary; type and year for
  the case studies.

- Source: https://github.com/mitre-atlas/atlas-data
  (`dist/v6/ATLAS-2026.10.yaml`, data format 6.1.0, content release 2026.10)
- Generated with `python tools/build_atlas_data.py --version 2026.10`
- License: Apache License 2.0, reproduced in [`LICENSE-ATLAS.txt`](LICENSE-ATLAS.txt)

Copyright 2021-2026 MITRE. Modified by Vigie: only the fields listed above
are kept, Markdown is turned into plain text, summaries are shortened, and the
related techniques are computed from the relationships of the source file.

MITRE ATLAS™ is a trademark of The MITRE Corporation.
