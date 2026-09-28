"""Detection rules shipped with Vigie, as Sigma YAML files.

``windows/`` and ``linux/`` hold one rule per file. Rules adapted from the
SigmaHQ project keep their original authors, link and license (Detection Rule
License 1.1, see ``LICENSE.DRL-1.1.md``); the other rules are covered by
Vigie's MIT license.
"""

from pathlib import Path

RULES_DIR = Path(__file__).parent
