"""Samples for ``vigie demo`` and ``vigie assess --demo``.

Synthetic AI agent logs, a synthetic Linux auth.log, and the generic maturity
questionnaire answered for a fictitious organization.
"""

from pathlib import Path

DEMO_LOGS = Path(__file__).parent / "logs"
DEMO_ASSESSMENT = Path(__file__).parent / "assessment.csv"
# The auth.log lines carry no year, like every classic syslog file.
DEMO_YEAR = 2024
