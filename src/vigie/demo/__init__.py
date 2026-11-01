"""Sample logs for ``vigie demo``: synthetic AI agent logs and a synthetic Linux auth.log."""

from pathlib import Path

DEMO_LOGS = Path(__file__).parent / "logs"
# The auth.log lines carry no year, like every classic syslog file.
DEMO_YEAR = 2024
