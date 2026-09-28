import shutil
from datetime import datetime
from pathlib import Path

import pytest

from vigie.analysis import analyze
from vigie.timeutils import UTC

FIXTURES = Path(__file__).parent.parent / "fixtures"
GENERATED_AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


@pytest.fixture
def analysis_of(tmp_path):
    """Analyze a copy of some fixture files with Vigie's own rules."""

    def run(*relative_paths):
        folder = tmp_path / "logs"
        folder.mkdir(exist_ok=True)
        for relative in relative_paths:
            target = folder / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(FIXTURES / relative, target)
        return analyze(folder, year=2024)

    return run
