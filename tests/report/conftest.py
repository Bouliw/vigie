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


# A rule tagged with MITRE ATLAS, run on the synthetic auth.log: what it tests is
# the ATLAS mapping in reports, not a detection.
ATLAS_RULE = """\
title: Test Rule Mapped To ATLAS
id: 0f6d3d0e-6f2a-4a51-9b0c-2b1f4f0f7a11
status: test
description: Accepted SSH logins, tagged as if they were an AI agent invoking a tool.
author: Vigie tests
tags:
    - atlas.execution
    - atlas.aml.t0053
    - atlas.aml.t0051.000
logsource:
    product: linux
    service: sshd
detection:
    selection:
        action: ssh_accepted
    condition: selection
level: medium
"""


@pytest.fixture
def atlas_rule(tmp_path):
    path = tmp_path / "rules" / "atlas_rule.yml"
    path.parent.mkdir()
    path.write_text(ATLAS_RULE, encoding="utf-8")
    return path
