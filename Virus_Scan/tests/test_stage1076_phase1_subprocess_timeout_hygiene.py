"""Stage 1076 Phase 1 regression guard for bounded subprocess tests.

Phase 1 timeout remediation requires subprocess-heavy tests to be bounded so a
broken child process is isolated as an explicit test finding instead of hiding
inside a full-suite timeout.
"""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import top_level_test_files, unbounded_subprocess_timeout_findings

from pathlib import Path


def _test_files() -> tuple[Path, ...]:
    return top_level_test_files()


def test_stage1076_subprocess_test_helpers_have_explicit_timeouts() -> None:
    offenders: list[str] = []
    for path in _test_files():
        offenders.extend(unbounded_subprocess_timeout_findings(path))
    assert offenders == []
