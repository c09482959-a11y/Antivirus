"""Stage 1075 Phase 1 regression guards for test-root-cause hygiene.

These checks lock the Phase 1 inventory findings that the repository test tree
must not hide missing functionality behind skip/xfail, monkeypatch-heavy tests,
or assertion-free placeholders.
"""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import assertion_free_test_function_findings, hidden_failure_test_hygiene_findings, top_level_test_files

from pathlib import Path


def _test_files() -> tuple[Path, ...]:
    return top_level_test_files()


def test_stage1075_tests_do_not_hide_failures_with_skip_xfail_or_monkeypatch() -> None:
    offenders: list[str] = []
    for path in _test_files():
        offenders.extend(hidden_failure_test_hygiene_findings(path))
    assert offenders == []


def test_stage1075_tests_are_not_assertion_free_placeholders() -> None:
    offenders: list[str] = []
    for path in _test_files():
        offenders.extend(assertion_free_test_function_findings(path))
    assert offenders == []
