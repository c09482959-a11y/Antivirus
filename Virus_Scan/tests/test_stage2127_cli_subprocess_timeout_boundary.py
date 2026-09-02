from __future__ import annotations

from pathlib import Path


def test_stage2127_stage359_cli_subprocess_timeout_is_full_suite_bounded() -> None:
    source = Path("Virus_Scan/tests/test_stage359_deterministic_integration_runtime.py").read_text(encoding="utf-8")
    assert "_CLI_TIMEOUT_SECONDS = 180" in source
    assert "process.wait(timeout=30)" not in source
    assert "process.wait(timeout=_CLI_TIMEOUT_SECONDS)" in source


def test_stage2127_resource_tracker_subprocess_timeout_is_full_suite_bounded() -> None:
    source = Path("Virus_Scan/tests/test_stage697_scheduler_multiprocessing_context_ownership.py").read_text(encoding="utf-8")
    assert "_RESOURCE_TRACKER_SUBPROCESS_TIMEOUT_SECONDS = 90" in source
    assert "timeout=20" not in source
    assert "timeout=_RESOURCE_TRACKER_SUBPROCESS_TIMEOUT_SECONDS" in source
