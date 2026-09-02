from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_file_scan_support import owned_cfg_snapshot, worker_non_empty_text
from Virus_Scan.scheduler.workers.inmemory_file_scan_support_evidence import (
    inmemory_worker_config_decision,
    inmemory_worker_text_decision,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileWorkerConfig:
    touched = 0

    def __iter__(self):  # pragma: no cover - invoking this is the defect
        type(self).touched += 1
        raise AssertionError("iteration hook invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str hook invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook invoked")


class HostileWorkerText:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str hook invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook invoked")


def test_stage2152_missing_worker_config_uses_replayable_empty_snapshot() -> None:
    decision = inmemory_worker_config_decision(None)

    assert decision.snapshot == {}
    assert decision.accepted is True
    assert decision.reason == "missing_config_empty_snapshot"
    assert ("decision", "inmemory_worker_config") in decision.evidence
    assert ("item_count", 0) in decision.evidence
    assert owned_cfg_snapshot(None) == {}


def test_stage2152_unsupported_worker_config_is_replayable_without_hooks() -> None:
    HostileWorkerConfig.touched = 0

    decision = inmemory_worker_config_decision(HostileWorkerConfig())

    assert decision.snapshot is None
    assert decision.accepted is False
    assert decision.reason == "inmemory_worker_config_rejected"
    assert ("decision", "inmemory_worker_config") in decision.evidence
    assert ("accepted", False) in decision.evidence
    assert HostileWorkerConfig.touched == 0
    assert owned_cfg_snapshot(HostileWorkerConfig()) is None
    assert HostileWorkerConfig.touched == 0


def test_stage2152_worker_text_rejection_is_replayable_without_hooks() -> None:
    HostileWorkerText.touched = 0

    decision = inmemory_worker_text_decision(HostileWorkerText())

    assert decision.text == ""
    assert decision.accepted is False
    assert decision.reason == "scheduler_text_rejected"
    assert ("decision", "inmemory_worker_text") in decision.evidence
    assert ("accepted", False) in decision.evidence
    assert HostileWorkerText.touched == 0
    assert worker_non_empty_text(HostileWorkerText()) == ""
    assert HostileWorkerText.touched == 0


def test_stage2152_inmemory_file_scan_support_hidden_defaults_removed_from_owner() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_file_scan_support.py"))

    assert "return {}" not in source
    assert "return None" not in source
    assert "return \"\"" not in source
    assert "inmemory_worker_config_decision(cfg).snapshot" in source
    assert "inmemory_worker_text_decision(value).text" in source
