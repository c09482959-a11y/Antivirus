from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.replay.replay_snapshot import hybrid_queue_state_get, validate_hybrid_counts
from Virus_Scan.scheduler.replay.replay_snapshot_evidence import (
    hybrid_count_value_decision,
    hybrid_counts_items_decision,
    hybrid_snapshot_read_missing_decision,
)


def test_stage2157_missing_hybrid_count_value_is_replayable_decision() -> None:
    decision = hybrid_count_value_decision(None)

    assert decision.value == 0
    assert decision.reason == "hybrid_queue_count_value_missing"
    assert decision.accepted is False
    assert decision.missing is True
    assert dict(validate_hybrid_counts({"done": None})) == {"done": 0}


def test_stage2157_missing_hybrid_count_mapping_is_replayable_decision() -> None:
    decision = hybrid_counts_items_decision(None)

    assert decision.items == ()
    assert decision.reason == "hybrid_queue_count_mapping_missing"
    assert decision.accepted is False
    assert decision.missing is True
    assert tuple(validate_hybrid_counts(None)) == ()


def test_stage2157_missing_hybrid_snapshot_file_is_replayable_decision(tmp_path: Path) -> None:
    state_path = tmp_path / "hybrid_queue_state.json"
    decision = hybrid_snapshot_read_missing_decision(state_path)

    assert decision.snapshot is None
    assert decision.reason == "hybrid_queue_state_file_missing"
    assert decision.available is False
    assert decision.path == state_path
    assert hybrid_queue_state_get(tmp_path) is None
