from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.contracts.queue_snapshot import QueueSnapshot
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section
from Virus_Scan.scheduler.queue.inmemory_result_completion_projection import (
    bad_result_message_text,
    exact_mapping_count,
)
from Virus_Scan.scheduler.queue.raw_queue_failure_audit import summarize_failed_queue_report
from Virus_Scan.scheduler.contracts.replay_result import ReplaySnapshot
from Virus_Scan.scheduler.replay.replay_mismatch import build_replay_mismatches

_TARGETS = (
    "Virus_Scan/scheduler/contracts/queue_snapshot.py",
    "Virus_Scan/scheduler/queue/raw_queue_failure_audit.py",
    "Virus_Scan/scheduler/queue/phase_ledger.py",
    "Virus_Scan/scheduler/queue/orphan_recovery_claim_state.py",
    "Virus_Scan/scheduler/evidence/records.py",
    "Virus_Scan/scheduler/replay/replay_mismatch.py",
    "Virus_Scan/scheduler/queue/inmemory_result_completion_projection.py",
)


def test_stage2212_scheduler_contract_surfaces_do_not_import_or_annotate_any() -> None:
    root = Path(__file__).resolve().parents[2]
    for relative in _TARGETS:
        text = (root / relative).read_text(encoding="utf-8")
        assert "typing import Any" not in text
        assert ": Any" not in text
        assert "[Any" not in text
        assert ", Any" not in text
        assert "Any]" not in text


def test_stage2212_queue_snapshot_and_evidence_still_materialize_replayable_dicts() -> None:
    snapshot = QueueSnapshot.from_mapping(
        {"phase": "collect", "pending": 1, "metadata": {"source": "unit"}}
    )
    payload = snapshot.as_dict()
    assert payload["phase"] == "collect"
    assert payload["pending"] == 1
    assert payload["metadata"] == {"source": "unit"}
    section = build_scheduler_json_evidence_section(())
    assert section["scheduler_status"] == "ok"
    assert section["evidence"] == []


def test_stage2212_projection_failure_audit_and_replay_contracts_remain_runtime_safe() -> None:
    assert bad_result_message_text(object(), 3).endswith(" items=3")
    assert exact_mapping_count({"a": 1, "b": 2}) == 2
    summary = summarize_failed_queue_report(
        [{"job_type": "file", "stage": "failed", "exception_type": "E", "error": "boom"}]
    )
    assert summary == [(("file", "failed", "E", "boom"), 1)]
    empty = ReplaySnapshot(replay_id="empty", records=())
    assert build_replay_mismatches(empty, empty) == ()
