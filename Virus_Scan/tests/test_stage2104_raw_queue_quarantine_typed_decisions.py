from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_quarantine import quarantine_job_decision
from Virus_Scan.scheduler.queue.raw_queue_quarantine_decisions import (
    RawQueueQuarantineDecision,
    raw_queue_bool_decision,
    raw_queue_mapping_decision,
)


class HostileBool:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook touched")


class HostileMapping:
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("iter hook touched")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook touched")


def _deps(tmp_path: Path, *, protected=False, payload=None):
    return {
        "active_claim_is_protected": lambda *_args, **_kwargs: protected,
        "quarantine_dir": lambda _queue_dir: tmp_path / "quarantine",
        "read_json_file": lambda _path: {} if payload is None else payload,
        "job_identity": lambda *_args: "job:ok",
        "quarantine_destination": lambda path, *, quarantine_root: (Path(quarantine_root) / Path(path).name, Path(path).parent.name),
        "remove_claim_sidecar_for_terminal_move": lambda *_args, **_kwargs: False,
        "remove_claim_meta": lambda _path: False,
        "cleanup_orphan_claim_sidecars": lambda *_args, **_kwargs: 0,
        "cleanup_orphans": lambda *_args, **_kwargs: 0,
        "orphan_cleanup_max": 0,
        "write_quarantine_sidecar": lambda *_args, **_kwargs: None,
        "quarantine_sidecar_payload": lambda **_kwargs: {},
        "report": lambda *_args, **_kwargs: None,
        "report_issue": lambda *_args, **_kwargs: None,
        "log_error": lambda *_args, **_kwargs: None,
    }


def test_stage2104_raw_queue_bool_and_mapping_decisions_are_typed_and_no_hook() -> None:
    HostileBool.touched = 0
    HostileMapping.touched = 0

    bool_decision = raw_queue_bool_decision(HostileBool(), rejected_reason="hostile_bool_rejected")
    mapping_decision = raw_queue_mapping_decision(HostileMapping(), rejected_reason="hostile_mapping_rejected")

    assert bool_decision.accepted is False
    assert bool_decision.value is False
    assert bool_decision.reason == "hostile_bool_rejected"
    assert mapping_decision.accepted is False
    assert mapping_decision.reason == "hostile_mapping_rejected"
    assert HostileBool.touched == 0
    assert HostileMapping.touched == 0


def test_stage2104_quarantine_missing_job_path_returns_typed_rejection(tmp_path: Path) -> None:
    decision = quarantine_job_decision(tmp_path / "pending" / "missing.json", **_deps(tmp_path))

    assert isinstance(decision, RawQueueQuarantineDecision)
    assert decision.quarantined is False
    assert decision.reason == "queue_quarantine_path_missing_or_not_json"


def test_stage2104_quarantine_active_claim_protection_is_replayable(tmp_path: Path) -> None:
    active = tmp_path / "active"
    active.mkdir()
    path = active / "job.json"
    path.write_text("{}", encoding="utf-8")

    decision = quarantine_job_decision(path, **_deps(tmp_path, protected=True))

    assert decision.quarantined is False
    assert decision.reason == "queue_quarantine_active_claim_protected"


def test_stage2104_quarantine_replace_failure_is_typed(tmp_path: Path) -> None:
    pending = tmp_path / "pending"
    pending.mkdir()
    path = pending / "job.json"
    path.write_text("{}", encoding="utf-8")
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    (quarantine / path.name).mkdir()

    decision = quarantine_job_decision(path, **_deps(tmp_path))

    assert decision.quarantined is False
    assert decision.reason == "queue_quarantine_replace_failed"


def test_stage2104_quarantine_success_preserves_canonical_projection(tmp_path: Path) -> None:
    pending = tmp_path / "pending"
    pending.mkdir()
    path = pending / "job.json"
    path.write_text("{}", encoding="utf-8")

    decision = quarantine_job_decision(path, **_deps(tmp_path))

    assert decision.quarantined is True
    assert decision.reason == "quarantined"
    assert decision.source_state == "pending"
    assert path.exists() is False
