from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_duplicate_evidence import (
    RawQueueDuplicateClaimNameDecision,
    RawQueueDuplicateMappingDecision,
    RawQueueDuplicateTextDecision,
    raw_queue_duplicate_claim_name,
    raw_queue_duplicate_job_mapping,
    raw_queue_duplicate_name_text,
)
from Virus_Scan.scheduler.queue.raw_queue_duplicates import duplicate_live_guard
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileDuplicateMapping:
    touched = 0

    def __bool__(self) -> bool:  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("duplicate mapping called __bool__")

    def __iter__(self) -> Iterator[object]:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate mapping called __iter__")

    def __str__(self) -> str:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate mapping called __str__")

    def __repr__(self) -> str:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate mapping called __repr__")


class HostileDuplicateName:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __str__")

    def __repr__(self) -> str:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __repr__")

    def __format__(self, _spec: object) -> str:  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("duplicate name called __format__")


def test_stage2147_duplicate_input_materializers_return_replayable_typed_decisions(tmp_path: Path) -> None:
    mapping_decision = raw_queue_duplicate_job_mapping(HostileDuplicateMapping())
    assert type(mapping_decision) is RawQueueDuplicateMappingDecision
    assert mapping_decision.accepted is False
    assert mapping_decision.reason == "raw_queue_duplicate_job_mapping_rejected"
    assert mapping_decision.mapping == {}

    name_decision = raw_queue_duplicate_name_text(HostileDuplicateName())
    assert type(name_decision) is RawQueueDuplicateTextDecision
    assert name_decision.accepted is False
    assert name_decision.reason == "unsafe_raw_queue_duplicate_name_rejected"
    assert name_decision.text == ""

    claim_decision = raw_queue_duplicate_claim_name(tmp_path / "active" / "claim.json")
    assert type(claim_decision) is RawQueueDuplicateClaimNameDecision
    assert claim_decision.accepted is True
    assert claim_decision.name == "claim.json"
    assert HostileDuplicateMapping.touched == 0
    assert HostileDuplicateName.touched == 0


def test_stage2147_duplicate_guard_rejects_current_job_mapping_without_hidden_empty_identity(tmp_path: Path) -> None:
    reports: list[tuple[str, dict[str, object]]] = []
    claim = tmp_path / "active" / "claim.json"
    claim.parent.mkdir(parents=True)
    claim.write_text("{}", encoding="utf-8")

    allowed = duplicate_live_guard(
        tmp_path,
        claim,
        HostileDuplicateMapping(),
        job_identity=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("job_identity must not run")),
        job_dirs=lambda _queue_dir: (_ for _ in ()).throw(AssertionError("job_dirs must not run")),
        safe_listdir=lambda _directory: (_ for _ in ()).throw(AssertionError("safe_listdir must not run")),
        is_job_json_name=lambda _name: True,
        read_json=lambda *_args, **_kwargs: {},
        merge_claim_meta=lambda _path, record=None: record or {},
        quarantine_job=lambda *_args, **_kwargs: True,
        report=lambda where, _exc, **kwargs: reports.append((where, kwargs)),
    )

    assert allowed is False
    assert reports[0][0] == "queue_duplicate_live_guard_job_mapping_rejected"
    assert reports[0][1]["extra"]["reason"] == "raw_queue_duplicate_job_mapping_rejected"
    assert reports[0][1]["extra"]["claim_path"].endswith("claim.json")
    assert HostileDuplicateMapping.touched == 0


def test_stage2147_raw_queue_duplicate_source_removed_hidden_default_returns() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_duplicates.py"))

    assert "return {}" not in source
    assert "return \"\"" not in source
    assert "return None" not in source
    assert "def _job_mapping(value: object) -> RawQueueDuplicateMappingDecision" in source
    assert "raw_queue_duplicate_job_mapping(value)" in source
    assert "queue_duplicate_live_guard_job_mapping_rejected" in source
