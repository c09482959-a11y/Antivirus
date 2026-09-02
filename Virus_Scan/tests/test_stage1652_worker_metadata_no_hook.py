from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.metadata import attach_worker_metadata, build_worker_metadata_annotation


class HostileWorkerMetadataValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not test truthiness")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not format")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not float")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("worker metadata must not iterate")


def test_stage1652_build_worker_metadata_rejects_hostile_fields_without_hooks() -> None:
    HostileWorkerMetadataValue.reset()

    annotation = build_worker_metadata_annotation(
        scheduler_mode=HostileWorkerMetadataValue(),
        worker_id=HostileWorkerMetadataValue(),
        worker_pid=HostileWorkerMetadataValue(),
    )
    payload = annotation.as_dict()

    assert HostileWorkerMetadataValue.touched == 0
    assert payload["scheduler_mode"] == "unknown"
    assert payload["worker_id"] == "worker"
    assert "worker_pid" not in payload
    reasons = {item["reason"] for item in payload["worker_metadata_evidence"]}
    assert "worker_scheduler_mode_rejected" in reasons
    assert "worker_id_rejected" in reasons
    assert "worker_pid_rejected" in reasons


def test_stage1652_attach_worker_metadata_rejects_hostile_result_secondary_values_without_hooks() -> None:
    HostileWorkerMetadataValue.reset()

    result = attach_worker_metadata(
        {
            "file": "sample.bin",
            "scheduler_mode": HostileWorkerMetadataValue(),
            "worker_id": HostileWorkerMetadataValue(),
        },
        scheduler_mode=None,
        worker_id=None,
        worker_pid="123",
    )

    assert HostileWorkerMetadataValue.touched == 0
    assert result["scheduler_mode"] == "unknown"
    assert result["worker_id"] == "worker"
    assert result["worker_pid"] == 123
    reasons = {item["reason"] for item in result["worker_metadata_evidence"]}
    assert "worker_scheduler_mode_rejected_secondary" in reasons
    assert "worker_id_rejected_secondary" in reasons


def test_stage1652_attach_worker_metadata_preserves_exact_valid_values() -> None:
    result = attach_worker_metadata(
        {"file": "sample.bin"},
        scheduler_mode="process",
        worker_id="w1",
        worker_pid="456",
    )

    assert result["scheduler_mode"] == "process"
    assert result["worker_id"] == "w1"
    assert result["worker_pid"] == 456
    assert "worker_metadata_evidence" not in result


def test_stage1959_worker_metadata_source_has_no_fallback_default_or_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "metadata.py").read_text(encoding="utf-8")

    forbidden = (
        "fallback",
        'f"',
        "f'",
        "default=",
        "scheduler_int",
        "fallback_value",
        "fallback_scheduler_mode",
        "fallback_worker_id",
    )
    for snippet in forbidden:
        assert snippet not in source
