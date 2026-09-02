from __future__ import annotations

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.records import (
    SchedulerEvidenceBundle,
    build_scheduler_evidence_bundle,
    build_scheduler_json_evidence_section,
)


class HostileBoundaryValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not len")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("do not items")


def _record() -> SchedulerEvidenceRecord:
    return SchedulerEvidenceRecord(
        stage="scheduler_evidence_section",
        state="degraded",
        error_category="stage1627_probe",
        message="probe",
    )


def test_stage1627_scheduler_json_section_rejects_hostile_checkpoint_and_replay_without_bool_hooks() -> None:
    HostileBoundaryValue.reset()
    hostile_checkpoint = HostileBoundaryValue()
    hostile_replay = HostileBoundaryValue()

    section = build_scheduler_json_evidence_section(
        (_record(),),
        checkpoint_status=hostile_checkpoint,
        replay_status=hostile_replay,
    )

    assert HostileBoundaryValue.touched == 0
    assert section["scheduler_status"] == "degraded"
    assert section["checkpoint"]["unsupported_scheduler_value"] is True
    assert section["checkpoint"]["field_name"] == "scheduler_value"
    assert section["replay_comparison_result"]["unsupported_scheduler_value"] is True
    assert section["replay_comparison_result"]["field_name"] == "scheduler_value"


def test_stage1627_scheduler_evidence_bundle_rejects_hostile_records_without_iterating() -> None:
    HostileBoundaryValue.reset()

    bundle = SchedulerEvidenceBundle(records=HostileBoundaryValue())  # type: ignore[arg-type]
    section = bundle.as_dict()

    assert HostileBoundaryValue.touched == 0
    assert bundle.fatal is True
    assert section["scheduler_status"] == "fatal"
    assert section["evidence"][0]["error_category"] == "scheduler_evidence_source_rejected"


def test_stage1627_scheduler_evidence_bundle_builder_does_not_bool_status_inputs() -> None:
    HostileBoundaryValue.reset()

    bundle = build_scheduler_evidence_bundle(
        _record(),
        checkpoint_status=HostileBoundaryValue(),
        replay_status=HostileBoundaryValue(),
    )
    section = bundle.as_dict()

    assert HostileBoundaryValue.touched == 0
    assert section["scheduler_status"] == "degraded"
    assert section["checkpoint"]["scheduler_mapping_unavailable"] is True
    assert section["checkpoint"]["reason"] == "non_materializable_scheduler_mapping"
    assert section["replay_comparison_result"]["scheduler_mapping_unavailable"] is True
    assert section["replay_comparison_result"]["reason"] == "non_materializable_scheduler_mapping"
