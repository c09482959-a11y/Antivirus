from __future__ import annotations

from Virus_Scan.contracts.result_record import EvidenceObjectSnapshot, ResultEvidenceSnapshot


class HostileInt:
    touched = 0

    def __int__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("do not call")

    def __float__(self) -> float:
        type(self).touched += 1
        raise RuntimeError("do not call")

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("do not call")


def test_stage1662_result_snapshot_rejects_nonintegral_float_counts_without_truncation() -> None:
    snapshot = ResultEvidenceSnapshot(
        verdict="malicious",
        score=80.0,
        tags=(),
        chains=(),
        yara_count=2.9,  # type: ignore[arg-type]
        decoded_count="3.7",  # type: ignore[arg-type]
        model_evidence_count=4.0,  # type: ignore[arg-type]
        error_present=False,
        explanation_present=False,
    )

    assert snapshot.yara_count == 0
    assert snapshot.decoded_count == 0
    assert snapshot.model_evidence_count == 4


def test_stage1662_evidence_object_snapshot_rejects_nonintegral_count_without_truncation() -> None:
    assert EvidenceObjectSnapshot("evidence", 2.9).count == 0  # type: ignore[arg-type]
    assert EvidenceObjectSnapshot("evidence", "2.9").count == 0  # type: ignore[arg-type]
    assert EvidenceObjectSnapshot("evidence", 2.0).count == 2  # type: ignore[arg-type]


def test_stage1662_result_count_rejects_hostile_numeric_hooks() -> None:
    HostileInt.touched = 0

    snapshot = ResultEvidenceSnapshot(
        verdict="malicious",
        score=80.0,
        tags=("tag",),
        chains=(),
        yara_count=HostileInt(),  # type: ignore[arg-type]
        decoded_count=HostileInt(),  # type: ignore[arg-type]
        model_evidence_count=HostileInt(),  # type: ignore[arg-type]
        error_present=False,
        explanation_present=False,
    )

    assert snapshot.yara_count == 0
    assert snapshot.decoded_count == 0
    assert snapshot.model_evidence_count == 0
    assert HostileInt.touched == 0


def test_stage1662_bool_count_compatibility_remains_explicit() -> None:
    snapshot = EvidenceObjectSnapshot(key=" evidence ", count=True)  # type: ignore[arg-type]
    assert snapshot.key == "evidence"
    assert snapshot.count == 1
