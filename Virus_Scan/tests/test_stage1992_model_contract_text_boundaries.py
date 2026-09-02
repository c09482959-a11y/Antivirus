from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    _boolean_flag,
    _nonnegative_support_metric,
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)
from Virus_Scan.models.contracts.model_snapshot import (
    make_model_snapshot,
    materialize_model_snapshot,
)
from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)
from Virus_Scan.models.contracts.text_boundaries import (
    model_contract_field_reason,
    model_contract_metric_reason,
    model_contract_type_label,
    model_contract_unavailable_reason_key,
    model_contract_unavailable_summary_reason,
)


CONTRACT_FILES = (
    Path("Virus_Scan/models/contracts/model_evidence.py"),
    Path("Virus_Scan/models/contracts/model_failure.py"),
    Path("Virus_Scan/models/contracts/model_feature_bundle.py"),
    Path("Virus_Scan/models/contracts/model_snapshot.py"),
    Path("Virus_Scan/models/contracts/probability_record.py"),
)


class HostileText:
    def __str__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, format_spec: str) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __format__ executed")

    def __bool__(self) -> bool:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned __bool__ executed")


class HostileMappingKey:
    def __str__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned key __str__ executed")

    def __repr__(self) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned key __repr__ executed")

    def __format__(self, format_spec: str) -> str:  # pragma: no cover - must never be reached
        raise AssertionError("caller-owned key __format__ executed")



def test_stage1992_model_contract_reason_builders_are_no_hook() -> None:
    hostile = HostileText()

    assert model_contract_type_label(hostile) == "<HostileText>"
    assert model_contract_field_reason("blank", hostile) == "blank_unknown_field"
    assert model_contract_metric_reason("non_numeric", hostile) == "non_numeric_unknown_field_metric"
    assert model_contract_unavailable_reason_key(hostile) == "unknown_model_field_unavailable_reason"
    assert model_contract_unavailable_summary_reason("score_unavailable_reason") == "score_unavailable"



def test_stage1992_model_contract_records_emit_explicit_reasons_without_hook_execution() -> None:
    hostile = HostileText()
    hostile_key = HostileMappingKey()

    evidence = materialize_model_evidence_record(
        make_model_evidence_record(
            {"score": float("nan"), hostile_key: hostile},
            model_name=hostile,
            evidence_type="",
            model_version=hostile,
        )
    )
    assert evidence["model_name_unavailable_reason"] == "unreadable_model_name"
    assert evidence["evidence_type_unavailable_reason"] == "blank_evidence_type"
    assert evidence["score_unavailable_reason"] == "non_finite_model_evidence"
    assert evidence["<HostileMappingKey>"]["unavailable_reason"] == "unsupported_model_evidence_value"

    failure = materialize_model_failure_record(
        make_model_failure_record(
            model_name=hostile,
            failure_type="",
            reason=hostile,
            affected_fields=[hostile],
            degraded=hostile,
            output_affecting=hostile,
            details={"x": float("nan")},
            model_version="",
        )
    )
    assert failure["model_name_unavailable_reason"] == "unreadable_model_name"
    assert failure["failure_type_unavailable_reason"] == "blank_failure_type"
    assert failure["degraded_unavailable_reason"] == "non_boolean_degraded"
    assert failure["output_affecting_unavailable_reason"] == "non_boolean_output_affecting"
    assert failure["details"]["x_unavailable_reason"] == "non_finite_model_failure_detail"
    assert _nonnegative_support_metric(hostile, field_name=hostile) == (
        0,
        "non_numeric_unknown_field_metric",
    )
    assert _boolean_flag(hostile, field_name=hostile, default=True) == (
        True,
        "non_boolean_unknown_field",
    )

    features = materialize_model_feature_bundle(
        make_model_feature_bundle({"x": float("nan"), hostile_key: hostile}, model_version=hostile)
    )
    assert features["model_version_unavailable_reason"] == "unreadable_model_version"
    assert features["x_unavailable_reason"] == "non_finite_model_feature"
    assert features["<HostileMappingKey>"]["unavailable_reason"] == "unsupported_model_feature_value"

    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            model_name=hostile,
            snapshot_type=hostile,
            ready=hostile,
            values={"x": float("nan"), hostile_key: hostile},
            reason=hostile,
            failures=[hostile],
            degraded=hostile,
            model_version=hostile,
        )
    )
    assert snapshot["model_name_unavailable_reason"] == "non_text_model_name"
    assert snapshot["ready_unavailable_reason"] == "non_boolean_ready"
    assert snapshot["values"]["x_unavailable_reason"] == "non_finite_model_snapshot_value"
    assert snapshot["values"]["<HostileMappingKey>"]["unavailable_reason"] == "unsupported_model_snapshot_value"

    probability = materialize_probability_record(
        make_probability_record(
            ready=hostile,
            probability=hostile,
            support=hostile,
            count=hostile,
            vocab=hostile,
            smoothing=hostile,
            reason=hostile,
            source=hostile,
            target=hostile,
            flow=[hostile],
            model_version=hostile,
        )
    )
    assert probability["ready_unavailable_reason"] == "non_boolean_ready_flag"
    assert probability["support_unavailable_reason"] == "non_numeric_support_metric"
    assert probability["count_unavailable_reason"] == "non_numeric_count_metric"
    assert probability["vocab_unavailable_reason"] == "non_numeric_vocab_metric"
    assert probability["source_unavailable_reason"] == "non_text_source"
    assert probability["flow_unavailable_reason"] == "non_text_flow_item"



def test_stage1992_contract_source_no_longer_contains_repaired_hook_strings() -> None:
    forbidden = (
        'f"<{no_hook_type_name(value)}>"',
        'f"blank_{field_name}"',
        'f"unreadable_{field_name}"',
        'f"non_text_{field_name}"',
        'f"missing_{field_name}"',
        'f"non_boolean_{field_name}"',
        'f"non_numeric_{field_name}_metric"',
        'f"non_finite_{field_name}_metric"',
        'f"negative_{field_name}_metric"',
        'f"non_integer_{field_name}_metric"',
        'f"{name}_unavailable_reason"',
        'f"{field_name}_unavailable_reason"',
    )
    for path in CONTRACT_FILES:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            assert pattern not in text, (path, pattern)
