from collections.abc import Mapping

from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)
from Virus_Scan.models.profiles.baseline import (
    profile_model_failure_record,
    profile_model_unavailable,
)
from Virus_Scan.models.profiles.timeline import profile_timeline_unavailable


class HostileReason(str):
    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise RuntimeError("caller-owned reason truthiness executed")

    def strip(self, *args, **kwargs):
        return self


class HostileCount:
    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise RuntimeError("caller-owned count truthiness executed")

    def __float__(self):
        return 7.0


class HostileDetails(Mapping):
    def __init__(self):
        self._data = {"proof": "present"}

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise RuntimeError("caller-owned details truthiness executed")


def test_stage1510_probability_record_reason_materialization_does_not_truthiness_probe_unavailable_reason():
    record = {
        "ready": False,
        "probability": None,
        "support": 0,
        "count": 0,
        "vocab": 0,
        "smoothing": "none",
        "reason": "",
        "model_version": "probability_record_v1",
        "probability_unavailable_reason": HostileReason("hostile_probability_unavailable"),
    }

    materialized = materialize_probability_record(record)

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["probability_unavailable_reason"] == "hostile_probability_unavailable"
    assert materialized["reason"] == "hostile_probability_unavailable"


def test_stage1510_probability_record_constructor_preserves_hostile_reason_without_boolean_fallback():
    record = make_probability_record(
        ready=True,
        probability=None,
        support=3,
        count=3,
        vocab=2,
        smoothing="laplace",
        reason=HostileReason("caller_cold_start"),
        model_version="probability_record_v1",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "caller_cold_start"
    assert record["probability_unavailable_reason"] == "ready_probability_missing"


def test_stage1510_profile_unavailable_records_do_not_truthiness_probe_reason_or_count():
    vector = profile_model_unavailable(HostileReason("vector_snapshot_corrupt"), count=HostileCount())
    timeline = profile_timeline_unavailable(HostileReason("timeline_snapshot_corrupt"), sample_count=HostileCount())

    assert vector["reason"] == "vector_snapshot_corrupt"
    assert vector["count"] == 0
    assert timeline["reason"] == "timeline_snapshot_corrupt"
    assert timeline["sample_count"] == 0
    assert timeline["final_json_must_record"] is True
    assert timeline["replay_record_required"] is True


def test_stage1510_profile_model_failure_record_does_not_truthiness_probe_details_mapping():
    record = profile_model_failure_record(
        "profiles",
        "profile_boundary_failed",
        HostileReason("profile_details_degraded"),
        details=HostileDetails(),
    )

    assert record["reason"] == "profile_details_degraded"
    assert record["details"] == {"proof": "present"}

from Virus_Scan.models.contracts.model_evidence import make_model_evidence_record
from Virus_Scan.models.contracts.model_feature_bundle import make_model_feature_bundle
from Virus_Scan.models.contracts.model_snapshot import make_model_snapshot


def test_stage1510_generic_model_contract_text_fields_do_not_truthiness_probe_str_subclasses():
    evidence = make_model_evidence_record(
        {"metric": 1.0},
        model_name=HostileReason("markov"),
        evidence_type=HostileReason("probability"),
        model_version=HostileReason("evidence_v1"),
    )
    bundle = make_model_feature_bundle(
        {"score": 0.25},
        model_version=HostileReason("feature_bundle_v1"),
    )
    snapshot = make_model_snapshot(
        {"count": 3},
        model_name=HostileReason("runtime_model_state"),
        snapshot_type=HostileReason("immutable_snapshot"),
        model_version=HostileReason("snapshot_v1"),
        ready=False,
        degraded=True,
        reason=HostileReason("cold_start"),
    )

    assert evidence["model_name"] == "markov"
    assert evidence["evidence_type"] == "probability"
    assert evidence["model_version"] == "evidence_v1"
    assert bundle["model_version"] == "feature_bundle_v1"
    assert snapshot["model_name"] == "runtime_model_state"
    assert snapshot["snapshot_type"] == "immutable_snapshot"
    assert snapshot["model_version"] == "snapshot_v1"
    assert snapshot["reason"] == "cold_start"
