"""Stage 1406: immutable model contracts absorb hostile public mappings."""

from __future__ import annotations

import json
from collections.abc import Mapping

from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)
from Virus_Scan.models.contracts.model_snapshot import (
    make_model_snapshot,
    make_replay_model_comparison_record,
    materialize_model_snapshot,
    materialize_replay_model_comparison_record,
)
from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)


class HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("mapping iteration unavailable")

    def __len__(self):
        raise RuntimeError("mapping length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("mapping item unavailable")

    def get(self, key, default=None):
        raise RuntimeError("mapping get unavailable")

    def keys(self):
        raise RuntimeError("mapping keys unavailable")


class HostileIterable:
    def __iter__(self):
        raise RuntimeError("iteration unavailable")


def _json_safe(value: object) -> None:
    json.dumps(value, sort_keys=True, allow_nan=False)


def test_stage1406_evidence_and_feature_bundle_contracts_absorb_hostile_mappings() -> None:
    evidence = materialize_model_evidence_record(
        make_model_evidence_record(
            HostileMapping(),
            model_name="graph",
            evidence_type="graph_evidence",
            model_version="v1",
        )
    )
    assert evidence["values_unavailable_reason"] == "unreadable_model_evidence_mapping"
    _json_safe(evidence)

    direct_evidence = materialize_model_evidence_record(HostileMapping())
    assert direct_evidence["unavailable_reason"] == "unreadable_model_evidence_mapping"
    _json_safe(direct_evidence)

    bundle = materialize_model_feature_bundle(make_model_feature_bundle(HostileMapping(), model_version="v1"))
    assert bundle["values_unavailable_reason"] == "unreadable_model_feature_mapping"
    _json_safe(bundle)

    direct_bundle = materialize_model_feature_bundle(HostileMapping())
    assert direct_bundle["unavailable_reason"] == "unreadable_model_feature_mapping"
    _json_safe(direct_bundle)


def test_stage1406_failure_probability_and_snapshot_contracts_absorb_hostile_inputs() -> None:
    failure = materialize_model_failure_record(
        make_model_failure_record(
            model_name="temporal",
            failure_type="temporal_failure",
            reason="bad_input",
            affected_fields=HostileIterable(),
            details=HostileMapping(),
        )
    )
    assert failure["details"]["unavailable_reason"] == "unreadable_model_failure_mapping"
    assert failure["affected_fields"] == ()
    _json_safe(failure)

    direct_failure = materialize_model_failure_record(HostileMapping())
    assert direct_failure["unavailable_reason"] == "unreadable_model_failure_mapping"
    _json_safe(direct_failure)

    probability = materialize_probability_record(HostileMapping())
    assert probability["ready"] is False
    assert probability["probability"] is None
    assert probability["probability_unavailable_reason"] == "unreadable_probability_record"
    _json_safe(probability)

    made_probability = make_probability_record(
        ready=True,
        probability=0.5,
        support=1,
        count=1,
        vocab=1,
        smoothing="laplace",
        reason="",
        flow=HostileIterable(),
    )
    assert made_probability["ready"] is False
    assert made_probability["flow_unavailable_reason"] == "unreadable_flow"
    assert made_probability["probability_unavailable_reason"] == "unreadable_flow"
    _json_safe(materialize_probability_record(made_probability))

    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            HostileMapping(),
            model_name="profiles",
            snapshot_type="profile_snapshot",
            model_version="v1",
            failures=HostileIterable(),
        )
    )
    assert snapshot["ready"] is False
    assert snapshot["degraded"] is True
    assert snapshot["values_unavailable_reason"] == "unreadable_model_snapshot_mapping"
    assert snapshot["failures_unavailable_reason"] == "unreadable_model_snapshot_failures"
    _json_safe(snapshot)


def test_stage1406_replay_comparison_contract_absorbs_hostile_mappings() -> None:
    comparison = materialize_replay_model_comparison_record(
        make_replay_model_comparison_record(
            model_name="markov",
            expected=HostileMapping(),
            actual=HostileMapping(),
            matched=True,
            mismatch_fields=HostileIterable(),
        )
    )
    assert comparison["matched"] is False
    assert comparison["expected_unavailable_reason"] == "unreadable_model_snapshot_mapping"
    assert comparison["actual_unavailable_reason"] == "unreadable_model_snapshot_mapping"
    assert comparison["mismatch_fields_unavailable_reason"] == "unreadable_replay_mismatch_fields"
    assert comparison["reason"] == "replay_model_comparison_unavailable"
    _json_safe(comparison)

    direct = materialize_replay_model_comparison_record(HostileMapping())
    assert direct["unavailable_reason"] == "unreadable_model_snapshot_mapping"
    _json_safe(direct)
