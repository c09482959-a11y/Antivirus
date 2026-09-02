import ast
import json
from pathlib import Path

from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    make_cold_start_record,
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)
from Virus_Scan.models.contracts.model_snapshot import make_model_snapshot, materialize_model_snapshot


class HostileText:
    def __str__(self):
        raise RuntimeError("string unavailable")

    def __repr__(self):
        raise RuntimeError("repr unavailable")


class HostileIterable:
    def __iter__(self):
        raise RuntimeError("iterator unavailable")


def test_stage1411_model_contracts_have_no_broad_exception_handlers():
    paths = (
        Path("Virus_Scan/models/contracts/model_evidence.py"),
        Path("Virus_Scan/models/contracts/model_failure.py"),
        Path("Virus_Scan/models/contracts/model_feature_bundle.py"),
        Path("Virus_Scan/models/contracts/model_snapshot.py"),
    )
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        broad_handlers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            is_broad = node.type is None or (
                isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
            )
            if is_broad:
                broad_handlers.append(node.lineno)
        assert broad_handlers == [], path


def test_stage1411_evidence_and_feature_metadata_failures_are_explicit_and_json_safe():
    evidence = materialize_model_evidence_record(
        make_model_evidence_record(
            {"score": 0.25},
            model_name=HostileText(),
            evidence_type=HostileText(),
            model_version=HostileText(),
        )
    )
    feature_bundle = materialize_model_feature_bundle(
        make_model_feature_bundle({"feature": 1.0}, model_version=HostileText())
    )

    assert evidence["model_name"] == "unknown_model"
    assert evidence["model_name_unavailable_reason"] == "unreadable_model_name"
    assert evidence["evidence_type_unavailable_reason"] == "unreadable_evidence_type"
    assert evidence["model_version_unavailable_reason"] == "unreadable_model_version"
    assert feature_bundle["model_version"] == "model_feature_bundle_v1"
    assert feature_bundle["model_version_unavailable_reason"] == "unreadable_model_version"
    json.dumps({"evidence": evidence, "feature_bundle": feature_bundle}, sort_keys=True)


def test_stage1411_failure_metadata_and_affected_fields_failures_are_explicit():
    failure = materialize_model_failure_record(
        make_model_failure_record(
            model_name=HostileText(),
            failure_type=HostileText(),
            reason=HostileText(),
            model_version=HostileText(),
            affected_fields=HostileIterable(),
            details={"safe": True},
        )
    )
    cold_start = materialize_model_failure_record(
        make_cold_start_record(
            model_name=HostileText(),
            reason=HostileText(),
            model_version=HostileText(),
            affected_fields=HostileIterable(),
        )
    )

    assert failure["model_name"] == "unknown_model"
    assert failure["failure_type"] == "unknown_failure"
    assert failure["reason"] == "model_failure"
    assert failure["model_name_unavailable_reason"] == "unreadable_model_name"
    assert failure["failure_type_unavailable_reason"] == "unreadable_failure_type"
    assert failure["reason_unavailable_reason"] == "unreadable_reason"
    assert failure["model_version_unavailable_reason"] == "unreadable_model_version"
    assert failure["affected_fields_unavailable_reason"] == "unreadable_model_failure_iterable"
    assert cold_start["model_name_unavailable_reason"] == "unreadable_model_name"
    assert cold_start["reason_unavailable_reason"] == "unreadable_reason"
    assert cold_start["model_version_unavailable_reason"] == "unreadable_model_version"
    assert cold_start["affected_fields_unavailable_reason"] == "unreadable_model_failure_iterable"
    json.dumps({"failure": failure, "cold_start": cold_start}, sort_keys=True)


def test_stage1411_snapshot_metadata_still_degrades_hostile_values_without_broad_handlers():
    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            {"hostile": HostileText()},
            model_name=HostileText(),
            snapshot_type=HostileText(),
            model_version=HostileText(),
            ready=HostileText(),
            degraded=HostileText(),
            reason=HostileText(),
            failures=HostileIterable(),
        )
    )

    assert snapshot["ready"] is False
    assert snapshot["degraded"] is True
    assert snapshot["failures_unavailable_reason"] == "unreadable_model_snapshot_failures"
    assert snapshot["model_name_unavailable_reason"] == "non_text_model_name"
    assert snapshot["values"]["hostile"]["unavailable_reason"] == "unsupported_model_snapshot_value"
    json.dumps(snapshot, sort_keys=True)

from collections.abc import Mapping

from Virus_Scan.models.api import clustering_contracts


class HostileLookupMapping(Mapping):
    def __iter__(self):
        raise KeyError("iter unavailable")

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise KeyError("getitem unavailable")

    def keys(self):
        raise KeyError("keys unavailable")


class ReadableBaselineMapping(Mapping):
    def __init__(self, values):
        self._values = dict(values)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __getitem__(self, key):
        return self._values[key]

    def keys(self):
        return self._values.keys()


def test_stage1411_cluster_vector_update_rejects_unknown_readable_mapping_without_mapping_hooks():
    updated = clustering_contracts.online_vector_update(
        ReadableBaselineMapping({"count": 1, "mean": (1.0, 1.0), "m2": (0.0, 0.0)}),
        (3.0, 5.0),
        feature_names=("a", "b"),
    )

    assert updated["degraded"] is True
    assert updated["unavailable_reason"] == "unreadable_cluster_baseline_mapping"


def test_stage1411_cluster_vector_update_unreadable_mapping_is_explicit_degraded_evidence():
    updated = clustering_contracts.online_vector_update(
        HostileLookupMapping(),
        (1.0, 2.0),
        feature_names=("a", "b"),
    )

    assert updated["degraded"] is True
    assert updated["unavailable_reason"] == "unreadable_cluster_baseline_mapping"
    assert updated["cluster_unavailable_reason"] == "unreadable_cluster_baseline_mapping"
    assert updated["final_json_must_record"] is True
    assert updated["replay_record_required"] is True
    json.dumps(dict(updated), sort_keys=True)
