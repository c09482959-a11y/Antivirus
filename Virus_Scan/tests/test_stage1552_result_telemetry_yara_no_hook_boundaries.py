from __future__ import annotations

from collections.abc import Iterable, Mapping

from Virus_Scan.contracts.result_record import ReplayComparableResultSnapshot, degraded_scan_integrity, scanner_degraded_tags
from Virus_Scan.contracts.stage_event_time import deterministic_stage_event_time
from Virus_Scan.contracts.tag_evidence import safe_tag_evidence_text, validation_text
from Virus_Scan.contracts.telemetry import materialize_telemetry_context, record_detector_error
from Virus_Scan.contracts.worker_record import FailureRecord, make_json_safe
from Virus_Scan.contracts.yara_hits import normalize_yara_hits, normalize_yara_rule_name
from Virus_Scan.models.api.clustering_contracts import _immutable_cluster_value, _public_cluster_sequence
from Virus_Scan.models.api.graph_contracts import _immutable_graph_value, _public_graph_sequence
from Virus_Scan.utils.tagging import ordered_unique_tags


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not format")


class HostileIterable(Iterable):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth test")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate mapping")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len mapping")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not index mapping")

    def keys(self):
        type(self).touched += 1
        raise RuntimeError("do not keys mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items mapping")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get mapping")


class HostilePathLike:
    touched = 0

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not call fspath")


class HostileRuleProperty:
    touched = 0

    @property
    def rule(self):
        type(self).touched += 1
        raise RuntimeError("do not read property")


def _reset() -> None:
    HostileText.touched = 0
    HostileIterable.touched = 0
    HostileMapping.touched = 0
    HostilePathLike.touched = 0
    HostileRuleProperty.touched = 0


def test_telemetry_and_worker_contracts_reject_unknown_objects_without_hooks() -> None:
    _reset()

    context = materialize_telemetry_context(HostileMapping())
    error = record_detector_error(HostileText(), HostileText(), context=HostileMapping(), extra=HostileIterable())
    safe = make_json_safe({"bad_text": HostileText(), "bad_iter": HostileIterable(), "bad_map": HostileMapping()})
    failure = FailureRecord.from_error(HostileText(), HostileText(), domain=HostileText())

    assert context["unavailable_reason"] == "non_materializable_telemetry_context_value"
    assert error["detector"] == "unknown"
    assert error["error"] == "detector_error_unavailable"
    assert safe["bad_text"]["unavailable_reason"] == "non_materializable_worker_output_json_value"
    assert safe["bad_iter"]["unavailable_reason"] == "non_materializable_worker_output_json_value"
    assert safe["bad_map"]["unavailable_reason"] == "non_materializable_worker_output_json_value"
    assert failure.stage == "unknown"
    assert failure.error == "worker_error_unavailable"
    assert HostileText.touched == HostileIterable.touched == HostileMapping.touched == 0


def test_yara_tagging_and_stage_time_boundaries_do_not_call_text_iter_or_path_hooks() -> None:
    _reset()

    assert normalize_yara_rule_name(HostilePathLike()) == ""
    assert normalize_yara_rule_name(HostileRuleProperty()) == ""
    assert normalize_yara_hits(HostileIterable()) == ["yara_hit_normalization_failure_evidence"]
    assert safe_tag_evidence_text(HostileText(), replacement_text="tag_evidence_unavailable") == "tag_evidence_unavailable"
    assert validation_text(HostileText()) == ""
    assert ordered_unique_tags(HostileIterable()) == ["tag_normalization_failure_evidence", "detection_stage_degraded"]
    deterministic_stage_event_time(HostileText(), HostileText(), HostileIterable())

    assert HostileText.touched == HostileIterable.touched == HostilePathLike.touched == HostileRuleProperty.touched == 0


def test_result_replay_and_degraded_helpers_do_not_stringify_or_iterate_unknowns() -> None:
    _reset()

    snapshot = ReplayComparableResultSnapshot(((HostileText(), {"bad": HostileText()}),))
    payload = snapshot.digest_payload()
    tags = scanner_degraded_tags(HostileIterable(), HostileText())
    integrity = degraded_scan_integrity(HostileText())

    assert "replay_canonical_key_0" in payload
    assert payload["replay_canonical_key_0"]["unavailable_reason"] == "invalid_key_type"
    assert "tag_text_unavailable" in tags
    assert "scanner_failure" in tags
    assert integrity["error"] == "result_record_error_unavailable"
    assert HostileText.touched == HostileIterable.touched == 0


def test_public_graph_and_cluster_contracts_reject_unknown_mapping_iterables_without_hooks() -> None:
    _reset()

    graph_mapping = _immutable_graph_value(HostileMapping())
    cluster_mapping = _immutable_cluster_value(HostileMapping())
    graph_seq, graph_reason = _public_graph_sequence(HostileIterable())
    cluster_seq, cluster_reason = _public_cluster_sequence(HostileIterable())

    assert graph_mapping["unavailable_reason"] == "unsupported_public_mapping"
    assert cluster_mapping["unavailable_reason"] == "unsupported_public_mapping"
    assert graph_seq == ()
    assert graph_reason == "unsupported_graph_public_iterable_sequence"
    assert cluster_seq == ()
    assert cluster_reason == "unsupported_cluster_vector_iterable"
    assert HostileMapping.touched == HostileIterable.touched == 0
