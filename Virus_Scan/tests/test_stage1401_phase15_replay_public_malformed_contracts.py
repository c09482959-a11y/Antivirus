"""Stage 1401: replay public APIs keep malformed inputs explicit and replay-safe."""

from __future__ import annotations

from Virus_Scan.models.api.replay_comparison_contracts import materialize_model_evidence_comparison
from Virus_Scan.models.api.replay_economics_contracts import (
    replay_compress_metadata,
    replay_should_retain,
)
from Virus_Scan.models.api.replay_learning import persist_parent_learning_from_results


class UnsupportedReplayMetadata:
    str_calls = 0

    def __str__(self) -> str:  # pragma: no cover - failure if invoked
        type(self).str_calls += 1
        raise AssertionError("replay metadata must not call caller-owned __str__")


def test_stage1401_replay_comparison_materializer_rejects_non_mapping_without_crashing() -> None:
    materialized = materialize_model_evidence_comparison("not-a-comparison-record")

    assert materialized["matched"] is False
    assert materialized["mismatch_fields"] == ("record",)
    assert materialized["reason"] == "non_mapping_replay_model_comparison_record"
    assert materialized["record_unavailable_reason"] == "non_mapping_replay_model_comparison_record"


def test_stage1401_replay_should_retain_malformed_result_fail_safe_keeps_metadata() -> None:
    assert replay_should_retain("not-a-result-record") is True
    assert replay_should_retain(UnsupportedReplayMetadata()) is True


def test_stage1401_replay_compress_metadata_reports_unsupported_leaf_type() -> None:
    UnsupportedReplayMetadata.str_calls = 0
    compressed = replay_compress_metadata({"meta": UnsupportedReplayMetadata()})

    assert compressed["meta"]["value"] == "<UnsupportedReplayMetadata>"
    assert compressed["meta"]["unavailable_reason"] == "unsupported_replay_metadata_type"
    assert UnsupportedReplayMetadata.str_calls == 0


def test_stage1401_parent_replay_learning_malformed_results_return_degraded_evidence() -> None:
    summary = persist_parent_learning_from_results(UnsupportedReplayMetadata())

    assert summary["errors"] == 1
    assert summary["degraded"] is True
    assert summary["unavailable_reason"] == "non_iterable_parent_replay_results"
