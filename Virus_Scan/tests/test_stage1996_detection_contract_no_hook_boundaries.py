"""Stage 1996: detection contract producers reject hostile boundary hooks."""
from __future__ import annotations

from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

import pytest

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.detection.contracts.binary_predicates import strict_fast_file_is_boring_text
from Virus_Scan.detection.contracts.filetype_context import filetype_validation_context
from Virus_Scan.detection.contracts.path_predicates import binary_ext_for_attack_cap
from Virus_Scan.detection.contracts.string_predicates import ascii_visibility_ratio, validate_high_risk_tag
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path
from Virus_Scan.detection.evidence.static_bytes import find_known_eof_offset, stage_read_bytes
from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    detection_cluster_projection,
    detection_temporal_history_timeline,
    detection_temporal_snapshot,
)
from Virus_Scan.detection.correlation.multi_signal.correlation_analysis import counterfactual_suppression_analysis
from Virus_Scan.detection.correlation.multi_signal.correlation_groups import infer_correlation_group
from Virus_Scan.detection.correlation.multi_signal.model_context import build_detection_model_context
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.enrichment.prefilter.scan import strict_fast_prefilter
from Virus_Scan.detection.scoring.weighting.prefilter_risk import _current_score_value, _read_prefilter_strings
from Virus_Scan.detection.tags.heuristics.archive_intent import classify_archive_intent_tags


class HostilePath:
    def __bool__(self) -> bool:
        raise AssertionError("hostile truthiness hook executed")

    def __fspath__(self) -> str:
        raise AssertionError("hostile fspath hook executed")

    def __str__(self) -> str:
        raise AssertionError("hostile str hook executed")


class HostileMapping(Mapping):
    def __iter__(self) -> Iterator[Any]:
        raise AssertionError("hostile mapping iteration executed")

    def __len__(self) -> int:
        raise AssertionError("hostile mapping length executed")

    def __getitem__(self, key: Any) -> Any:
        raise AssertionError("hostile mapping getitem executed")

    def get(self, key: Any, default: Any = None) -> Any:
        raise AssertionError("hostile mapping get executed")

    def items(self):
        raise AssertionError("hostile mapping items executed")


class HostileIterable:
    def __iter__(self):
        raise AssertionError("hostile iterable hook executed")


class HostileText:
    def __str__(self) -> str:
        raise AssertionError("hostile text hook executed")


class HostileNumber:
    def __bool__(self) -> bool:
        raise AssertionError("hostile number truthiness hook executed")

    def __float__(self) -> float:
        raise AssertionError("hostile float hook executed")


class HostileBytes:
    def __bool__(self) -> bool:
        raise AssertionError("hostile bytes truthiness hook executed")

    def __bytes__(self) -> bytes:
        raise AssertionError("hostile bytes hook executed")


def test_stage1996_binary_and_path_predicates_reject_hostile_paths_without_hooks() -> None:
    is_boring, meta = strict_fast_file_is_boring_text(HostilePath())

    assert is_boring is False
    assert meta == {"extension": ""}
    assert binary_ext_for_attack_cap(HostilePath()) is False
    assert binary_ext_for_attack_cap(Path("sample.exe")) is True


def test_stage1996_filetype_context_rejects_hostile_registry_mappings() -> None:
    def fake_registry_value(name: str, default: Any) -> Any:
        if name == "ENGINE_SPECIFIC_FILETYPE_BUCKETS":
            return {
                "media": {
                    "asset_audio": {
                        "extensions": ("ogg",),
                        "execution_capability": HostileText(),
                        "normal_buckets": HostileIterable(),
                        "rare_buckets": (),
                        "high_risk_buckets": (),
                    }
                },
                "other": HostileMapping(),
            }
        if name == "GLOBAL_COMMON_FILETYPE_BUCKETS":
            return {
                "global_audio": {
                    "extensions": ("ogg",),
                    "execution_capability": HostileText(),
                    "normal_buckets": HostileIterable(),
                    "rare_buckets": (),
                    "high_risk_buckets": (),
                }
            }
        return default

    with patch(
        "Virus_Scan.detection.contracts.filetype_context.detection_registry_value",
        fake_registry_value,
    ):
        context = filetype_validation_context(HostileText(), Path("soundtrack.ogg"))

    assert context["active_bucket"] == "global_audio"
    assert context["execution_capability"] == "unknown"
    assert "filetype_bucket_unavailable" in context["normal_buckets"]


def test_stage2226_filetype_context_records_unavailable_extension_policy() -> None:
    def fake_registry_value(name: str, default: Any) -> Any:
        if name == "ENGINE_SPECIFIC_FILETYPE_BUCKETS":
            return {}
        if name == "GLOBAL_COMMON_FILETYPE_BUCKETS":
            return {
                "global_audio": {
                    "extensions": HostileMapping(),
                    "execution_capability": "none",
                    "normal_buckets": (),
                    "rare_buckets": (),
                    "high_risk_buckets": (),
                }
            }
        return default

    with patch(
        "Virus_Scan.detection.contracts.filetype_context.detection_registry_value",
        fake_registry_value,
    ):
        context = filetype_validation_context("media", Path("soundtrack.ogg"))

    assert context["active_bucket"] == "unknown_global"
    assert context["filetype_policy_unavailable"] is True
    assert context["reason"] == "policy_sequence_backing_missing"
    assert context["replay_must_record"] is True


def test_stage2226_filetype_context_records_unavailable_top_level_policy() -> None:
    def fake_registry_value(name: str, default: Any) -> Any:
        if name == "ENGINE_SPECIFIC_FILETYPE_BUCKETS":
            return {}
        if name == "GLOBAL_COMMON_FILETYPE_BUCKETS":
            return HostileMapping()
        return default

    with patch(
        "Virus_Scan.detection.contracts.filetype_context.detection_registry_value",
        fake_registry_value,
    ):
        context = filetype_validation_context("media", Path("soundtrack.ogg"))

    assert context["active_bucket"] == "unknown_global"
    assert context["filetype_policy_unavailable"] is True
    assert context["reason"] == "policy_mapping_backing_missing"
    assert context["field_name"] == "_data"


def test_stage1996_adaptive_scoring_does_not_format_caught_exceptions() -> None:
    adaptive_dir = Path("Virus_Scan/detection/scoring/adaptive")
    offenders = []
    for source_path in adaptive_dir.glob("*.py"):
        source = source_path.read_text(encoding="utf-8")
        if "log_error(f" in source:
            offenders.append(source_path.as_posix())

    assert offenders == []


def test_stage1996_model_projections_reject_hostile_events_without_hooks() -> None:
    events = [HostileMapping(), {"tag": HostileText(), "stage": HostileText(), "time": HostileText()}]

    snapshot = detection_temporal_snapshot(HostilePath(), ordered_events=events)
    timeline = detection_temporal_history_timeline(HostilePath(), ordered_events=events)
    cluster = detection_cluster_projection(HostilePath(), [HostileText()], engine_context=HostileMapping())

    assert snapshot["ready"] is True
    assert snapshot["flow"] == []
    assert timeline[0]["stage"] == "current"
    assert timeline[0]["tags"] == []
    assert cluster is None


def test_stage1996_string_and_tag_contracts_reject_hostile_values_without_hooks() -> None:
    tags = validate_tags_for_path([HostileText()], HostilePath(), HostileText(), source=HostileText())

    assert ascii_visibility_ratio(HostileText()) == 0.0
    assert validate_high_risk_tag(HostileText(), HostileText(), HostilePath()) is True
    assert "tag_validation_failure_evidence" in tags


def test_stage1996_correlation_context_rejects_hostile_public_inputs_without_hooks() -> None:
    suppression = counterfactual_suppression_analysis(
        tags=HostileIterable(),
        causal_edges=HostileIterable(),
        probabilistic=HostileMapping(),
    )
    hostile_tags = HostileIterable()
    tag_evidence = normalize_tag_evidence(hostile_tags, source_detector="stage1996", source_stage="model_context")
    context = build_detection_model_context(
        HostilePath(),
        tags=tag_evidence,
        chain_evidence=evaluate_chain_evidence(tags=tag_evidence),
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest="a" * 64,
        update_cluster=HostileText(),
    )

    assert infer_correlation_group(HostileText(), tags=HostileIterable()) == "generic_behavior"
    assert suppression["adjusted_posterior"] == 0.0
    assert context.cluster_context.get("cluster_id") is None
    assert context.failure_evidence == ()
    assert tag_evidence.tags == ("detection_observation_unavailable",)
    assert tag_evidence.records[0].unavailable_reason == "detection_observation_unstructured_input"


def test_stage1996_path_prefilter_and_static_byte_helpers_reject_hostile_hooks() -> None:
    with pytest.raises(OSError):
        stage_read_bytes(HostilePath())

    with pytest.raises(TypeError, match="artifact_read_snapshot_required"):
        strict_fast_prefilter(HostilePath(), artifact_read_snapshot=object())
    assert find_known_eof_offset(HostileBytes()) == (None, None)
    assert _read_prefilter_strings(HostilePath()) == ("", None)
    assert _current_score_value({"score": HostileNumber()}) == 0.0
    assert classify_archive_intent_tags("zipfile savegame", HostilePath()) == ["save_archive_access"]
