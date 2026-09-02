from __future__ import annotations

from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from collections.abc import Mapping
from unittest.mock import patch

import pytest

from Virus_Scan.cli.exit_codes import exit_code_for_score, score_from_result
from Virus_Scan.detection.correlation.multi_signal.model_context import (
    build_detection_model_context,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.models.replay.api import detach_replay_payload_mapping
from Virus_Scan.reporting.summary import correlation_group_summary
from Virus_Scan.runtime.scheduler_runtime_state import SchedulerRuntimeState
from Virus_Scan.scheduler.workers.inmemory_runtime_config import (
    build_inmemory_runtime_config_snapshot,
)


from Virus_Scan.orchestration.yara_initialization import initialize_yara_worker_runtime
from Virus_Scan.orchestration.worker_runtime_descriptors import (
    WorkerYaraRuntimeDescriptor,
)

def _disabled_yara_descriptor() -> WorkerYaraRuntimeDescriptor:
    return WorkerYaraRuntimeDescriptor(
        initializer=initialize_yara_worker_runtime,
        root="/tmp/yara",
        enabled=False,
        available=False,
        scan_mode="auto",
        package_kind="",
        source_path="",
        source_digest="",
        compiled_cache_digest="",
        rule_catalog_digest="",
        unavailable_reason="yara_disabled",
    )


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - failure proves hook use
        type(self).touched += 1
        raise AssertionError("caller-owned __getitem__ invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ invoked")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __len__ invoked")


def test_stage1743_reporting_correlation_failure_uses_canonical_evidence() -> None:
    HostileMapping.touched = 0

    summary = correlation_group_summary(HostileMapping())

    assert HostileMapping.touched == 0
    failure = summary["unsupported_probability_evidence"]
    assert failure["degraded"] is True
    assert failure["failure_evidence_recorded"] is True
    assert failure["invalid_numeric_reason"] == (
        "unsupported_probability_evidence_iterable"
    )


def test_stage1743_replay_mapping_rejection_is_not_empty_detached_state() -> None:
    HostileMapping.touched = 0

    detached = detach_replay_payload_mapping(HostileMapping())

    assert HostileMapping.touched == 0
    assert detached != {}
    assert detached["unavailable_reason"] == "unsupported_replay_payload_mapping"
    assert detached["replay_record_required"] is True
    assert detached["final_json_must_record"] is True


def test_stage1743_replay_mapping_none_remains_legitimate_absence() -> None:
    assert detach_replay_payload_mapping(None) == {}


def test_stage1743_model_projection_rejections_are_context_failure_evidence() -> None:
    HostileMapping.touched = 0

    tag_evidence = normalize_tag_evidence(("process_injection",), source_detector="stage1743", source_stage="model_context")
    context = build_detection_model_context(
        "sample.exe",
        tags=tag_evidence,
        chain_evidence=evaluate_chain_evidence(tags=tag_evidence),
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest="a" * 64,
        update_cluster=False,
        graph_features_builder=lambda node: HostileMapping(),
        temporal_snapshot_builder=lambda *args, **kwargs: HostileMapping(),
        markov_features_builder=lambda *args, **kwargs: HostileMapping(),
    )

    assert HostileMapping.touched == 0
    assert context.graph_features["unavailable_reason"] == (
        "graph_features_mapping_rejected"
    )
    assert context.temporal_features["unavailable_reason"] == (
        "temporal_features_mapping_rejected"
    )
    assert context.markov_features["unavailable_reason"] == (
        "markov_features_mapping_rejected"
    )
    records = tuple(dict(failure) for failure in context.failure_evidence)
    assert {record["message"] for record in records} >= {
        "graph_features_mapping_rejected",
        "temporal_features_mapping_rejected",
        "markov_features_mapping_rejected",
    }
    assert all(record["json_record_required"] is True for record in records)
    assert all(record["replay_record_required"] is True for record in records)


def test_stage1743_engine_projection_rejection_is_not_silent_other_context() -> None:
    HostileMapping.touched = 0

    with patch(
        "Virus_Scan.detection.correlation.multi_signal.model_context.infer_engine_context",
        return_value=HostileMapping(),
    ):
        tag_evidence = normalize_tag_evidence(("process_injection",), source_detector="stage1743", source_stage="engine_context")
        context = build_detection_model_context(
            "sample.exe",
            tags=tag_evidence,
            chain_evidence=evaluate_chain_evidence(tags=tag_evidence),
            projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest="a" * 64,
            update_cluster=False,
        )

    assert HostileMapping.touched == 0
    assert context.engine_context["unavailable_reason"] == (
        "engine_context_mapping_rejected"
    )
    assert any(
        failure["message"] == "engine_context_mapping_rejected"
        for failure in context.failure_evidence
    )


def test_stage1743_scheduler_runtime_rejected_tables_retain_evidence() -> None:
    HostileMapping.touched = 0
    state = SchedulerRuntimeState()

    state.configure_worker_stage_tables(
        stage_limits=HostileMapping(),
        stage_semaphores=HostileMapping(),
    )

    snapshot = state.stage_tables_snapshot()
    assert HostileMapping.touched == 0
    assert snapshot["stage_limits"] == {}
    assert snapshot["stage_semaphores"] == {}
    assert {
        item["context"]["table_name"]
        for item in snapshot["stage_table_evidence"]
    } == {"stage_limits", "stage_semaphores"}
    assert all(
        item["final_json_must_record"] is True
        for item in snapshot["stage_table_evidence"]
    )


def test_stage1743_scheduler_config_failure_uses_defaults_with_evidence() -> None:
    class FailingContext:
        def Array(self, *args, **kwargs):
            raise RuntimeError("ipc unavailable")

        def BoundedSemaphore(self, limit):
            raise RuntimeError("semaphore unavailable")

    snapshot = build_inmemory_runtime_config_snapshot(
        ctx=FailingContext(),
        ctypes_module=type("Ctypes", (), {"c_ulonglong": int}),
        environ={"UMIGE_STAGE_LIMIT_RAW": "invalid"},
        recoverable_exceptions=(RuntimeError, ValueError),
        file_count=2,
        workers=2,
        logical_slots=4,
        strict=False,
        yara_enabled=False,
        scan_cache_enabled=False,
        yara_runtime_descriptor=_disabled_yara_descriptor(),
        per_file_timeout_sec=30,
        slow_file_warn_sec=5.0,
        worker_threads=1,
        worker_threads_base=1,
        worker_threads_max=2,
        timeout_budget_factory=lambda *args, **kwargs: None,
        timeout_result_annotator=lambda result, **kwargs: result,
        timeout_error_type=TimeoutError,
        mitre_initializer=lambda **_kwargs: None,
        mitre_root="/tmp/mitre",
        mitre_enabled=False,
        mitre_available=False,
        mitre_repository_digest="",
        mitre_dataset_version="",
        mitre_unavailable_reason="mitre_disabled",

        scan_session_snapshot=scan_session_snapshot_fixture(),
        routing_evidence_context=RoutingEvidenceContext.build("/tmp"),
    )

    reasons = {
        item["error_category"] for item in snapshot.scheduler_config_evidence
    }
    assert snapshot.stage_limits["raw"] == 16
    assert snapshot.stage_semaphores == {}
    assert reasons == {
        "scheduler_cancel_table_unavailable",
        "scheduler_heartbeat_table_unavailable",
        "scheduler_stage_limits_invalid",
        "scheduler_stage_semaphores_unavailable",
    }
    assert all(
        item["final_json_must_record"] is True
        for item in snapshot.scheduler_config_evidence
    )


def test_stage1743_scoreless_or_rejected_result_cannot_become_clean_exit() -> None:
    with pytest.raises(ValueError, match="does not contain a score"):
        score_from_result({})
    with pytest.raises(ValueError, match="not an exact result record"):
        score_from_result(HostileMapping())

    assert HostileMapping.touched == 0
    assert exit_code_for_score(None) == 4
    assert exit_code_for_score(float("nan")) == 4
