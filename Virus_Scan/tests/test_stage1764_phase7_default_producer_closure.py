from __future__ import annotations

from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store

from unittest.mock import patch

from Virus_Scan.detection.evidence.behavioral.semantics import (
    tag_effective_evidence_score,
)
from Virus_Scan.detection.profiles import baseline_snapshot
from Virus_Scan.detection.scoring.behavior.bucket_validation import (
    behavior_bucket_validation,
)
from Virus_Scan.detection.explainability.evidence_builder import (
    build_explanation_bundle,
)
from Virus_Scan.detection.correlation.multi_signal.model_context import (
    build_detection_model_context,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.profile_learning import promote_clean_observation
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.runtime.config_state import (
    configure_profiles_dir,
)
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state


def _isolate_profile_state(tmp_path: Path) -> None:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    state.set_staged_cache(
        default_staged_benign_store(),
        dirty=False,
    )
    ensure_authoritative_engine_profiles()
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    ensure_graph_node_owned,
    reset_graph_state,
)
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
)
from Virus_Scan.scheduler.runtime import queue_json_publication


class HostileSequence:
    touched = 0

    def __iter__(self):  # pragma: no cover - touching proves unsafe routing
        type(self).touched += 1
        raise AssertionError("hostile sequence iterated")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile sequence truth-tested")


class HostileSchedulerEvidence:
    touched = 0

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile scheduler evidence iterated")


def test_phase7_behavior_probability_uses_learned_profile_snapshot(tmp_path) -> None:
    _isolate_profile_state(tmp_path)
    samples = []
    for index in range(3):
        sample = tmp_path / f"payload-{index}.dll"
        sample.write_bytes(b"MZ" + bytes((index,)) + b"\0" * 63)
        promote_clean_observation("unity", sample, ["network_activity"], strings_blob="socket")
        samples.append(sample)

    record = tag_effective_evidence_score("unity", samples[-1], "network_activity")

    assert record["probability_ready"] is True
    assert record["probability"] > 0.0
    assert record["probability_unavailable_reason"] is None


def test_phase7_behavior_probability_cold_start_is_explicit(tmp_path) -> None:
    _isolate_profile_state(tmp_path)
    record = tag_effective_evidence_score(
        "cold-engine",
        tmp_path / "never-observed.bin",
        "process_exec",
    )

    assert record["probability"] == 0.0
    assert record["probability_ready"] is False
    assert record["probability_unavailable_reason"] == "insufficient_trusted_profile_support"


def test_phase7_bucket_probability_failure_is_explicit() -> None:
    with patch.object(
        baseline_snapshot,
        "read_extension_baseline_snapshot",
        return_value={
            "files": 4,
            "vector_baseline": {
                "trusted_count": 4, "maturity": "warming",
                "suppression_authority": 0.35,
            },
            "behavior_buckets": {
                "os_execution": {"files": object()},
            },
        },
    ):
        probability = baseline_snapshot.behavior_bucket_probability_record(
            "unity",
            "sample.dll",
            "os_execution",
        )

    assert probability["probability"] == 0.0
    assert probability["ready"] is False
    assert probability["reason"] == "invalid_behavior_bucket_observation_count"
    assert probability["final_json_must_record"] is True


def test_phase7_bucket_probability_uses_smoothed_valid_profile_counts() -> None:
    with patch.object(
        baseline_snapshot,
        "read_extension_baseline_snapshot",
        return_value={
            "files": 4,
            "vector_baseline": {
                "trusted_count": 4, "maturity": "warming",
                "suppression_authority": 0.35,
            },
            "behavior_buckets": {
                "os_execution": {"files": 3},
            },
        },
    ):
        probability = baseline_snapshot.behavior_bucket_probability_record(
            "unity",
            "sample.dll",
            "os_execution",
        )

    assert probability["probability"] == 4 / 6
    assert probability["ready"] is True
    assert probability["support"] == 4
    assert probability["successes"] == 3
    assert probability["estimator"] == "laplace_beta_binomial_v1"


def test_phase7_bucket_scoring_publishes_cold_start_reason(tmp_path) -> None:
    _isolate_profile_state(tmp_path)
    result = behavior_bucket_validation(
        "cold-engine",
        tmp_path / "never-observed.bin",
        ("process_exec",),
    )
    record = result["records"][0]

    assert record["bucket_probability"] == 0.0
    assert record["bucket_probability_ready"] is False
    assert record["bucket_probability_unavailable_reason"] == "insufficient_trusted_profile_support"


def test_phase7_explanation_bundle_reports_missing_graph_and_temporal_support() -> None:
    reset_graph_state()
    bundle = build_explanation_bundle(
        "stage1764-missing-node",
        ("process_exec",),
    )

    graph = bundle["graph_influence"][0]
    temporal = bundle["temporal_drift"][0]
    assert graph["unavailable_reason"] == "graph_node_missing"
    assert graph["final_json_must_record"] is True
    assert temporal["unavailable_reason"] == "insufficient_temporal_history"
    assert temporal["final_json_must_record"] is True


def test_phase7_explanation_bundle_preserves_present_empty_and_graph_influence() -> None:
    reset_graph_state()
    ensure_graph_node_owned("stage1764-present-empty")
    empty_bundle = build_explanation_bundle(
        "stage1764-present-empty",
        (),
    )
    assert empty_bundle["graph_influence"] == ()

    add_graph_edge_owned(
        "stage1764-present-empty",
        "stage1764-peer",
        edge_type="method_call",
        weight=1.0,
    )
    influenced = build_explanation_bundle(
        "stage1764-present-empty",
        (),
    )
    assert influenced["graph_influence"]


def test_phase7_model_context_rejected_sequences_emit_failure_evidence() -> None:
    HostileSequence.touched = 0
    hostile = HostileSequence()

    tag_evidence = normalize_tag_evidence(hostile, source_detector="stage1764", source_stage="model_context")
    context = build_detection_model_context(
        "stage1764-input.exe",
        tags=tag_evidence,
        chain_evidence=evaluate_chain_evidence(tags=tag_evidence),
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest="a" * 64,
        api_calls=hostile,
        ordered_events=hostile,
        behavior_timeline=hostile,
        update_cluster=False,
    )

    assert HostileSequence.touched == 0
    messages = {
        failure["message"]
        for failure in context.failure_evidence
    }
    assert messages >= {
        "api_calls_sequence_rejected",
        "ordered_events_sequence_rejected",
        "behavior_timeline_sequence_rejected",
    }


def test_phase7_scheduler_exact_evidence_rejection_is_not_empty() -> None:
    HostileSchedulerEvidence.touched = 0

    records = collect_exact_scheduler_evidence(HostileSchedulerEvidence())

    assert HostileSchedulerEvidence.touched == 0
    assert records
    payload = records[0].as_dict()
    assert payload["error_category"] == "scheduler_evidence_source_rejected"
    assert payload["context"]["unsupported_scheduler_evidence_source"]["unsupported_scheduler_value"] is True


def test_phase7_claim_meta_path_failure_records_scheduler_evidence() -> None:
    events = []
    with (
        patch.object(
            queue_json_publication,
            "queue_claim_meta_path",
            side_effect=ValueError("bad claim path"),
        ),
        patch.object(
            queue_json_publication,
            "record_queue_json_degraded",
            side_effect=lambda stage, exc, *, domain: events.append(
                (stage, type(exc).__name__, domain)
            ),
        ),
    ):
        assert queue_json_publication.queue_write_claim_meta("claim", {}) is False
    assert events == [("queue_claim_meta_write_failed", "ValueError", "scheduler")]
