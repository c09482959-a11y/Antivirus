"""Stage2636.10006 canonical temporal v5 acceptance contracts."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest

from Virus_Scan.contracts.temporal_accumulator import (
    TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
    initial_temporal_accumulator_state,
)
from Virus_Scan.contracts.temporal_baseline import (
    empty_temporal_baselines,
    validate_temporal_baselines,
)
from Virus_Scan.contracts.temporal_learning import TEMPORAL_RUNTIME_STATE_SCHEMA
from Virus_Scan.models.profiles.learning_decision import build_learning_decision
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.models.profiles.temporal_target import apply_temporal_learning_target
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.models.profiles.learning_decision import content_sha256_for_path
from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.models.temporal.accumulator import temporal_evidence_accumulator_update
from Virus_Scan.models.temporal.dwell_baseline import (
    TEMPORAL_DWELL_MINIMUM_SUPPORT,
    apply_temporal_baseline_learning,
    temporal_dwell_evidence,
)
from Virus_Scan.models.temporal.event_materialization import materialize_temporal_events
from Virus_Scan.models.temporal.policy import (
    temporal_burst_policy_evidence,
    temporal_delay_policy_evidence,
)
from Virus_Scan.models.temporal.validation import compute_temporal_validation
from Virus_Scan.models.temporal.validation_support import (
    temporal_observed_delay_projection,
)
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.runtime.temporal_state import (
    TemporalStateOwner,
    load_temporal_runtime_state,
    temporal_history_snapshot,
)
from Virus_Scan.tests.support.profile_learning import (
    accepted_learning_request,
    accepted_runtime_transaction_result,
)
from Virus_Scan.tests.support.temporal_v5 import temporal_v5_event, temporal_v5_request


def _event(
    identity: str, behavior: str, ordinal: int, timestamp: float | None,
    *, stage: str = "runtime", clock: str = "scan",
    kind: str = "observed", source: str | None = None,
):
    return temporal_v5_event(
        event_id=identity,
        source_evidence_id=source or identity,
        behavior_id=behavior,
        stage=stage,
        source_ordinal=ordinal,
        timestamp_value=timestamp,
        timestamp_kind=kind,
        clock_domain=clock,
        ordering_confidence=1.0 if kind in {"observed", "derived"} else 0.5,
    )


def _observed_rows(delay: float) -> tuple[object, ...]:
    return (
        {"event_id": "source", "tag": "decode", "stage": "asset", "timestamp": 100.0, "clock_domain": "scan"},
        {"event_id": "target", "tag": "execute", "stage": "runtime", "timestamp": 100.0 + delay, "clock_domain": "scan"},
    )


def _empty_runtime() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    result = load_temporal_runtime_state({
        "schema_version": TEMPORAL_RUNTIME_STATE_SCHEMA,
        "nodes": {},
        "applied_learning_keys": [],
    })
    assert result["loaded"] is True


def test_synthetic_order_proves_order_but_never_elapsed_time_or_dwell() -> None:
    events, validations = materialize_temporal_events(
        ordered_events=({
            "event_id": "raw", "tags": ("decode", "execute"),
            "stage": "runtime", "timestamp": 12.0,
        },),
        behavior_flow=(), observation_id="synthetic", previous_stage="asset",
        current_stage="runtime",
    )
    assert [event.timestamp_kind for event in events] == ["observed", "synthetic_order"]
    assert events[1].timestamp_value is None
    observed = temporal_observed_delay_projection(events)
    assert observed["ready"] is False
    assert observed["records"][0]["unavailable_reason"] == "temporal_order_only"
    store, learned = apply_temporal_baseline_learning(
        empty_temporal_baselines(), temporal_v5_request(node_id="synthetic.rpy", events=events),
    )
    assert learned["transitions"] == 0
    assert learned["reason"] == "temporal_order_only_no_dwell_update"
    assert store["records"] == {}
    assert validations[1].status == "degraded"


def test_reversed_duplicate_and_mixed_clock_evidence_remain_explicitly_degraded() -> None:
    rows = (
        {"event_id": "a", "tag": "decode", "stage": "asset", "timestamp": 20.0, "clock_domain": "clock-a"},
        {"event_id": "b", "tag": "execute", "stage": "runtime", "timestamp": 10.0, "clock_domain": "clock-a"},
        {"event_id": "c", "tag": "persist", "stage": "runtime", "timestamp": 10.0, "clock_domain": "clock-a"},
        {"event_id": "d", "tag": "network", "stage": "runtime", "timestamp": 11.0, "clock_domain": "clock-b"},
    )
    events, validations = materialize_temporal_events(
        ordered_events=rows, behavior_flow=(), observation_id="degraded",
        previous_stage="asset", current_stage="runtime",
    )
    reasons = {reason for validation in validations for reason in validation.reasons}
    assert {
        "temporal_timestamp_reversed", "temporal_timestamp_duplicate",
        "temporal_clock_domain_mismatch",
    }.issubset(reasons)
    observed = temporal_observed_delay_projection(events)
    assert observed["ready"] is False
    assert tuple(row["unavailable_reason"] for row in observed["records"]) == (
        "temporal_timestamp_reversed",
        "temporal_timestamp_duplicate",
        "temporal_clock_domain_mismatch",
    )
    policy = temporal_delay_policy_evidence(events)
    assert all(row["ready"] is False and row["strength"] == 0.0 for row in policy)
    assert policy[1]["delay_seconds"] == 0.0


def test_dwell_query_accepts_immutable_profile_v5_store_and_uses_mature_fallback() -> None:
    store: object = empty_temporal_baselines()
    base_events = (_event("a", "decode", 0, 0.0, stage="asset"), _event("b", "execute", 1, 10.0))
    for ordinal in range(TEMPORAL_DWELL_MINIMUM_SUPPORT):
        store, _ = apply_temporal_baseline_learning(
            store, temporal_v5_request(
                node_id="train.rpy", events=base_events, decision_ordinal=ordinal + 1,
            ),
        )
    text_events = (_event("c", "decode", 0, 0.0, stage="asset"), _event("d", "execute", 1, 10.0))
    store, _ = apply_temporal_baseline_learning(
        store, temporal_v5_request(
            node_id="single.txt", events=text_events,
            decision_ordinal=TEMPORAL_DWELL_MINIMUM_SUPPORT + 1,
        ),
    )
    frozen = MappingProxyType({
        "schema_version": store["schema_version"],
        "model_version": store["model_version"],
        "records": MappingProxyType({
            key: MappingProxyType({
                field: tuple(value) if type(value) is list else value
                for field, value in record.items()
            }) for key, record in store["records"].items()
        }),
        "applied_learning_keys": MappingProxyType(dict(store["applied_learning_keys"])),
    })
    evidence = temporal_dwell_evidence(
        frozen, engine="other", node_id="single.txt", events=text_events,
    )[0]
    assert evidence["ready"] is True
    assert evidence["fallback_level"] == "engine"
    assert evidence["support"] == TEMPORAL_DWELL_MINIMUM_SUPPORT + 1
    assert 0.0 < evidence["confidence"] < 1.0
    assert validate_temporal_baselines(frozen) == store


def test_trusted_profile_decision_is_required_for_baseline_and_runtime_mutation(tmp_path: Path) -> None:
    _empty_runtime()
    path = tmp_path / "sample.rpy"
    ordered_events = _observed_rows(10.0)
    accepted = accepted_learning_request(
        path, flow=("decode", "execute"), observation_id="trusted-temporal",
        ordered_events=ordered_events,
    )
    profile = default_engine_profile("renpy")
    result = apply_temporal_learning_target(profile, accepted)
    assert result["updated"] is True
    assert result["transitions"] == 1
    assert len(temporal_history_snapshot(str(path))) == 2
    store_before = profile["model_state"]["temporal_baselines"]

    gate = ProfileLearningGateRequest(
        "renpy", str(path), accepted.tag_evidence, 0.0, "", "clean", (),
        ordered_events, scan_integrity={},
    )
    rejected_decision = build_learning_decision(
        gate, observation_id="rejected-temporal", yara_hits=(),
        behavior_flow=("decode", "execute"), previous_stage="asset",
        current_stage="runtime", learning_allowed=False,
        reason="temporal_learning_rejected", validation=accepted.validation,
        gate_version="test_gate_v5", decision_ordinal=2,
    )
    rejected = LearningCommitRequest(
        decision=rejected_decision, engine="renpy", content_sha256=content_sha256_for_path(path), file_path=str(path),
        tag_evidence=accepted.tag_evidence, yara_hits=(), risk=0.0,
        strings_blob="", verdict="clean", api_calls=(),
        ordered_events=ordered_events, behavior_flow=("decode", "execute"),
        previous_stage="asset", current_stage="runtime",
        validation=accepted.validation, scan_integrity={},
    )
    rejected.validate()
    blocked = apply_temporal_learning_target(profile, rejected)
    assert blocked == {"updated": False, "reason": "temporal_target_contract_invalid"}
    assert profile["model_state"]["temporal_baselines"] == store_before
    assert len(temporal_history_snapshot(str(path))) == 2


def test_learning_digest_binds_ordered_event_timestamps_and_replay_is_exactly_once(tmp_path: Path) -> None:
    _empty_runtime()
    path = tmp_path / "digest.rpy"
    rows = _observed_rows(10.0)
    request = accepted_learning_request(
        path, flow=("decode", "execute"), observation_id="digest-bound",
        ordered_events=rows,
    )
    altered = replace(request, ordered_events=_observed_rows(999.0))
    try:
        altered.validate()
    except ValueError as error:
        assert str(error) == "learning transaction observation mismatch"
    else:
        raise AssertionError("altered temporal evidence was not digest-bound")

    learning_result = accepted_runtime_transaction_result(request)
    tampered = dict(learning_result)
    tampered["source_record_digest"] = "f" * 64
    blocked = project_runtime_transaction_stats(tampered, {"runtime": 0})
    assert blocked["reason"] == "source_record_digest_mismatch"
    assert temporal_history_snapshot(str(path)) == ()

    first_summary = {"runtime": 0}
    first = project_runtime_transaction_stats(learning_result, first_summary)
    reused_summary = {"runtime": 0}
    second = project_runtime_transaction_stats(
        accepted_runtime_transaction_result(request, reused=True), reused_summary,
    )
    assert first["temporal"] is True
    assert first["temporal_mutated"] is True
    assert first["idempotent_replay"] is False
    assert first_summary["runtime"] == 1
    assert second["temporal"] is True
    assert second["temporal_mutated"] is False
    assert second["idempotent_replay"] is True
    assert reused_summary["runtime"] == 1
    # Replay is metadata projection only; runtime mutation belongs to the transaction owner.
    assert temporal_history_snapshot(str(path)) == ()


def test_hidden_state_decay_is_deterministic_and_evidence_time_only() -> None:
    first = temporal_evidence_accumulator_update(
        previous=initial_temporal_accumulator_state(), observation=1.0,
        observation_confidence=1.0, evidence_timestamp=100.0, support=5,
    )
    left = temporal_evidence_accumulator_update(
        previous=first, observation=0.0, observation_confidence=0.0,
        evidence_timestamp=100.0 + TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
        support=5,
    )
    right = temporal_evidence_accumulator_update(
        previous=first, observation=0.0, observation_confidence=0.0,
        evidence_timestamp=100.0 + TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
        support=5,
    )
    assert left == right
    assert left.elapsed_evidence_time == TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC
    assert left.posterior_belief == 0.5
    reversed_state = temporal_evidence_accumulator_update(
        previous=first, observation=0.0, observation_confidence=0.0,
        evidence_timestamp=99.0, support=5,
    )
    assert reversed_state.last_evidence_timestamp == 100.0
    assert reversed_state.unavailable_reason == "temporal_evidence_timestamp_reversed"


def test_cold_start_is_neutral_and_smoothed_tail_never_claims_certainty() -> None:
    events = (_event("a", "decode", 0, 0.0, stage="asset"), _event("b", "execute", 1, 10.0))
    store: object = empty_temporal_baselines()
    for ordinal in range(TEMPORAL_DWELL_MINIMUM_SUPPORT - 1):
        store, _ = apply_temporal_baseline_learning(
            store, temporal_v5_request(node_id="cold.rpy", events=events, decision_ordinal=ordinal + 1),
        )
    cold = temporal_dwell_evidence(store, engine="other", node_id="cold.rpy", events=events)[0]
    assert cold["ready"] is False
    assert cold["tail_probability"] is None
    assert cold["anomaly"] == 0.0
    store, _ = apply_temporal_baseline_learning(
        store, temporal_v5_request(node_id="cold.rpy", events=events, decision_ordinal=99),
    )
    extreme = (_event("c", "decode", 0, 0.0, stage="asset"), _event("d", "execute", 1, 100000.0))
    mature = temporal_dwell_evidence(store, engine="other", node_id="cold.rpy", events=extreme)[0]
    assert mature["ready"] is True
    assert 0.0 < mature["tail_probability"] < 1.0
    assert 0.0 < mature["anomaly"] < 1.0


def test_burst_policy_deduplicates_aliases_by_raw_source_identity() -> None:
    behaviors = (
        "process_injection", "memory_write", "thread_execution",
        "memory_protect", "powershell_exec",
    )
    aliases = tuple(
        _event(str(index), behavior, index, None, kind="synthetic_order", clock="synthetic:raw", source="raw")
        for index, behavior in enumerate(behaviors)
    )
    alias_result = temporal_burst_policy_evidence(aliases)
    assert alias_result["deduplicated_source_events"] == 1
    assert alias_result["ready"] is False
    distinct = tuple(
        _event(str(index), behavior, index, float(index), source="raw-" + str(index))
        for index, behavior in enumerate(behaviors[:3])
    )
    distinct_result = temporal_burst_policy_evidence(distinct)
    assert distinct_result["ready"] is True
    assert distinct_result["observed_time_confirmed"] is True
    assert distinct_result["strength"] == 0.75


def test_markov_and_chain_remain_externally_owned_and_unmixed() -> None:
    rows = (
        {"event_id": "a", "tag": "powershell_exec", "stage": "asset", "timestamp": 1.0},
        {"event_id": "b", "tag": "scheduled_task", "stage": "runtime", "timestamp": 2.0},
        {"event_id": "c", "tag": "wmi_exec", "stage": "runtime", "timestamp": 3.0},
    )
    result = compute_temporal_validation(
        "owner-check", tags=("powershell_exec", "scheduled_task", "wmi_exec"),
        prev_stage="asset", curr_stage="runtime", ordered_events=rows,
        markov={"ready": True, "sequence_anomaly": 0.4},
        temporal_baselines=empty_temporal_baselines(),
    )
    assert result["markov_transition_evidence"]["ownership"] == "markov"
    assert result["chain_evidence"]["ownership"] == "chains"
    assert result["chain_evidence"]["score_contribution"] == 0.0
    assert result["chain_score_contribution"] == 0.0
    assert result["high_risk_burst_evidence"]["evidence_family"] == "high_risk_burst_policy"


def test_runtime_persistence_is_exact_v5_and_has_no_migration_path() -> None:
    owner = TemporalStateOwner()
    events = (_event("a", "decode", 0, 1.0, stage="asset"), _event("b", "execute", 1, 2.0))
    request = temporal_v5_request(node_id="persist.rpy", events=events)
    assert owner.commit_request(request) is True
    record = owner.to_record()
    restored = TemporalStateOwner()
    assert restored.load_record(record)["loaded"] is True
    assert restored.to_record() == record
    before = restored.to_record()
    invalid = dict(record)
    invalid["schema_version"] = "temporal_runtime_state_v4"
    assert restored.load_record(invalid) == {
        "loaded": False, "reason": "temporal_state_schema_invalid",
    }
    assert restored.to_record() == before
    root = Path("Virus_Scan")
    scoped = (
        *root.joinpath("contracts").glob("temporal_*.py"),
        *root.joinpath("models", "temporal").glob("*.py"),
        root / "runtime" / "temporal_state.py",
        root / "models" / "profiles" / "temporal_target.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in scoped)
    assert "temporal_state_migration" not in source
    assert "dual_read" not in source and "dual_write" not in source
    assert not (root / "runtime" / "temporal_state_migration.py").exists()
    assert "temporal_runtime_state_v4" not in source


def test_temporal_learning_request_binds_source_digest_to_exact_events() -> None:
    events = (
        _event("digest-a", "decode", 0, 0.0, stage="asset"),
        _event("digest-b", "execute", 1, 12.0),
    )
    request = temporal_v5_request(
        node_id="temporal-digest-binding.rpy", events=events,
        decision_ordinal=88,
    )
    forged = replace(request, source_record_digest="f" * 64)
    with pytest.raises(ValueError, match="temporal source record digest mismatch"):
        forged.validate()
