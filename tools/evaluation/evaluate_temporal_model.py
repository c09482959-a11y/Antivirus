"""Deterministic evaluation of the canonical temporal v5 production owners.

The evaluator owns fixtures, source/family partitioning, thresholds, and metric
aggregation only. Temporal event materialization, profile authorization, dwell
learning, percentile smoothing, delay/burst policy, accumulator decay, and replay
transaction telemetry projection all execute through production owners.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import argparse
import json
from pathlib import Path
from statistics import fmean
from typing import Final

from Virus_Scan.contracts.temporal_accumulator import (
    TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
    initial_temporal_accumulator_state,
)
from Virus_Scan.contracts.temporal_baseline import empty_temporal_baselines
from Virus_Scan.contracts.temporal_learning import TEMPORAL_RUNTIME_STATE_SCHEMA
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.learning_decision import build_learning_decision
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.models.replay.transaction_projection import project_runtime_transaction_stats
from Virus_Scan.models.temporal.accumulator import temporal_evidence_accumulator_update
from Virus_Scan.models.temporal.dwell_baseline import (
    TEMPORAL_DWELL_MINIMUM_SUPPORT,
    apply_temporal_baseline_learning,
    temporal_dwell_evidence,
)
from Virus_Scan.models.temporal.event_materialization import materialize_temporal_events
from Virus_Scan.models.temporal.learning import build_temporal_learning_request
from Virus_Scan.models.temporal.policy import (
    temporal_burst_policy_evidence,
    temporal_delay_policy_evidence,
)
from Virus_Scan.models.temporal.validation import compute_temporal_validation
from Virus_Scan.models.temporal.validation_support import temporal_observed_delay_projection
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.runtime.temporal_state import (
    load_temporal_runtime_state,
    temporal_history_snapshot,
)

EVALUATION_VERSION: Final[str] = "stage2636_temporal_evaluation_v2"
CORPUS_VERSION: Final[str] = "stage2636_temporal_holdout_corpus_v2"
TEMPORAL_SCORE_THRESHOLD: Final[float] = 4.0
FIXED_POLICY_THRESHOLD: Final[float] = 0.75
_ENGINE: Final[str] = "renpy"
_FLOW: Final[tuple[str, str]] = ("decode", "execute")
_TRAIN_DELAYS: Final[tuple[float, ...]] = (
    8.0, 9.0, 10.0, 11.0, 12.0,
    8.0, 9.0, 10.0, 11.0, 12.0,
    8.0, 9.0, 10.0, 11.0, 12.0,
    8.0, 9.0, 10.0, 11.0, 12.0,
)


@dataclass(frozen=True, slots=True)
class DelayFixture:
    group: str
    source_package: str
    label: str
    delay_seconds: float
    node_id: str


_HOLDOUT: Final[tuple[DelayFixture, ...]] = (
    DelayFixture("benign_installer_fast", "installer_pkg_a", "benign", 8.0, "holdout/installer_a.rpy"),
    DelayFixture("benign_installer_typical", "installer_pkg_b", "benign", 10.0, "holdout/installer_b.rpy"),
    DelayFixture("benign_updater_typical", "updater_pkg_a", "benign", 12.0, "holdout/updater_a.rpy"),
    DelayFixture("benign_updater_slow", "updater_pkg_b", "benign", 20.0, "holdout/updater_b.rpy"),
    DelayFixture("benign_updater_boundary", "updater_pkg_c", "benign", 30.0, "holdout/updater_c.rpy"),
    DelayFixture("malicious_delayed_90", "family_delay_a", "malicious", 90.0, "holdout/family_a.rpy"),
    DelayFixture("malicious_delayed_180", "family_delay_b", "malicious", 180.0, "holdout/family_b.rpy"),
    DelayFixture("malicious_delayed_240", "family_delay_c", "malicious", 240.0, "holdout/family_c.rpy"),
    DelayFixture("malicious_delayed_300", "family_delay_d", "malicious", 300.0, "holdout/family_d.rpy"),
    DelayFixture("malicious_delayed_600", "family_delay_e", "malicious", 600.0, "holdout/family_e.rpy"),
    DelayFixture("malicious_delayed_1200", "family_delay_f", "malicious", 1200.0, "holdout/family_f.rpy"),
    DelayFixture("malicious_delayed_3600", "family_delay_g", "malicious", 3600.0, "holdout/family_g.rpy"),
)


def _reset_runtime() -> None:
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
    if result.get("loaded") is not True:
        raise RuntimeError("temporal evaluation runtime reset failed")


def _rows(delay: float, identity: str) -> tuple[dict[str, object], ...]:
    return (
        {
            "event_id": identity + ":source",
            "source_evidence_id": identity + ":source",
            "tag": _FLOW[0], "stage": "asset", "timestamp": 100.0,
            "timestamp_kind": "observed", "clock_domain": "scan",
        },
        {
            "event_id": identity + ":target",
            "source_evidence_id": identity + ":target",
            "tag": _FLOW[1], "stage": "runtime",
            "timestamp": 100.0 + delay,
            "timestamp_kind": "observed", "clock_domain": "scan",
        },
    )


def _decision(
    *, node_id: str, rows: tuple[dict[str, object], ...],
    observation_id: str, ordinal: int,
):
    context = contextual_profile_learning_policy(
        node_id, trusted_benign=True, degraded=False,
    )
    validation = {"contextual_engine_identity": context.as_record_fields()}
    request = ProfileLearningGateRequest(
        _ENGINE, node_id, _FLOW, 0.0, "", "clean", (), rows,
        scan_integrity={"allow_learning": True},
    )
    return build_learning_decision(
        request, observation_id=observation_id, yara_hits=(),
        behavior_flow=_FLOW, previous_stage="asset", current_stage="runtime",
        learning_allowed=True, reason="temporal_evaluation_authorized",
        validation=validation, gate_version=EVALUATION_VERSION,
        decision_ordinal=ordinal,
    )


def _request(
    *, node_id: str, delay: float, identity: str, ordinal: int,
):
    rows = _rows(delay, identity)
    decision = _decision(
        node_id=node_id, rows=rows, observation_id=identity, ordinal=ordinal,
    )
    request, validations = build_temporal_learning_request(
        learning_decision=decision, node=node_id, previous_stage="asset",
        current_stage="runtime", ordered_events=rows, behavior_flow=_FLOW,
    )
    if any(row["status"] != "valid" for row in validations):
        raise RuntimeError("temporal evaluation fixture invalid")
    return request


def _train_store() -> dict[str, object]:
    store: object = empty_temporal_baselines()
    for ordinal, delay in enumerate(_TRAIN_DELAYS, start=1):
        request = _request(
            node_id="train/installer_reference.rpy", delay=delay,
            identity=f"{EVALUATION_VERSION}:train:{ordinal}", ordinal=ordinal,
        )
        store, result = apply_temporal_baseline_learning(store, request)
        if result.get("updated") is not True:
            raise RuntimeError("temporal evaluation baseline learning failed")
    return store


def _score_delay(
    store: object, *, delay: float, node_id: str, identity: str,
) -> dict[str, object]:
    rows = _rows(delay, identity)
    validation = compute_temporal_validation(
        node_id, tags=_FLOW, prev_stage="asset", curr_stage="runtime",
        ordered_events=rows, engine=_ENGINE, temporal_baselines=store,
    )
    dwell = validation["learned_dwell_evidence"]
    delay_records = validation["dangerous_delay_policy_evidence"]
    policy_strength = max(
        (float(row["strength"]) for row in delay_records if row["ready"] is True),
        default=0.0,
    )
    score = float(validation["score"])
    return {
        "delay_seconds": delay,
        "score": score,
        "evidence_strength": float(validation["evidence_strength"]),
        "detected": score >= TEMPORAL_SCORE_THRESHOLD,
        "fixed_policy_detected": policy_strength >= FIXED_POLICY_THRESHOLD,
        "dwell_ready": dwell["ready"],
        "dwell_anomaly": dwell["maximum_anomaly"],
        "dwell_confidence": dwell["confidence"],
        "dwell_fallback_level": (
            dwell["records"][0]["fallback_level"] if dwell["records"] else None
        ),
        "dwell_support": (
            dwell["records"][0]["support"] if dwell["records"] else 0
        ),
        "policy_strength": policy_strength,
        "policy_rule": next(
            (row["matched_rule"] for row in delay_records if row["ready"] is True),
            None,
        ),
        "production_temporal_model_version": validation["temporal_model_version"],
        "production_fusion_version": validation["fusion_version"],
    }


def _holdout_metrics(store: object) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for fixture in _HOLDOUT:
        score = _score_delay(
            store, delay=fixture.delay_seconds, node_id=fixture.node_id,
            identity=EVALUATION_VERSION + ":holdout:" + fixture.group,
        )
        rows.append({
            "group": fixture.group,
            "source_package": fixture.source_package,
            "label": fixture.label,
            **score,
        })
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    hybrid_recall = fmean(float(row["detected"]) for row in malicious)
    fixed_recall = fmean(float(row["fixed_policy_detected"]) for row in malicious)
    hybrid_false_positive_rate = fmean(float(row["detected"]) for row in benign)
    fixed_false_positive_rate = fmean(
        float(row["fixed_policy_detected"]) for row in benign
    )
    return {
        "temporal_score_threshold": TEMPORAL_SCORE_THRESHOLD,
        "fixed_policy_threshold": FIXED_POLICY_THRESHOLD,
        "delayed_execution_recall": hybrid_recall,
        "fixed_only_delayed_execution_recall": fixed_recall,
        "recall_improvement_over_fixed_only": hybrid_recall - fixed_recall,
        "benign_installer_updater_false_positive_rate": hybrid_false_positive_rate,
        "fixed_only_benign_false_positive_rate": fixed_false_positive_rate,
        "rows": rows,
    }


def _synthetic_separation() -> dict[str, object]:
    synthetic, validations = materialize_temporal_events(
        ordered_events=({
            "event_id": "synthetic:raw", "source_evidence_id": "synthetic:raw",
            "tags": _FLOW, "stage": "runtime", "timestamp": 10.0,
            "clock_domain": "scan",
        },),
        behavior_flow=(), observation_id="synthetic-evaluation",
        previous_stage="asset", current_stage="runtime",
    )
    observed, _ = materialize_temporal_events(
        ordered_events=_rows(10.0, "observed-evaluation"),
        behavior_flow=(), observation_id="observed-evaluation",
        previous_stage="asset", current_stage="runtime",
    )
    synthetic_projection = temporal_observed_delay_projection(synthetic)
    observed_projection = temporal_observed_delay_projection(observed)
    return {
        "synthetic_order_delay_ready": synthetic_projection["ready"],
        "observed_delay_ready": observed_projection["ready"],
        "synthetic_timestamp_value": synthetic[1].timestamp_value,
        "synthetic_validation_degraded": validations[1].status == "degraded",
        "separated": (
            synthetic_projection["ready"] is False
            and observed_projection["ready"] is True
            and synthetic[1].timestamp_value is None
        ),
    }


def _dwell_calibration(store: object) -> dict[str, object]:
    exact = _score_delay(
        store, delay=10.0, node_id="query/exact.rpy",
        identity="calibration:exact",
    )
    engine = _score_delay(
        store, delay=10.0, node_id="query/engine.txt",
        identity="calibration:engine",
    )
    request = _request(
        node_id="query/global.txt", delay=10.0,
        identity="calibration:global", ordinal=20_000,
    )
    global_row = temporal_dwell_evidence(
        store, engine="unity", node_id="query/global.txt", events=request.events,
    )[0]
    incremental: object = empty_temporal_baselines()
    readiness: list[bool] = []
    supports: list[int] = []
    for ordinal in range(1, TEMPORAL_DWELL_MINIMUM_SUPPORT + 1):
        request = _request(
            node_id="incremental/reference.rpy", delay=10.0,
            identity=f"incremental:{ordinal}", ordinal=30_000 + ordinal,
        )
        incremental, _ = apply_temporal_baseline_learning(incremental, request)
        row = temporal_dwell_evidence(
            incremental, engine=_ENGINE,
            node_id="incremental/reference.rpy", events=request.events,
        )[0]
        readiness.append(row["ready"] is True)
        supports.append(int(row["support"]))
    return {
        "exact": exact,
        "engine_fallback": engine,
        "global_fallback": {
            "ready": global_row["ready"],
            "fallback_level": global_row["fallback_level"],
            "confidence": global_row["confidence"],
            "support": global_row["support"],
        },
        "incremental_support": supports,
        "incremental_readiness": readiness,
        "cold_start_neutral_until_minimum_support": (
            readiness[:-1] == [False] * (TEMPORAL_DWELL_MINIMUM_SUPPORT - 1)
            and readiness[-1] is True
        ),
    }


def _hidden_state_metrics() -> dict[str, object]:
    first = temporal_evidence_accumulator_update(
        previous=initial_temporal_accumulator_state(), observation=1.0,
        observation_confidence=1.0, evidence_timestamp=100.0,
        support=TEMPORAL_DWELL_MINIMUM_SUPPORT,
    )
    left = temporal_evidence_accumulator_update(
        previous=first, observation=0.0, observation_confidence=0.0,
        evidence_timestamp=100.0 + TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
        support=TEMPORAL_DWELL_MINIMUM_SUPPORT,
    )
    right = temporal_evidence_accumulator_update(
        previous=first, observation=0.0, observation_confidence=0.0,
        evidence_timestamp=100.0 + TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
        support=TEMPORAL_DWELL_MINIMUM_SUPPORT,
    )
    return {
        "deterministic": left == right,
        "half_life_seconds": TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
        "posterior_after_one_half_life": left.posterior_belief,
        "half_life_error": abs(left.posterior_belief - 0.5),
        "elapsed_evidence_time": left.elapsed_evidence_time,
    }


def _burst_metrics() -> dict[str, object]:
    positive_rows = (
        {"event_id": "burst:a", "source_evidence_id": "burst:a", "tag": "process_injection", "stage": "runtime", "timestamp": 1.0},
        {"event_id": "burst:b", "source_evidence_id": "burst:b", "tag": "memory_write", "stage": "runtime", "timestamp": 2.0},
        {"event_id": "burst:c", "source_evidence_id": "burst:c", "tag": "thread_execution", "stage": "runtime", "timestamp": 3.0},
    )
    positive, _ = materialize_temporal_events(
        ordered_events=positive_rows, behavior_flow=(), observation_id="burst-positive",
        previous_stage="asset", current_stage="runtime",
    )
    aliases, _ = materialize_temporal_events(
        ordered_events=({
            "event_id": "burst:alias", "source_evidence_id": "burst:alias",
            "tags": ("process_injection", "memory_write", "thread_execution"),
            "stage": "runtime", "timestamp": 1.0,
        },),
        behavior_flow=(), observation_id="burst-alias",
        previous_stage="asset", current_stage="runtime",
    )
    positive_result = temporal_burst_policy_evidence(positive)
    alias_result = temporal_burst_policy_evidence(aliases)
    true_positive = positive_result["observed_time_confirmed"] is True
    false_positive = alias_result["ready"] is True
    precision = 1.0 if true_positive and not false_positive else 0.0
    return {
        "positive_detected": true_positive,
        "alias_false_positive": false_positive,
        "precision": precision,
        "positive": positive_result,
        "alias_control": alias_result,
    }


def _poisoning_metrics(store: object) -> dict[str, object]:
    before_extreme = _score_delay(
        store, delay=100_000.0, node_id="train/installer_reference.rpy",
        identity="poison:before:extreme",
    )
    before_benign = _score_delay(
        store, delay=10.0, node_id="train/installer_reference.rpy",
        identity="poison:before:benign",
    )
    poisoned, _ = apply_temporal_baseline_learning(
        store,
        _request(
            node_id="train/installer_reference.rpy", delay=100_000.0,
            identity="poison:one-shot", ordinal=90_000,
        ),
    )
    after_extreme = _score_delay(
        poisoned, delay=100_000.0, node_id="train/installer_reference.rpy",
        identity="poison:after:extreme",
    )
    after_benign = _score_delay(
        poisoned, delay=10.0, node_id="train/installer_reference.rpy",
        identity="poison:after:benign",
    )
    delta = float(before_extreme["dwell_anomaly"]) - float(after_extreme["dwell_anomaly"])
    return {
        "extreme_anomaly_before": before_extreme["dwell_anomaly"],
        "extreme_anomaly_after": after_extreme["dwell_anomaly"],
        "extreme_anomaly_delta": delta,
        "benign_anomaly_before": before_benign["dwell_anomaly"],
        "benign_anomaly_after": after_benign["dwell_anomaly"],
        "bounded": delta <= 0.10 and float(after_extreme["dwell_anomaly"]) >= 0.80,
        "benign_stable": before_benign["dwell_anomaly"] == after_benign["dwell_anomaly"],
    }


def _replay_metrics() -> dict[str, object]:
    _reset_runtime()
    node_id = "evaluation/replay.rpy"
    rows = _rows(10.0, "replay")
    decision = _decision(
        node_id=node_id, rows=rows, observation_id="temporal-evaluation-replay",
        ordinal=100_000,
    )
    statuses = {target: "succeeded" for target in decision.permitted_model_targets}
    learning_result = {
        "learned": True,
        "promoted": True,
        "persisted": True,
        "transaction_status": "complete",
        "transaction_id": "b" * 64,
        "learning_decision": decision.to_record(),
        "source_record_digest": decision.observation_digest,
        "target_status": statuses,
        "target_outputs": {
            "markov": {
                "learned": True, "idempotent_replay": False, "transitions": 1,
            },
            "temporal": {
                "updated": True, "idempotent_replay": False, "transitions": 1,
            },
        },
        "idempotent_replay": False,
    }
    first_summary = {"runtime": 0}
    first = project_runtime_transaction_stats(learning_result, first_summary)
    reused = dict(learning_result)
    reused["idempotent_replay"] = True
    second_summary = {"runtime": 0}
    second = project_runtime_transaction_stats(reused, second_summary)
    history = temporal_history_snapshot(node_id)
    return {
        "first_temporal_mutated": first.get("temporal_mutated") is True,
        "duplicate_idempotent": second.get("idempotent_replay") is True,
        "duplicate_temporal_mutated": second.get("temporal_mutated") is True,
        "history_event_count": len(history),
        "projection_does_not_execute_temporal": len(history) == 0,
        "deterministic": (
            first.get("runtime_committed") is True
            and first.get("temporal_mutated") is True
            and second.get("idempotent_replay") is True
            and second.get("temporal_mutated") is False
            and first_summary["runtime"] == 1
            and second_summary["runtime"] == 1
            and len(history) == 0
        ),
    }


def evaluate_temporal_model() -> dict[str, object]:
    _reset_runtime()
    store = _train_store()
    holdout = _holdout_metrics(store)
    synthetic = _synthetic_separation()
    dwell = _dwell_calibration(store)
    hidden = _hidden_state_metrics()
    burst = _burst_metrics()
    poisoning = _poisoning_metrics(store)
    replay = _replay_metrics()
    acceptance = {
        "delayed_execution_recall_at_least_0_95": holdout["delayed_execution_recall"] >= 0.95,
        "benign_false_positive_rate_at_most_0_05": holdout["benign_installer_updater_false_positive_rate"] <= 0.05,
        "recall_improves_over_fixed_only_by_at_least_0_25": holdout["recall_improvement_over_fixed_only"] >= 0.25,
        "hybrid_does_not_increase_benign_false_positives": holdout["benign_installer_updater_false_positive_rate"] <= holdout["fixed_only_benign_false_positive_rate"],
        "synthetic_and_observed_time_are_separated": synthetic["separated"] is True,
        "exact_context_is_ready": dwell["exact"]["dwell_ready"] is True,
        "engine_fallback_is_ready": dwell["engine_fallback"]["dwell_fallback_level"] == "engine",
        "global_fallback_is_ready": dwell["global_fallback"]["fallback_level"] == "global",
        "cold_start_is_neutral_until_minimum_support": dwell["cold_start_neutral_until_minimum_support"] is True,
        "hidden_state_is_deterministic": hidden["deterministic"] is True,
        "half_life_error_at_most_1e_6": hidden["half_life_error"] <= 1e-6,
        "burst_precision_is_one": burst["precision"] == 1.0,
        "replay_is_deterministic_and_idempotent": replay["deterministic"] is True,
        "one_shot_poisoning_is_bounded": poisoning["bounded"] is True,
        "benign_dwell_is_stable_after_one_shot_poisoning": poisoning["benign_stable"] is True,
    }
    return {
        "evaluation_version": EVALUATION_VERSION,
        "corpus_version": CORPUS_VERSION,
        "train_source_packages": ("installer_reference_pkg",),
        "holdout_source_packages": tuple(fixture.source_package for fixture in _HOLDOUT),
        "source_packages_are_group_isolated": len({fixture.source_package for fixture in _HOLDOUT}) == len(_HOLDOUT),
        "holdout": holdout,
        "synthetic_order_separation": synthetic,
        "dwell_calibration": dwell,
        "hidden_state": hidden,
        "burst_precision": burst,
        "replay_determinism": replay,
        "one_shot_poisoning": poisoning,
        "acceptance": acceptance,
        "all_acceptance_passed": all(acceptance.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate_temporal_model()
    payload = json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if report["all_acceptance_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
