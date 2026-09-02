"""Deterministic holdout evaluation of the canonical production Markov model.

The evaluator owns only corpus partitioning and metric aggregation.  All
learning, smoothing, fallback, feature, persistence, and unavailable-evidence
behavior is exercised through the production owners.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
from statistics import fmean

from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    MARKOV_MINIMUM_SUPPORT,
    MARKOV_MODEL_VERSION,
    MARKOV_SMOOTHING_ALPHA,
    MARKOV_SMOOTHING_NAME,
    MARKOV_STATE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.learning_decision import build_learning_decision
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)

EVALUATION_VERSION = "stage2636_markov_evaluation_v1"
CORPUS_VERSION = "stage2636_markov_holdout_corpus_v1"
_ENGINE = "renpy"
_FILE_PATH = "evaluation/game/script.rpy"
_PREVIOUS_STAGE = "asset"
_CURRENT_STAGE = "runtime"
_TRAIN_REPETITIONS = 6


@dataclass(frozen=True, slots=True)
class FlowFixture:
    group: str
    source_package: str
    label: str
    flow: tuple[str, ...]


_TRAIN = (
    FlowFixture("benign_train_asset_decode", "pkg_asset_a", "benign", ("resource_fetch", "decode", "file_read")),
    FlowFixture("benign_train_network_decode", "pkg_network_a", "benign", ("network_download", "decode", "file_write")),
    FlowFixture("benign_train_asset_extract", "pkg_asset_b", "benign", ("resource_fetch", "extract", "file_write")),
    FlowFixture("benign_train_network_extract", "pkg_network_b", "benign", ("network_download", "extract", "cache")),
    FlowFixture("benign_train_reference_extract", "pkg_reference_a", "benign", ("reference_url", "extract", "file_read")),
    FlowFixture("benign_train_reference_decode", "pkg_reference_b", "benign", ("reference_url", "decode", "cache")),
)

_VALIDATION = (
    FlowFixture("benign_validation_network_extract_read", "pkg_validation_b1", "benign", ("network_download", "extract", "file_read")),
    FlowFixture("benign_validation_reference_decode_write", "pkg_validation_b2", "benign", ("reference_url", "decode", "file_write")),
    FlowFixture("benign_validation_asset_extract_cache", "pkg_validation_b3", "benign", ("resource_fetch", "extract", "cache")),
    FlowFixture("malicious_validation_network_extract_exec", "family_validation_m1", "malicious", ("network_download", "extract", "process_exec")),
    FlowFixture("malicious_validation_reference_decode_shell", "family_validation_m2", "malicious", ("reference_url", "decode", "shell")),
    FlowFixture("malicious_validation_asset_decode_persist", "family_validation_m3", "malicious", ("resource_fetch", "decode", "persistence")),
)

_HOLDOUT = (
    FlowFixture("benign_holdout_reference_extract_write", "pkg_holdout_b1", "benign", ("reference_url", "extract", "file_write")),
    FlowFixture("benign_holdout_asset_decode_cache", "pkg_holdout_b2", "benign", ("resource_fetch", "decode", "cache")),
    FlowFixture("benign_holdout_network_decode_read", "pkg_holdout_b3", "benign", ("network_download", "decode", "file_read")),
    FlowFixture("benign_holdout_asset_extract_read", "pkg_holdout_b4", "benign", ("resource_fetch", "extract", "file_read")),
    FlowFixture("benign_holdout_network_extract_write", "pkg_holdout_b5", "benign", ("network_download", "extract", "file_write")),
    FlowFixture("benign_holdout_reference_decode_read", "pkg_holdout_b6", "benign", ("reference_url", "decode", "file_read")),
    FlowFixture("malicious_holdout_reference_extract_exec", "family_holdout_m1", "malicious", ("reference_url", "extract", "process_exec")),
    FlowFixture("malicious_holdout_asset_decode_shell", "family_holdout_m2", "malicious", ("resource_fetch", "decode", "shell")),
    FlowFixture("malicious_holdout_network_decode_persist", "family_holdout_m3", "malicious", ("network_download", "decode", "persistence")),
    FlowFixture("malicious_holdout_asset_extract_shell", "family_holdout_m4", "malicious", ("resource_fetch", "extract", "shell")),
    FlowFixture("malicious_holdout_network_decode_exec", "family_holdout_m5", "malicious", ("network_download", "decode", "process_exec")),
    FlowFixture("malicious_holdout_reference_decode_persist", "family_holdout_m6", "malicious", ("reference_url", "decode", "persistence")),
)


def _reset() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _decision(flow: tuple[str, ...], observation_id: str) -> object:
    context = contextual_profile_learning_policy(
        _FILE_PATH, trusted_benign=True, degraded=False,
    )
    validation = {"contextual_engine_identity": context.as_record_fields()}
    request = ProfileLearningGateRequest(
        _ENGINE,
        _FILE_PATH,
        flow,
        0.0,
        "",
        "clean",
        (),
        (),
        scan_integrity={"allow_learning": True},
    )
    return build_learning_decision(
        request,
        observation_id=observation_id,
        yara_hits=(),
        behavior_flow=flow,
        previous_stage=_PREVIOUS_STAGE,
        current_stage=_CURRENT_STAGE,
        learning_allowed=True,
        reason="markov_evaluation_authorized",
        validation=validation,
        gate_version=EVALUATION_VERSION,
    )


def _learn(flow: tuple[str, ...], observation_id: str) -> tuple[tuple[str, str], ...]:
    decision = _decision(flow, observation_id)
    result = markov.update_markov_model(
        _PREVIOUS_STAGE,
        flow,
        _CURRENT_STAGE,
        learning_decision=decision,
    )
    if result.get("learned") is not True:
        raise RuntimeError("canonical markov evaluation learning failed")
    return decision.context_identity


def _train_model() -> tuple[tuple[str, str], ...]:
    _reset()
    context_identity: tuple[tuple[str, str], ...] = ()
    for fixture in _TRAIN:
        for ordinal in range(_TRAIN_REPETITIONS):
            context_identity = _learn(
                fixture.flow,
                f"{EVALUATION_VERSION}:train:{fixture.group}:{ordinal}",
            )
    return context_identity


def _pair_score(
    flow: tuple[str, ...], context_identity: tuple[tuple[str, str], ...]
) -> dict[str, object]:
    records = tuple(
        markov.markov_pair_probability(
            source,
            target,
            prev_stage=_PREVIOUS_STAGE,
            context_identity=context_identity,
            engine=_ENGINE,
        )
        for source, target in zip(flow, flow[1:], strict=False)
    )
    ready = all(record.get("ready") is True for record in records)
    probabilities = tuple(
        float(record["probability"])
        for record in records
        if record.get("ready") is True and record.get("probability") is not None
    )
    average_nll = (
        -fmean(math.log(max(1e-300, value)) for value in probabilities)
        if ready and len(probabilities) == len(records)
        else None
    )
    return {
        "ready": ready,
        "average_negative_log_likelihood": average_nll,
        "minimum_transition_probability": min(probabilities) if probabilities else None,
        "records": tuple(
            {
                "source": record.get("source"),
                "target": record.get("target"),
                "support": record.get("support"),
                "count": record.get("count"),
                "probability": record.get("probability"),
                "fallback_level": record.get("fallback_level"),
            }
            for record in records
        ),
    }


def _score_fixtures(
    fixtures: tuple[FlowFixture, ...],
    context_identity: tuple[tuple[str, str], ...],
) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for fixture in fixtures:
        pair = _pair_score(fixture.flow, context_identity)
        features = markov.compute_markov_features(
            _PREVIOUS_STAGE,
            fixture.flow,
            _CURRENT_STAGE,
            context_identity=context_identity,
            engine=_ENGINE,
        )
        rows.append({
            "group": fixture.group,
            "source_package": fixture.source_package,
            "label": fixture.label,
            "flow": fixture.flow,
            "pair_ready": pair["ready"],
            "score": pair["average_negative_log_likelihood"],
            "minimum_transition_probability": pair["minimum_transition_probability"],
            "full_flow_ready": features.get("ready") is True,
            "full_flow_anomaly": float(features.get("sequence_anomaly", 0.0)),
            "full_flow_reason": features.get("reason"),
        })
    return tuple(rows)


def _roc_auc(rows: tuple[dict[str, object], ...]) -> float:
    positives = tuple(float(row["score"]) for row in rows if row["label"] == "malicious")
    negatives = tuple(float(row["score"]) for row in rows if row["label"] == "benign")
    comparisons = tuple(
        1.0 if positive > negative else 0.5 if positive == negative else 0.0
        for positive in positives
        for negative in negatives
    )
    return fmean(comparisons) if comparisons else 0.0


def _pr_auc(rows: tuple[dict[str, object], ...]) -> float:
    ranked = sorted(rows, key=lambda row: (-float(row["score"]), str(row["group"])))
    positive_total = sum(row["label"] == "malicious" for row in ranked)
    found = 0
    precisions: list[float] = []
    for index, row in enumerate(ranked, start=1):
        if row["label"] == "malicious":
            found += 1
            precisions.append(found / index)
    return sum(precisions) / max(1, positive_total)


def _classification_metrics(
    rows: tuple[dict[str, object], ...], threshold: float,
) -> dict[str, object]:
    tp = fp = tn = fn = 0
    for row in rows:
        predicted = float(row["score"]) >= threshold
        positive = row["label"] == "malicious"
        tp += int(predicted and positive)
        fp += int(predicted and not positive)
        tn += int(not predicted and not positive)
        fn += int(not predicted and positive)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2.0 * precision * recall / max(1e-300, precision + recall)
    return {
        "threshold": threshold,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / max(1, fp + tn),
    }


def _select_threshold(rows: tuple[dict[str, object], ...]) -> dict[str, object]:
    values = sorted({float(row["score"]) for row in rows})
    candidates = [values[0] - 1e-12]
    candidates.extend((left + right) / 2.0 for left, right in zip(values, values[1:], strict=False))
    candidates.append(values[-1] + 1e-12)
    metrics = tuple(_classification_metrics(rows, threshold) for threshold in candidates)
    return max(
        metrics,
        key=lambda item: (
            float(item["f1"]),
            -float(item["false_positive_rate"]),
            float(item["threshold"]),
        ),
    )


def _partition_evidence() -> dict[str, object]:
    partitions = {"train": _TRAIN, "validation": _VALIDATION, "holdout": _HOLDOUT}
    serialized = {
        name: tuple(
            {
                "group": row.group,
                "source_package": row.source_package,
                "label": row.label,
                "flow": row.flow,
            }
            for row in rows
        )
        for name, rows in partitions.items()
    }
    groups = {name: {row.group for row in rows} for name, rows in partitions.items()}
    packages = {name: {row.source_package for row in rows} for name, rows in partitions.items()}
    flows = {name: {row.flow for row in rows} for name, rows in partitions.items()}
    overlap_pairs = (("train", "validation"), ("train", "holdout"), ("validation", "holdout"))
    canonical = json.dumps(serialized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "corpus_version": CORPUS_VERSION,
        "corpus_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "partitions": serialized,
        "group_overlap_count": sum(len(groups[left] & groups[right]) for left, right in overlap_pairs),
        "source_package_overlap_count": sum(len(packages[left] & packages[right]) for left, right in overlap_pairs),
        "exact_flow_overlap_count": sum(len(flows[left] & flows[right]) for left, right in overlap_pairs),
    }


def _support_bucket(support: int) -> str:
    if support < 6:
        return "3_to_5"
    if support < 12:
        return "6_to_11"
    if support < 24:
        return "12_to_23"
    return "24_plus"


def _calibration(context_identity: tuple[tuple[str, str], ...]) -> tuple[dict[str, object], ...]:
    observed: dict[str, Counter[str]] = defaultdict(Counter)
    for fixture in _TRAIN:
        for source, target in zip(fixture.flow, fixture.flow[1:], strict=False):
            observed[source][target] += _TRAIN_REPETITIONS
    rows: list[dict[str, object]] = []
    for source, targets in sorted(observed.items()):
        support = sum(targets.values())
        candidates = tuple(sorted(targets)) + ("process_exec",)
        for target in candidates:
            record = markov.markov_pair_probability(
                source,
                target,
                prev_stage=_PREVIOUS_STAGE,
                context_identity=context_identity,
                engine=_ENGINE,
            )
            predicted = float(record["probability"])
            empirical = targets[target] / support
            rows.append({
                "source": source,
                "target": target,
                "support": support,
                "bucket": _support_bucket(support),
                "predicted_probability": predicted,
                "empirical_frequency": empirical,
                "absolute_gap": abs(predicted - empirical),
                "squared_gap": (predicted - empirical) ** 2,
            })
    buckets: list[dict[str, object]] = []
    for bucket in sorted({str(row["bucket"]) for row in rows}):
        selected = tuple(row for row in rows if row["bucket"] == bucket)
        buckets.append({
            "bucket": bucket,
            "record_count": len(selected),
            "mean_predicted_probability": fmean(float(row["predicted_probability"]) for row in selected),
            "mean_empirical_frequency": fmean(float(row["empirical_frequency"]) for row in selected),
            "mean_absolute_gap": fmean(float(row["absolute_gap"]) for row in selected),
            "mean_squared_gap": fmean(float(row["squared_gap"]) for row in selected),
        })
    return tuple(buckets)


def _support_policy() -> tuple[dict[str, object], ...]:
    _reset()
    flow = ("network_download", "decode", "file_write")
    context_identity: tuple[tuple[str, str], ...] = ()
    rows: list[dict[str, object]] = []
    for support in range(1, MARKOV_MINIMUM_SUPPORT + 1):
        context_identity = _learn(flow, f"{EVALUATION_VERSION}:support:{support}")
        pair = markov.markov_pair_probability(
            "network_download",
            "decode",
            prev_stage=_PREVIOUS_STAGE,
            context_identity=context_identity,
            engine=_ENGINE,
        )
        features = markov.compute_markov_features(
            _PREVIOUS_STAGE,
            flow,
            _CURRENT_STAGE,
            context_identity=context_identity,
            engine=_ENGINE,
        )
        rows.append({
            "support": support,
            "pair_ready": pair.get("ready") is True,
            "pair_probability": pair.get("probability"),
            "feature_ready": features.get("ready") is True,
            "feature_anomaly": float(features.get("sequence_anomaly", 0.0)),
        })
    return tuple(rows)


def _fallback_evidence(context_identity: tuple[tuple[str, str], ...]) -> dict[str, object]:
    engine_context = tuple(
        (key, "renpy/.other" if key == "learning_baseline_key" else value)
        for key, value in context_identity
    )
    global_context = (
        ("container_engine", "python"),
        ("learning_baseline_key", "python/.other"),
    )
    queries = (
        ("exact", context_identity, _ENGINE),
        ("engine", engine_context, _ENGINE),
        ("global", global_context, "python"),
    )
    rows = []
    for requested, context, engine in queries:
        record = markov.markov_pair_probability(
            "network_download",
            "decode",
            prev_stage=_PREVIOUS_STAGE,
            context_identity=context,
            engine=engine,
        )
        rows.append({
            "requested": requested,
            "actual": record.get("fallback_level"),
            "context_key": record.get("context_key"),
            "confidence": float(record.get("fallback_confidence", 0.0)),
            "probability": record.get("probability"),
        })
    return {
        "records": tuple(rows),
        "deterministic_order": tuple(row["actual"] for row in rows) == ("exact", "engine", "global"),
        "strict_confidence_reduction": rows[0]["confidence"] > rows[1]["confidence"] > rows[2]["confidence"],
    }


def _poisoning_sensitivity() -> dict[str, object]:
    context_identity = _train_model()
    flow = ("resource_fetch", "decode", "process_exec")
    before = _pair_score(flow, context_identity)
    _learn(flow, f"{EVALUATION_VERSION}:poison:one")
    after = _pair_score(flow, context_identity)
    before_probability = float(before["records"][1]["probability"])
    after_probability = float(after["records"][1]["probability"])
    return {
        "target_transition": ("decode", "process_exec"),
        "probability_before": before_probability,
        "probability_after_one_authorized_observation": after_probability,
        "probability_delta": after_probability - before_probability,
        "maximum_confidence_avoided": after_probability < 1.0,
        "average_nll_before": before["average_negative_log_likelihood"],
        "average_nll_after": after["average_negative_log_likelihood"],
    }


def _persistence_determinism(
    context_identity: tuple[tuple[str, str], ...],
    before_rows: tuple[dict[str, object], ...],
) -> dict[str, object]:
    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    _reset()
    loaded = load_runtime_model_baselines(snapshot)
    after_rows = _score_fixtures(_HOLDOUT, context_identity)
    comparable_before = tuple(
        (row["group"], row["score"], row["full_flow_ready"], row["full_flow_reason"])
        for row in before_rows
    )
    comparable_after = tuple(
        (row["group"], row["score"], row["full_flow_ready"], row["full_flow_reason"])
        for row in after_rows
    )
    return {
        "loaded": loaded.get("loaded") is True,
        "load_reason": loaded.get("reason"),
        "state_schema": snapshot.get("markov_state_schema_version"),
        "identical_holdout_evidence_after_reload": comparable_before == comparable_after,
    }


def _mean_score(rows: tuple[dict[str, object], ...], label: str) -> float:
    return fmean(float(row["score"]) for row in rows if row["label"] == label)


def evaluate_markov_model() -> dict[str, object]:
    partition = _partition_evidence()
    support_policy = _support_policy()
    context_identity = _train_model()
    validation_rows = _score_fixtures(_VALIDATION, context_identity)
    threshold = _select_threshold(validation_rows)
    holdout_rows = _score_fixtures(_HOLDOUT, context_identity)
    holdout_metrics = _classification_metrics(holdout_rows, float(threshold["threshold"]))
    roc_auc = _roc_auc(holdout_rows)
    pr_auc = _pr_auc(holdout_rows)
    benign_nll = _mean_score(holdout_rows, "benign")
    malicious_nll = _mean_score(holdout_rows, "malicious")
    cold_start_benign = tuple(row for row in holdout_rows if row["label"] == "benign")
    cold_start_false_positives = sum(
        row["full_flow_ready"] is True
        and float(row["full_flow_anomaly"]) >= float(threshold["threshold"])
        for row in cold_start_benign
    )
    fallback = _fallback_evidence(context_identity)
    calibration = _calibration(context_identity)
    persistence = _persistence_determinism(context_identity, holdout_rows)
    poisoning = _poisoning_sensitivity()
    acceptance = {
        "partition_isolation": partition["group_overlap_count"] == 0
        and partition["source_package_overlap_count"] == 0
        and partition["exact_flow_overlap_count"] == 0,
        "holdout_roc_auc_at_least_0_90": roc_auc >= 0.90,
        "holdout_pr_auc_at_least_0_90": pr_auc >= 0.90,
        "holdout_false_positive_rate_at_most_0_05": float(holdout_metrics["false_positive_rate"]) <= 0.05,
        "malicious_nll_exceeds_benign_nll": malicious_nll > benign_nll,
        "cold_start_false_positive_rate_zero": cold_start_false_positives == 0,
        "one_and_two_shot_not_ready": all(not row["pair_ready"] for row in support_policy[:-1]),
        "minimum_support_ready_without_certainty": support_policy[-1]["pair_ready"] is True
        and 0.0 < float(support_policy[-1]["pair_probability"]) < 1.0,
        "one_shot_poisoning_avoids_certainty": poisoning["maximum_confidence_avoided"] is True,
        "one_shot_poisoning_probability_delta_bounded": float(poisoning["probability_delta"]) <= 0.10,
        "fallback_order_and_confidence": fallback["deterministic_order"] is True
        and fallback["strict_confidence_reduction"] is True,
        "persistence_replay_deterministic": persistence["loaded"] is True
        and persistence["identical_holdout_evidence_after_reload"] is True,
    }
    return {
        "evaluation_version": EVALUATION_VERSION,
        "corpus": partition,
        "model_version": MARKOV_MODEL_VERSION,
        "state_schema_version": MARKOV_STATE_SCHEMA_VERSION,
        "smoothing": MARKOV_SMOOTHING_NAME,
        "alpha": MARKOV_SMOOTHING_ALPHA,
        "minimum_support": MARKOV_MINIMUM_SUPPORT,
        "training_observations": len(_TRAIN) * _TRAIN_REPETITIONS,
        "validation": {
            "records": validation_rows,
            "selected_threshold": threshold,
        },
        "holdout": {
            "records": holdout_rows,
            "benign_transition_average_negative_log_likelihood": benign_nll,
            "malicious_transition_average_negative_log_likelihood": malicious_nll,
            "malicious_minus_benign_nll": malicious_nll - benign_nll,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "classification": holdout_metrics,
            "full_flow_ready_rate": sum(row["full_flow_ready"] is True for row in holdout_rows) / len(holdout_rows),
            "cold_start_benign_false_positive_rate": cold_start_false_positives / max(1, len(cold_start_benign)),
        },
        "support_policy": support_policy,
        "calibration_by_support_bucket": calibration,
        "one_shot_poisoning": poisoning,
        "context_fallback": fallback,
        "persistence_replay": persistence,
        "acceptance": acceptance,
        "all_acceptance_checks_pass": all(acceptance.values()),
    }


def main() -> int:
    result = evaluate_markov_model()
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["all_acceptance_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
