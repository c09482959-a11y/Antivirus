"""Deterministic labeled evaluation of the canonical production clustering model.

The evaluator owns corpus partitioning and metric aggregation only. Feature
normalization, similarity, microcluster creation, trusted updates, quarantine,
and poisoning controls are exercised through production owners.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
import hashlib
import json
import math
from time import perf_counter

from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.clustering.chain_signatures import (
    cluster_behavior_signature,
    cluster_chain_signature,
)
from Virus_Scan.models.clustering.feature_registry import CLUSTER_FEATURE_REGISTRY
from Virus_Scan.models.clustering.metadata import cluster_kind_for_tags
from Virus_Scan.models.clustering.microcluster import (
    QUARANTINED,
    TRUSTED_BENIGN,
    TRUSTED_MALICIOUS,
    empty_microcluster_snapshot,
)
from Virus_Scan.models.clustering.microcluster_update import update_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.normalization import normalize_cluster_vector
from Virus_Scan.models.clustering.policy import (
    CLUSTER_POLICY,
    CLUSTER_POLICY_DIGEST,
    CLUSTER_POLICY_VERSION,
    ClusterPolicyManifest,
)
from Virus_Scan.models.clustering.similarity import cluster_similarity_evidence

EVALUATION_VERSION = "stage2636_04_clustering_evaluation_v1"
CORPUS_VERSION = "stage2636_04_family_source_corpus_v1"


@dataclass(frozen=True, slots=True)
class ClusterFixture:
    partition: str
    family: str
    source_package: str
    label: str
    raw_vector: tuple[float, ...]
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicyCandidate:
    name: str
    manifest: ClusterPolicyManifest


def _raw_vector(**overrides: float) -> tuple[float, ...]:
    values = {
        "tag_count": 3.0,
        "tag_entropy": 0.5,
        "unique_tag_count": 2.0,
        "yara_count": 0.0,
        "yara_weight": 0.0,
        "graph_risk": 0.1,
        "graph_anomaly": 0.1,
        "temporal_belief": 0.1,
        "markov_transition": 0.1,
        "markov_rarity": 0.1,
        "markov_pair_anomaly": 0.1,
        "unity_context": 0.0,
        "renpy_context": 0.0,
        "rpgm_context": 0.0,
        "media_context": 0.0,
        "other_context": 0.0,
        "cluster_size": 0.0,
        "cluster_risk": 0.0,
        "cluster_anomaly": 0.0,
    }
    values.update(overrides)
    return tuple(float(values[spec.feature_id]) for spec in CLUSTER_FEATURE_REGISTRY)


def _family_vector(family: str, variation: float) -> tuple[float, ...]:
    if family == "benign_image":
        return _raw_vector(
            tag_count=2.0 + variation,
            tag_entropy=0.25 + variation * 0.01,
            unique_tag_count=2.0,
            graph_risk=0.03 + variation * 0.002,
            graph_anomaly=0.02,
            media_context=1.0,
        )
    if family == "benign_script":
        return _raw_vector(
            tag_count=4.0 + variation,
            tag_entropy=0.75 + variation * 0.01,
            unique_tag_count=3.0,
            graph_risk=0.08,
            temporal_belief=0.18 + variation * 0.002,
            markov_transition=0.22,
            renpy_context=1.0,
        )
    if family == "malicious_injection":
        return _raw_vector(
            tag_count=7.0 + variation,
            tag_entropy=1.8,
            unique_tag_count=6.0,
            yara_count=3.0,
            yara_weight=0.65,
            graph_risk=0.96,
            graph_anomaly=0.92 + variation * 0.001,
            temporal_belief=0.72,
            markov_transition=0.84,
            markov_rarity=0.78,
            markov_pair_anomaly=0.90,
            unity_context=1.0,
        )
    if family == "malicious_exfiltration":
        return _raw_vector(
            tag_count=6.0 + variation,
            tag_entropy=1.55,
            unique_tag_count=5.0,
            yara_count=2.0,
            yara_weight=0.55,
            graph_risk=0.91,
            graph_anomaly=0.77,
            temporal_belief=0.86,
            markov_transition=0.68,
            markov_rarity=0.88,
            markov_pair_anomaly=0.76 + variation * 0.001,
            other_context=1.0,
        )
    return _raw_vector(
        tag_count=5.0 + variation,
        tag_entropy=1.2,
        unique_tag_count=4.0,
        graph_risk=0.52,
        graph_anomaly=0.58,
        temporal_belief=0.49,
        markov_transition=0.46,
        markov_rarity=0.57,
        markov_pair_anomaly=0.51,
        rpgm_context=1.0,
    )


def _family_tags(family: str) -> tuple[str, ...]:
    return {
        "benign_image": ("image_asset",),
        "benign_script": ("text_file",),
        "malicious_injection": ("process_injection", "credential_access"),
        "malicious_exfiltration": ("network_exfiltration", "http_upload"),
        "unknown": ("novel_behavior", "unclassified_runtime"),
    }[family]


def _partition(partition: str, repetitions: int, *, include_unknown: bool = False) -> tuple[ClusterFixture, ...]:
    rows: list[ClusterFixture] = []
    families = (
        ("benign_image", "benign"),
        ("benign_script", "benign"),
        ("malicious_injection", "malicious"),
        ("malicious_exfiltration", "malicious"),
    )
    partition_offset = {"train": 0.0, "validation": 0.35, "holdout": 0.70}[partition]
    for family, label in families:
        for index in range(repetitions):
            variation = partition_offset + index * 0.15
            rows.append(ClusterFixture(
                partition=partition,
                family=family,
                source_package=f"{partition}_{family}_source_{index}",
                label=label,
                raw_vector=_family_vector(family, variation),
                tags=_family_tags(family),
            ))
    if include_unknown:
        for index in range(3):
            rows.append(ClusterFixture(
                partition=partition,
                family="unknown",
                source_package=f"{partition}_unknown_source_{index}",
                label="unknown",
                raw_vector=_family_vector("unknown", float(index) * 0.2),
                tags=_family_tags("unknown"),
            ))
    return tuple(rows)


_TRAIN = _partition("train", 3)
_VALIDATION = _partition("validation", 2, include_unknown=True)
_HOLDOUT = _partition("holdout", 2, include_unknown=True)


def _candidate_policies() -> tuple[PolicyCandidate, ...]:
    return (
        PolicyCandidate("selected_production", CLUSTER_POLICY),
        PolicyCandidate("balanced", replace(
            CLUSTER_POLICY,
            cosine_weight=0.34,
            mahalanobis_weight=0.26,
            tag_weight=0.14,
            chain_weight=0.18,
            behavior_weight=0.08,
            selection_evidence="stage2636_04_balanced_candidate",
        )),
        PolicyCandidate("numeric_heavy", replace(
            CLUSTER_POLICY,
            cosine_weight=0.52,
            mahalanobis_weight=0.34,
            tag_weight=0.05,
            chain_weight=0.05,
            behavior_weight=0.04,
            selection_evidence="stage2636_04_numeric_candidate",
        )),
    )


def _authority(label: str) -> str:
    if label == "benign":
        return TRUSTED_BENIGN
    if label == "malicious":
        return TRUSTED_MALICIOUS
    return QUARANTINED


def _chain_evidence(tags: tuple[str, ...]) -> object:
    return evaluate_chain_evidence(tags=tags, match_modes=("anchor", "unordered"))


def _build_prototypes(fixtures: tuple[ClusterFixture, ...]) -> dict[str, object]:
    grouped: dict[str, list[ClusterFixture]] = defaultdict(list)
    for fixture in fixtures:
        grouped[fixture.family].append(fixture)
    prototypes: dict[str, object] = {}
    for family, rows in sorted(grouped.items()):
        first = rows[0]
        normalized = normalize_cluster_vector(first.raw_vector)
        if not normalized.available:
            raise AssertionError(normalized.unavailable_reason)
        chain = _chain_evidence(first.tags)
        snapshot = empty_microcluster_snapshot(
            f"evaluation_{family}",
            f"evaluation_{family}_context",
            normalized,
            node=first.source_package,
            observation_digest=hashlib.sha256(first.source_package.encode("utf-8")).hexdigest(),
            authority=_authority(first.label),
            observed_kind=first.label,
            tags=first.tags,
            chains=cluster_chain_signature(chain),
            behaviors=cluster_behavior_signature(first.tags),
            ordinal=1,
            label_provenance=(f"evaluation:{first.source_package}",),
        )
        for ordinal, fixture in enumerate(rows[1:], start=2):
            normalized = normalize_cluster_vector(fixture.raw_vector)
            chain = _chain_evidence(fixture.tags)
            snapshot = update_microcluster_snapshot(
                snapshot,
                normalized,
                node=fixture.source_package,
                observation_digest=hashlib.sha256(
                    fixture.source_package.encode("utf-8")
                ).hexdigest(),
                authority=_authority(fixture.label),
                observed_kind=fixture.label,
                tags=fixture.tags,
                chains=cluster_chain_signature(chain),
                behaviors=cluster_behavior_signature(fixture.tags),
                ordinal=ordinal,
                assignment_similarity=1.0,
                label_provenance=(f"evaluation:{fixture.source_package}",),
            )
        prototypes[family] = snapshot
    return prototypes


def _threshold(policy: ClusterPolicyManifest, observed_kind: str) -> float:
    if observed_kind == "benign":
        return policy.benign_reuse_threshold
    if observed_kind == "malicious":
        return policy.malicious_reuse_threshold
    return policy.quarantine_reuse_threshold


def _assign(
    fixture: ClusterFixture,
    prototypes: dict[str, object],
    policy: ClusterPolicyManifest,
) -> dict[str, object]:
    normalized = normalize_cluster_vector(fixture.raw_vector)
    chain = _chain_evidence(fixture.tags)
    scored: list[tuple[float, str, object]] = []
    for family, snapshot in sorted(prototypes.items()):
        evidence = cluster_similarity_evidence(
            normalized.assignment_vector,
            microcluster_value(snapshot, "centroid_vector", ()),
            chain,
            tags=fixture.tags,
            meta=snapshot,
            policy=policy,
        )
        scored.append((evidence.score, family, evidence))
    best_score, best_family, best_evidence = max(scored, key=lambda row: (row[0], row[1]))
    observed_kind = cluster_kind_for_tags(fixture.tags)
    threshold = _threshold(policy, observed_kind)
    prediction = best_family if best_score >= threshold else "outlier"
    return {
        "family": fixture.family,
        "source_package": fixture.source_package,
        "label": fixture.label,
        "observed_kind": observed_kind,
        "prediction": prediction,
        "score": best_score,
        "threshold": threshold,
        "component_scores": best_evidence.as_pairs(),
    }


def _choose2(value: int) -> int:
    return value * (value - 1) // 2


def _pair_metrics(rows: tuple[dict[str, object], ...]) -> dict[str, object]:
    tp = fp = fn = tn = 0
    false_merge = false_split = 0
    for left_index, left in enumerate(rows):
        for right in rows[left_index + 1:]:
            same_truth = left["family"] == right["family"]
            same_prediction = (
                left["prediction"] != "outlier"
                and left["prediction"] == right["prediction"]
            )
            tp += int(same_truth and same_prediction)
            fp += int(not same_truth and same_prediction)
            fn += int(same_truth and not same_prediction)
            tn += int(not same_truth and not same_prediction)
            false_merge += int(not same_truth and same_prediction)
            false_split += int(same_truth and not same_prediction)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "pair_precision": precision,
        "pair_recall": recall,
        "pair_f1": 2.0 * precision * recall / max(1e-12, precision + recall),
        "false_merge_count": false_merge,
        "false_split_count": false_split,
        "false_merge_rate": false_merge / max(1, fp + tn),
        "false_split_rate": false_split / max(1, tp + fn),
    }


def _purity(rows: tuple[dict[str, object], ...]) -> float:
    groups: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        groups[str(row["prediction"])][str(row["family"])] += 1
    return sum(max(counter.values()) for counter in groups.values()) / max(1, len(rows))


def _adjusted_rand(rows: tuple[dict[str, object], ...]) -> float:
    truth = Counter(str(row["family"]) for row in rows)
    predicted = Counter(str(row["prediction"]) for row in rows)
    contingency = Counter(
        (str(row["family"]), str(row["prediction"])) for row in rows
    )
    sum_comb = sum(_choose2(value) for value in contingency.values())
    truth_comb = sum(_choose2(value) for value in truth.values())
    predicted_comb = sum(_choose2(value) for value in predicted.values())
    total_comb = _choose2(len(rows))
    expected = truth_comb * predicted_comb / max(1, total_comb)
    maximum = 0.5 * (truth_comb + predicted_comb)
    return (sum_comb - expected) / max(1e-12, maximum - expected)


def _normalized_mutual_information(rows: tuple[dict[str, object], ...]) -> float:
    total = max(1, len(rows))
    truth = Counter(str(row["family"]) for row in rows)
    predicted = Counter(str(row["prediction"]) for row in rows)
    contingency = Counter(
        (str(row["family"]), str(row["prediction"])) for row in rows
    )
    mutual = 0.0
    for (truth_name, predicted_name), count in contingency.items():
        probability = count / total
        mutual += probability * math.log(
            probability / ((truth[truth_name] / total) * (predicted[predicted_name] / total))
        )
    truth_entropy = -sum(
        (count / total) * math.log(count / total) for count in truth.values()
    )
    predicted_entropy = -sum(
        (count / total) * math.log(count / total) for count in predicted.values()
    )
    return mutual / max(1e-12, math.sqrt(truth_entropy * predicted_entropy))


def _score_partition(
    fixtures: tuple[ClusterFixture, ...],
    prototypes: dict[str, object],
    policy: ClusterPolicyManifest,
) -> dict[str, object]:
    rows = tuple(_assign(fixture, prototypes, policy) for fixture in fixtures)
    known = tuple(row for row in rows if row["label"] != "unknown")
    unknown = tuple(row for row in rows if row["label"] == "unknown")
    pairs = _pair_metrics(known)
    same_scores = tuple(float(row["score"]) for row in known if row["prediction"] == row["family"])
    wrong_scores = tuple(float(row["score"]) for row in known if row["prediction"] not in {row["family"], "outlier"})
    malicious = tuple(row for row in known if row["label"] == "malicious")
    benign = tuple(row for row in known if row["label"] == "benign")
    benign_families = {"benign_image", "benign_script"}
    return {
        "rows": rows,
        **pairs,
        "cluster_purity": _purity(known),
        "adjusted_rand_index": _adjusted_rand(known),
        "normalized_mutual_information": _normalized_mutual_information(known),
        "exact_family_accuracy": sum(row["prediction"] == row["family"] for row in known) / max(1, len(known)),
        "malicious_family_grouping_recall": sum(row["prediction"] == row["family"] for row in malicious) / max(1, len(malicious)),
        "unknown_outlier_rejection_rate": sum(row["prediction"] == "outlier" for row in unknown) / max(1, len(unknown)),
        "unknown_mean_score": sum(float(row["score"]) for row in unknown) / max(1, len(unknown)),
        "benign_suppression_false_positive_rate": sum(row["prediction"] != row["family"] for row in benign) / max(1, len(benign)),
        "benign_suppression_false_negative_rate": sum(row["prediction"] in benign_families for row in malicious) / max(1, len(malicious)),
        "mean_correct_score": sum(same_scores) / max(1, len(same_scores)),
        "mean_wrong_merge_score": sum(wrong_scores) / max(1, len(wrong_scores)),
        "separation_margin": (
            sum(same_scores) / max(1, len(same_scores))
            - sum(wrong_scores) / max(1, len(wrong_scores))
        ),
    }


def _partition_evidence() -> dict[str, object]:
    partitions = {"train": _TRAIN, "validation": _VALIDATION, "holdout": _HOLDOUT}
    payload = {
        name: tuple({
            "family": row.family,
            "source_package": row.source_package,
            "label": row.label,
            "raw_vector": row.raw_vector,
            "tags": row.tags,
        } for row in rows)
        for name, rows in partitions.items()
    }
    sources = {name: {row.source_package for row in rows} for name, rows in partitions.items()}
    family_sources = {
        name: {(row.family, row.source_package) for row in rows}
        for name, rows in partitions.items()
    }
    pairs = (("train", "validation"), ("train", "holdout"), ("validation", "holdout"))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return {
        "corpus_version": CORPUS_VERSION,
        "corpus_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "partitions": payload,
        "source_package_overlap_count": sum(len(sources[a] & sources[b]) for a, b in pairs),
        "family_source_overlap_count": sum(len(family_sources[a] & family_sources[b]) for a, b in pairs),
    }


def _poisoning_evidence(prototype: object) -> dict[str, object]:
    original_centroid = tuple(microcluster_value(prototype, "centroid_vector", ()))
    snapshot = prototype
    poison = normalize_cluster_vector(_family_vector("unknown", 0.1))
    started = perf_counter()
    for ordinal in range(100, 200):
        snapshot = update_microcluster_snapshot(
            snapshot,
            poison,
            node=f"poison-{ordinal}",
            observation_digest=hashlib.sha256(f"poison-{ordinal}".encode()).hexdigest(),
            authority=QUARANTINED,
            observed_kind="mixed",
            tags=_family_tags("unknown"),
            chains=(),
            behaviors=_family_tags("unknown"),
            ordinal=ordinal,
            assignment_similarity=0.80,
        )
    quarantine_elapsed = perf_counter() - started
    centroid_after_quarantine = tuple(microcluster_value(snapshot, "centroid_vector", ()))
    far = normalize_cluster_vector(_family_vector("malicious_injection", 1.0))
    outlier = update_microcluster_snapshot(
        snapshot,
        far,
        node="trusted-outlier",
        observation_digest=hashlib.sha256(b"trusted-outlier").hexdigest(),
        authority=TRUSTED_BENIGN,
        observed_kind="benign",
        tags=("image_asset",),
        chains=(),
        behaviors=("image_asset",),
        ordinal=201,
        assignment_similarity=0.0,
    )
    centroid_after_outlier = tuple(microcluster_value(outlier, "centroid_vector", ()))
    return {
        "quarantine_sample_count": microcluster_value(snapshot, "quarantined_sample_count", 0),
        "quarantine_centroid_unchanged": centroid_after_quarantine == original_centroid,
        "trusted_outlier_centroid_unchanged": centroid_after_outlier == centroid_after_quarantine,
        "trusted_outlier_update_applied": microcluster_value(outlier, "last_update_applied", True),
        "trusted_outlier_rejected_reason": microcluster_value(outlier, "last_update_rejected_reason", ""),
        "maximum_quarantined_samples": CLUSTER_POLICY.maximum_quarantined_samples,
        "quarantine_runtime_seconds": quarantine_elapsed,
        "quarantine_runtime_bound_seconds": 2.0,
        "quarantine_runtime_within_bound": quarantine_elapsed <= 2.0,
    }


def _prototype_digest(prototypes: dict[str, object]) -> str:
    payload = {
        family: {
            "centroid": tuple(microcluster_value(snapshot, "centroid_vector", ())),
            "variance": tuple(microcluster_value(snapshot, "dimension_variance", ())),
            "trusted": microcluster_value(snapshot, "trusted_sample_count", 0),
            "tags": tuple(sorted(microcluster_value(snapshot, "tag_signature", ()))),
            "chains": tuple(sorted(microcluster_value(snapshot, "chain_signature", ()))),
        }
        for family, snapshot in sorted(prototypes.items())
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate_clustering_model() -> dict[str, object]:
    started = perf_counter()
    partition = _partition_evidence()
    prototypes = _build_prototypes(_TRAIN)
    candidates: list[dict[str, object]] = []
    for candidate in _candidate_policies():
        result = _score_partition(_VALIDATION, prototypes, candidate.manifest)
        candidates.append({
            "name": candidate.name,
            "policy_selection_evidence": candidate.manifest.selection_evidence,
            "pair_f1": result["pair_f1"],
            "false_merge_rate": result["false_merge_rate"],
            "false_split_rate": result["false_split_rate"],
            "exact_family_accuracy": result["exact_family_accuracy"],
            "unknown_outlier_rejection_rate": result["unknown_outlier_rejection_rate"],
            "unknown_mean_score": result["unknown_mean_score"],
            "separation_margin": result["separation_margin"],
        })
    selected = max(
        candidates,
        key=lambda row: (
            float(row["pair_f1"]),
            float(row["exact_family_accuracy"]),
            float(row["unknown_outlier_rejection_rate"]),
            -float(row["unknown_mean_score"]),
            -float(row["false_merge_rate"]),
            -float(row["false_split_rate"]),
            float(row["separation_margin"]),
            row["name"] == "selected_production",
        ),
    )
    holdout = _score_partition(_HOLDOUT, prototypes, CLUSTER_POLICY)
    forward = tuple(
        (row["source_package"], row["prediction"])
        for row in holdout["rows"]
    )
    reverse_rows = tuple(
        _assign(fixture, prototypes, CLUSTER_POLICY) for fixture in reversed(_HOLDOUT)
    )
    reverse = tuple(sorted(
        (row["source_package"], row["prediction"]) for row in reverse_rows
    ))
    replay_prototypes = _build_prototypes(_TRAIN)
    poisoning = _poisoning_evidence(prototypes["benign_image"])
    elapsed = perf_counter() - started
    acceptance = {
        "partition_isolated": (
            partition["source_package_overlap_count"] == 0
            and partition["family_source_overlap_count"] == 0
        ),
        "selected_manifest_wins_validation": selected["name"] == "selected_production",
        "pair_precision": holdout["pair_precision"] >= 0.95,
        "pair_recall": holdout["pair_recall"] >= 0.90,
        "false_merge": holdout["false_merge_rate"] <= 0.05,
        "false_split": holdout["false_split_rate"] <= 0.10,
        "purity": holdout["cluster_purity"] >= 0.95,
        "adjusted_rand": holdout["adjusted_rand_index"] >= 0.90,
        "normalized_mutual_information": holdout["normalized_mutual_information"] >= 0.90,
        "malicious_grouping": holdout["malicious_family_grouping_recall"] >= 0.90,
        "unknown_rejection": holdout["unknown_outlier_rejection_rate"] >= 0.90,
        "benign_suppression_fp": holdout["benign_suppression_false_positive_rate"] <= 0.05,
        "benign_suppression_fn": holdout["benign_suppression_false_negative_rate"] <= 0.05,
        "quarantine_poisoning": poisoning["quarantine_centroid_unchanged"] is True,
        "trusted_outlier_gate": (
            poisoning["trusted_outlier_centroid_unchanged"] is True
            and poisoning["trusted_outlier_update_applied"] is False
        ),
        "replay_deterministic": _prototype_digest(prototypes) == _prototype_digest(replay_prototypes),
        "order_deterministic": tuple(sorted(forward)) == reverse,
        "resource_bounds": (
            len(prototypes) <= CLUSTER_POLICY.maximum_cluster_count
            and all(
                len(microcluster_value(snapshot, "members", ())) <= CLUSTER_POLICY.maximum_members
                for snapshot in prototypes.values()
            )
        ),
        "runtime_bound": elapsed <= 5.0 and poisoning["quarantine_runtime_within_bound"] is True,
    }
    return {
        "evaluation_version": EVALUATION_VERSION,
        "policy_version": CLUSTER_POLICY_VERSION,
        "policy_digest": CLUSTER_POLICY_DIGEST,
        "policy_selection_evidence": CLUSTER_POLICY.selection_evidence,
        "partition_evidence": partition,
        "validation_candidates": tuple(candidates),
        "selected_validation_candidate": selected,
        "holdout": holdout,
        "poisoning_resistance": poisoning,
        "replay_determinism": {
            "prototype_digest": _prototype_digest(prototypes),
            "replay_digest": _prototype_digest(replay_prototypes),
            "deterministic": acceptance["replay_deterministic"],
        },
        "order_determinism": {
            "forward": tuple(sorted(forward)),
            "reverse": reverse,
            "deterministic": acceptance["order_deterministic"],
        },
        "memory_bounds": {
            "prototype_count": len(prototypes),
            "maximum_cluster_count": CLUSTER_POLICY.maximum_cluster_count,
            "maximum_members_observed": max(
                len(microcluster_value(snapshot, "members", ()))
                for snapshot in prototypes.values()
            ),
            "maximum_members": CLUSTER_POLICY.maximum_members,
        },
        "runtime_seconds": elapsed,
        "runtime_bound_seconds": 5.0,
        "acceptance": acceptance,
        "all_acceptance_passed": all(acceptance.values()),
    }


def main() -> int:
    print(json.dumps(evaluate_clustering_model(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
