"""Deterministic labeled evaluation of the canonical production graph model.

The evaluator owns fixtures, partitioning, candidate comparison, and metrics
only. Snapshot construction, component scoring, cache behavior, corruption
admission, traversal bounds, and mutation invalidation are exercised through
production owners.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter

from Virus_Scan.models.graph.attention import graph_attention_evidence
from Virus_Scan.models.graph.contracts import (
    GRAPH_CONTEXT_BASELINE_VERSION,
    GRAPH_RISK_POLICY,
    GRAPH_RISK_POLICY_VERSION,
)
from Virus_Scan.models.graph.risk import get_graph_risk_enhanced_evidence
from Virus_Scan.models.graph.snapshot import admitted_graph_snapshot
from Virus_Scan.models.graph.state import prune_graph
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    reset_graph_state,
    update_graph_node_owned,
)

EVALUATION_VERSION = "stage2636_09_graph_evaluation_v1"
_COMPONENT_NAMES = (
    "structural", "attention", "execution", "temporal", "context_anomaly",
)


@dataclass(frozen=True, slots=True)
class EdgeFixture:
    destination: str
    edge_type: str
    weight: float
    confidence: float
    evidence_id: str
    direction: str = "outbound"


@dataclass(frozen=True, slots=True)
class GraphFixture:
    partition: str
    family: str
    source_package: str
    label: str
    context: tuple[str, str, str]
    baseline_median: tuple[float, float, float, float]
    edges: tuple[EdgeFixture, ...]


@dataclass(frozen=True, slots=True)
class PolicyCandidate:
    name: str
    weights: tuple[float, float, float, float, float]


def _edge(
    destination: str,
    edge_type: str,
    weight: float,
    confidence: float,
    evidence_id: str,
) -> EdgeFixture:
    return EdgeFixture(destination, edge_type, weight, confidence, evidence_id)


def _generic_edges(prefix: str, count: int, weight: float) -> tuple[EdgeFixture, ...]:
    return tuple(
        _edge(
            f"module:{prefix}:{index}", "generic", weight, 0.95,
            f"{prefix}:generic:{index}",
        )
        for index in range(count)
    )


def _family_edges(family: str, variation: float, package: str) -> tuple[EdgeFixture, ...]:
    if family == "benign_framework":
        count = 24 + int(round(variation * 10.0))
        return _generic_edges(package, count, 0.48 + variation * 0.08)
    if family == "benign_toolchain":
        return _generic_edges(package, 10, 0.42 + variation * 0.05) + (
            _edge("api:ReadFile", "call", 0.42, 0.90, package + ":read"),
            _edge("api:LoadLibrary", "call", 0.46, 0.91, package + ":load"),
        )
    if family == "benign_updater":
        return _generic_edges(package, 7, 0.38 + variation * 0.04) + (
            _edge("api:CreateProcess", "call", 0.68, 0.90, package + ":spawn"),
            _edge("temporal:installer", "temporal", 0.40, 0.80, package + ":time"),
        )
    if family == "malicious_injection":
        return (
            _edge("tag:process_injection", "behavior", 2.70 + variation, 0.98, package + ":behavior"),
            _edge("api:VirtualAllocEx", "call", 3.00, 0.99, package + ":alloc"),
            _edge("api:WriteProcessMemory", "call", 2.90, 0.99, package + ":write"),
            _edge("phase:execution", "attack_phase", 2.50, 0.98, package + ":phase"),
            _edge("temporal:stage2", "temporal", 2.25, 0.95, package + ":temporal"),
        )
    if family == "malicious_persistence":
        return (
            _edge("tag:persistence", "behavior", 2.35 + variation, 0.96, package + ":behavior"),
            _edge("api:RegSetValue", "call", 2.40, 0.96, package + ":registry"),
            _edge("phase:persistence", "attack_phase", 2.50, 0.97, package + ":phase"),
            _edge("temporal:registry_startup", "temporal", 1.90, 0.94, package + ":temporal"),
        )
    if family == "malicious_sparse_execution":
        return (
            _edge("api:VirtualAllocEx", "call", 2.75 + variation, 0.98, package + ":alloc"),
            _edge("tag:process_injection", "behavior", 2.65, 0.97, package + ":behavior"),
        )
    return (
        _edge("api:CreateRemoteThread", "call", 2.45 + variation, 0.96, package + ":thread"),
        _edge("temporal:delayed_execution", "temporal", 2.00, 0.95, package + ":temporal"),
        _edge("phase:execution", "attack_phase", 2.30, 0.95, package + ":phase"),
    )


def _family_contract(family: str) -> tuple[str, tuple[str, str, str], tuple[float, float, float, float]]:
    contracts = {
        "benign_framework": ("benign", ("unity", ".dll", "assembly"), (0.22, 0.58, 0.08, 0.05)),
        "benign_toolchain": ("benign", ("dotnet", ".dll", "assembly"), (0.28, 0.45, 0.12, 0.05)),
        "benign_updater": ("benign", ("installer", ".exe", "binary"), (0.30, 0.40, 0.16, 0.20)),
        "malicious_injection": ("malicious", ("unity", ".exe", "binary"), (0.18, 0.20, 0.08, 0.05)),
        "malicious_persistence": ("malicious", ("generic", ".exe", "binary"), (0.18, 0.20, 0.08, 0.05)),
        "malicious_sparse_execution": ("malicious", ("unknown", ".bin", "binary"), (0.10, 0.10, 0.05, 0.02)),
        "malicious_temporal": ("malicious", ("renpy", ".rpy", "script"), (0.12, 0.18, 0.05, 0.05)),
    }
    return contracts[family]


def _partition(partition: str) -> tuple[GraphFixture, ...]:
    offset = {"train": 0.00, "validation": 0.08, "holdout": 0.16}[partition]
    rows: list[GraphFixture] = []
    families = (
        "benign_framework", "benign_toolchain", "benign_updater",
        "malicious_injection", "malicious_persistence",
        "malicious_sparse_execution", "malicious_temporal",
    )
    for family in families:
        label, context, median = _family_contract(family)
        for index in range(2):
            package = f"{partition}_{family}_source_{index}"
            variation = offset + index * 0.03
            rows.append(GraphFixture(
                partition=partition,
                family=family,
                source_package=package,
                label=label,
                context=context,
                baseline_median=median,
                edges=_family_edges(family, variation, package),
            ))
    return tuple(rows)


_TRAIN = _partition("train")
_VALIDATION = _partition("validation")
_HOLDOUT = _partition("holdout")


def _context(fixture: GraphFixture) -> dict[str, str]:
    engine, extension, node_type = fixture.context
    return {"engine": engine, "extension": extension, "node_type": node_type}


def _context_key(fixture: GraphFixture) -> str:
    engine, extension, node_type = fixture.context
    return f"engine:{engine}|extension:{extension}|node_type:{node_type}"


def _baseline(fixture: GraphFixture) -> dict[str, object]:
    structural, attention, execution, temporal = fixture.baseline_median
    return {
        "version": GRAPH_CONTEXT_BASELINE_VERSION,
        "trusted": True,
        "support_count": 32,
        "context_key": _context_key(fixture),
        "median": {
            "structural": structural,
            "attention": attention,
            "execution": execution,
            "temporal": temporal,
        },
        "iqr": {
            "structural": 0.10,
            "attention": 0.12,
            "execution": 0.10,
            "temporal": 0.10,
        },
    }


def _build_fixture(fixture: GraphFixture, *, reverse: bool = False) -> None:
    reset_graph_state()
    edges = tuple(reversed(fixture.edges)) if reverse else fixture.edges
    for edge in edges:
        add_graph_edge_owned(
            fixture.source_package,
            edge.destination,
            edge.edge_type,
            edge.weight,
            evidence_id=edge.evidence_id,
            confidence=edge.confidence,
            direction=edge.direction,
        )
    update_graph_node_owned(
        fixture.source_package,
        context=_context(fixture),
        context_baseline=_baseline(fixture),
        current_scan_cycle_guard="raw_graph_features_only",
    )


def _production_row(fixture: GraphFixture, *, reverse: bool = False) -> dict[str, object]:
    _build_fixture(fixture, reverse=reverse)
    evidence = get_graph_risk_enhanced_evidence(fixture.source_package)
    components = evidence["components"]
    return {
        "partition": fixture.partition,
        "family": fixture.family,
        "source_package": fixture.source_package,
        "label": fixture.label,
        "risk": float(evidence["risk"]),
        "confidence": float(evidence["confidence"]),
        "snapshot_digest": evidence["snapshot_digest"],
        "cache_key": evidence["cache_key"],
        "components": {
            name: {
                "value": float(components[name]["value"]),
                "maturity": float(components[name]["maturity"]),
                "ready": bool(components[name]["ready"]),
            }
            for name in _COMPONENT_NAMES
        },
    }


def _candidate_policies() -> tuple[PolicyCandidate, ...]:
    return (
        PolicyCandidate("selected_production", (
            GRAPH_RISK_POLICY.structural_weight,
            GRAPH_RISK_POLICY.attention_weight,
            GRAPH_RISK_POLICY.execution_weight,
            GRAPH_RISK_POLICY.temporal_weight,
            GRAPH_RISK_POLICY.anomaly_weight,
        )),
        PolicyCandidate("balanced", (0.34, 0.22, 0.24, 0.12, 0.08)),
        PolicyCandidate("structural_heavy", (0.55, 0.12, 0.18, 0.10, 0.05)),
        PolicyCandidate("attention_heavy", (0.25, 0.40, 0.18, 0.10, 0.07)),
    )


def _candidate_score(row: dict[str, object], candidate: PolicyCandidate) -> float:
    components = row["components"]
    weights = candidate.weights
    total_weight = sum(weights)
    confidence = sum(
        float(components[name]["maturity"]) * weight
        for name, weight in zip(_COMPONENT_NAMES, weights)
        if components[name]["ready"]
    ) / total_weight
    supplemental_weights = weights[1:]
    supplemental_total = sum(supplemental_weights)
    supplemental = sum(
        float(components[name]["value"]) * weight
        for name, weight in zip(_COMPONENT_NAMES[1:], supplemental_weights)
        if components[name]["ready"]
    ) / supplemental_total
    structural = float(components["structural"]["value"])
    return min(1.0, max(0.0, structural + (1.0 - structural) * supplemental * confidence))


def _classification_metrics(rows: tuple[dict[str, object], ...], candidate: PolicyCandidate) -> dict[str, object]:
    threshold = GRAPH_RISK_POLICY.decision_threshold
    scored = tuple((row, _candidate_score(row, candidate)) for row in rows)
    tp = sum(row["label"] == "malicious" and score >= threshold for row, score in scored)
    tn = sum(row["label"] == "benign" and score < threshold for row, score in scored)
    fp = sum(row["label"] == "benign" and score >= threshold for row, score in scored)
    fn = sum(row["label"] == "malicious" and score < threshold for row, score in scored)
    malicious_scores = tuple(score for row, score in scored if row["label"] == "malicious")
    benign_scores = tuple(score for row, score in scored if row["label"] == "benign")
    recall = tp / max(1, tp + fn)
    false_positive_rate = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    accuracy = (tp + tn) / max(1, len(scored))
    margin = min(malicious_scores) - max(benign_scores)
    return {
        "candidate": candidate.name,
        "threshold": threshold,
        "accuracy": accuracy,
        "precision": precision,
        "malicious_recall": recall,
        "false_positive_rate": false_positive_rate,
        "separation_margin": margin,
        "minimum_malicious_score": min(malicious_scores),
        "maximum_benign_score": max(benign_scores),
        "rows": tuple({
            "source_package": row["source_package"],
            "family": row["family"],
            "label": row["label"],
            "score": score,
            "prediction": "malicious" if score >= threshold else "benign",
        } for row, score in scored),
    }


def _partition_evidence() -> dict[str, object]:
    partitions = {"train": _TRAIN, "validation": _VALIDATION, "holdout": _HOLDOUT}
    sources = {
        name: {row.source_package for row in rows}
        for name, rows in partitions.items()
    }
    overlap = sum(
        len(sources[left] & sources[right])
        for left, right in (("train", "validation"), ("train", "holdout"), ("validation", "holdout"))
    )
    return {
        "source_package_overlap_count": overlap,
        "counts": {name: len(rows) for name, rows in partitions.items()},
        "families": tuple(sorted({row.family for row in _TRAIN})),
    }


def _incremental_component_value(rows: tuple[dict[str, object], ...]) -> dict[str, float]:
    candidate = _candidate_policies()[0]
    malicious = tuple(row for row in rows if row["label"] == "malicious")
    out: dict[str, float] = {}
    for component_name in _COMPONENT_NAMES[1:]:
        deltas: list[float] = []
        for row in malicious:
            full = _candidate_score(row, candidate)
            copied = {**row, "components": {
                name: dict(values) for name, values in row["components"].items()
            }}
            copied["components"][component_name]["value"] = 0.0
            deltas.append(max(0.0, full - _candidate_score(copied, candidate)))
        out[component_name] = sum(deltas) / max(1, len(deltas))
    return out


def _digest_metrics(row: dict[str, object]) -> str:
    payload = {
        "risk": row["risk"],
        "confidence": row["confidence"],
        "components": row["components"],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def replay_digest() -> str:
    return _digest_metrics(_production_row(_HOLDOUT[-1]))


def _process_determinism() -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    command = [sys.executable, "-m", "tools.evaluation.evaluate_graph_model", "--replay-digest"]
    outputs: list[str] = []
    for _index in range(2):
        completed = subprocess.run(
            command,
            cwd=root,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        outputs.append(completed.stdout.strip())
    return {"digests": tuple(outputs), "deterministic": outputs[0] == outputs[1]}


def _cache_evidence() -> dict[str, object]:
    fixture = _VALIDATION[3]
    _build_fixture(fixture)
    first = get_graph_risk_enhanced_evidence(fixture.source_package)
    second = get_graph_risk_enhanced_evidence(fixture.source_package)
    add_graph_edge_owned(
        fixture.source_package, "module:cache-mutation", "generic", 0.5,
        evidence_id=fixture.source_package + ":cache-mutation", confidence=0.9,
    )
    third = get_graph_risk_enhanced_evidence(fixture.source_package)
    return {
        "first_source": first["source"],
        "second_source": second["source"],
        "third_source": third["source"],
        "first_cache_key": first["cache_key"],
        "third_cache_key": third["cache_key"],
        "first_snapshot_digest": first["snapshot_digest"],
        "third_snapshot_digest": third["snapshot_digest"],
        "hit_correct": second["source"] == "cache" and second["risk"] == first["risk"],
        "mutation_invalidated": (
            third["source"] == "snapshot"
            and third["cache_key"] != first["cache_key"]
            and third["snapshot_digest"] != first["snapshot_digest"]
        ),
    }


def _corruption_evidence() -> dict[str, object]:
    fixture = _VALIDATION[0]
    _build_fixture(fixture)
    snapshot = graph_node_snapshot(fixture.source_package)
    forged = dict(snapshot or {})
    forged["snapshot_digest"] = "0" * 64
    admitted, reason = admitted_graph_snapshot(forged)
    return {"admitted": admitted is not None, "reason": reason}


def _duplicate_stability() -> dict[str, object]:
    context = ("generic", ".bin", "binary")
    median = (0.10, 0.10, 0.05, 0.02)
    one = GraphFixture(
        "validation", "duplicate_control", "duplicate_control_source", "benign",
        context, median,
        (_edge("tag:one", "tag", 1.0, 0.9, "shared-root"),),
    )
    many = GraphFixture(
        "validation", "duplicate_aliases", "duplicate_alias_source", "benign",
        context, median,
        tuple(_edge(f"tag:alias:{index}", "tag", 1.0, 0.9, "shared-root") for index in range(10)),
    )
    one_row = _production_row(one)
    many_row = _production_row(many)
    return {
        "control_risk": one_row["risk"],
        "alias_risk": many_row["risk"],
        "control_digest": _digest_metrics(one_row),
        "alias_digest": _digest_metrics(many_row),
        "stable": _digest_metrics(one_row) == _digest_metrics(many_row),
    }


def _replay_evidence() -> dict[str, object]:
    fixture = _HOLDOUT[-1]
    first = _production_row(fixture)
    second = _production_row(fixture)
    reverse = _production_row(fixture, reverse=True)
    return {
        "first_metric_digest": _digest_metrics(first),
        "second_metric_digest": _digest_metrics(second),
        "reverse_metric_digest": _digest_metrics(reverse),
        "first_snapshot_digest": first["snapshot_digest"],
        "second_snapshot_digest": second["snapshot_digest"],
        "reverse_snapshot_digest": reverse["snapshot_digest"],
        "exact_replay_deterministic": (
            _digest_metrics(first) == _digest_metrics(second)
            and first["snapshot_digest"] == second["snapshot_digest"]
        ),
        "order_metric_deterministic": _digest_metrics(first) == _digest_metrics(reverse),
        "order_provenance_distinct": first["snapshot_digest"] != reverse["snapshot_digest"],
    }


def _resource_evidence() -> dict[str, object]:
    reset_graph_state()
    node = "adversarial_graph_source"
    started = perf_counter()
    for index in range(GRAPH_RISK_POLICY.maximum_attention_work + 50):
        add_graph_edge_owned(
            node, f"adversarial:{index}", "generic", 0.5,
            evidence_id=f"adversarial-evidence:{index}", confidence=0.9,
        )
    update_graph_node_owned(
        node,
        context={"engine": "generic", "extension": ".bin", "node_type": "binary"},
        current_scan_cycle_guard="raw_graph_features_only",
    )
    attention = graph_attention_evidence(node)
    elapsed = perf_counter() - started
    before = graph_node_snapshot(node)
    before_count = len(before["edge_records"]) if before is not None else 0
    prune_graph(max_nodes=GRAPH_RISK_POLICY.maximum_attention_work + 60, max_edges_per_node=200)
    after = graph_node_snapshot(node)
    after_count = len(after["edge_records"]) if after is not None else 0
    return {
        "attention": attention.value,
        "attention_ready": attention.ready,
        "work_limit": GRAPH_RISK_POLICY.maximum_attention_work,
        "edge_count_before_prune": before_count,
        "edge_count_after_prune": after_count,
        "runtime_seconds": elapsed,
        "bounded": (
            attention.ready
            and 0.0 <= attention.value <= 1.0
            and before_count == GRAPH_RISK_POLICY.maximum_attention_work + 50
            and after_count <= 200
            and elapsed <= 10.0
        ),
    }


def evaluate_graph_model() -> dict[str, object]:
    started = perf_counter()
    train_rows = tuple(_production_row(fixture) for fixture in _TRAIN)
    validation_rows = tuple(_production_row(fixture) for fixture in _VALIDATION)
    holdout_rows = tuple(_production_row(fixture) for fixture in _HOLDOUT)
    candidates = tuple(
        _classification_metrics(validation_rows, candidate)
        for candidate in _candidate_policies()
    )
    selected = max(candidates, key=lambda row: (
        float(row["accuracy"]),
        float(row["malicious_recall"]),
        -float(row["false_positive_rate"]),
        float(row["separation_margin"]),
        row["candidate"] == "selected_production",
    ))
    holdout = _classification_metrics(holdout_rows, _candidate_policies()[0])
    incremental = _incremental_component_value(holdout_rows)
    cache = _cache_evidence()
    corruption = _corruption_evidence()
    duplicate = _duplicate_stability()
    replay = _replay_evidence()
    process = _process_determinism()
    resources = _resource_evidence()
    high_degree_rows = tuple(row for row in holdout["rows"] if row["family"] == "benign_framework")
    execution_rows = tuple(row for row in holdout_rows if row["label"] == "malicious")
    execution_recall = sum(
        row["risk"] >= GRAPH_RISK_POLICY.decision_threshold
        and row["components"]["execution"]["value"] > 0.0
        for row in execution_rows
    ) / max(1, len(execution_rows))
    elapsed = perf_counter() - started
    acceptance = {
        "partition_isolated": _partition_evidence()["source_package_overlap_count"] == 0,
        "selected_policy_wins_validation": selected["candidate"] == "selected_production",
        "holdout_accuracy": holdout["accuracy"] >= 0.95,
        "malicious_recall": holdout["malicious_recall"] >= 0.95,
        "benign_false_positive_rate": holdout["false_positive_rate"] <= 0.05,
        "high_degree_benign_false_positive": all(row["prediction"] == "benign" for row in high_degree_rows),
        "execution_detection_recall": execution_recall >= 0.90,
        "component_incremental_value": (
            incremental["attention"] > 0.0
            and incremental["execution"] > 0.0
            and incremental["temporal"] > 0.0
            and incremental["context_anomaly"] > 0.0
        ),
        "corruption_fails_closed": corruption["admitted"] is False and corruption["reason"] == "graph_snapshot_digest_mismatch",
        "cache_hit_correct": cache["hit_correct"] is True,
        "cache_mutation_invalidation": cache["mutation_invalidated"] is True,
        "duplicate_evidence_stable": duplicate["stable"] is True,
        "exact_replay_deterministic": replay["exact_replay_deterministic"] is True,
        "order_metric_deterministic": replay["order_metric_deterministic"] is True,
        "process_deterministic": process["deterministic"] is True,
        "resource_bounds": resources["bounded"] is True,
        "runtime_bound": elapsed <= 20.0,
    }
    reset_graph_state()
    return {
        "evaluation_version": EVALUATION_VERSION,
        "policy_version": GRAPH_RISK_POLICY_VERSION,
        "policy_selection_evidence": GRAPH_RISK_POLICY.selection_evidence,
        "decision_threshold": GRAPH_RISK_POLICY.decision_threshold,
        "partition_evidence": _partition_evidence(),
        "train": _classification_metrics(train_rows, _candidate_policies()[0]),
        "validation_candidates": candidates,
        "selected_validation_candidate": selected,
        "holdout": holdout,
        "incremental_component_value": incremental,
        "execution_detection_recall": execution_recall,
        "cache_correctness": cache,
        "corruption_behavior": corruption,
        "duplicate_evidence_stability": duplicate,
        "replay_determinism": replay,
        "process_determinism": process,
        "resource_bounds": resources,
        "runtime_seconds": elapsed,
        "runtime_bound_seconds": 20.0,
        "acceptance": acceptance,
        "all_acceptance_passed": all(acceptance.values()),
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--replay-digest"]:
        print(replay_digest())
        return 0
    print(json.dumps(evaluate_graph_model(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
