"""Deterministic, inert-fixture evaluation of canonical YARA scan behavior.

This module is evaluation-only.  It exercises the production ``yara_scan``
entry point with an inert compiled-rules fixture and approved labeled metadata;
it does not own detector logic, load runtime state, or claim effectiveness for an
external rule corpus that was not supplied and measured.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from math import ceil
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter_ns
import tracemalloc

from Virus_Scan.yara.contracts import YaraRuleLoadResult
from Virus_Scan.yara.match import normalize_yara_hits, yara_scan

EVALUATION_VERSION = "stage2636_05_yara_corpus_evaluation_v1"
CORPUS_VERSION = "stage2636_05_yara_inert_labeled_fixture_v1"
_PACKAGE_KINDS = ("full", "light")
_LABELS = ("benign", "malicious")
_MAX_PAYLOAD_BYTES = 1 << 20
_RUNTIME_EXCLUDED_FIELDS = frozenset(("latency", "memory"))


def _exact_text(value: object, reason: str, *, maximum: int = 256) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.strip(str.__str__(value))
    if not text or len(text) > maximum:
        raise ValueError(reason)
    return text


def _ordered_labels(value: object, reason: str) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(reason)
    labels = tuple(_exact_text(item, reason, maximum=128) for item in value)
    if labels != tuple(sorted(set(labels))):
        raise ValueError(reason)
    return labels


@dataclass(frozen=True, slots=True)
class YaraEvaluationRule:
    package_kind: str
    rule_id: str
    source_member: str
    marker: bytes
    family_labels: tuple[str, ...]
    behavior_labels: tuple[str, ...]
    review_ordinal: int

    def __post_init__(self) -> None:
        if type(self) is not YaraEvaluationRule:
            raise TypeError("yara_evaluation_rule_owner_invalid")
        package = _exact_text(self.package_kind, "yara_evaluation_package_invalid", maximum=16)
        if package not in _PACKAGE_KINDS:
            raise ValueError("yara_evaluation_package_invalid")
        if type(self.marker) is not bytes or not self.marker or len(self.marker) > 256:
            raise ValueError("yara_evaluation_rule_marker_invalid")
        if type(self.review_ordinal) is not int or type(self.review_ordinal) is bool or self.review_ordinal < 0:
            raise ValueError("yara_evaluation_review_ordinal_invalid")
        object.__setattr__(self, "package_kind", package)
        object.__setattr__(self, "rule_id", _exact_text(self.rule_id, "yara_evaluation_rule_id_invalid", maximum=160))
        object.__setattr__(self, "source_member", _exact_text(self.source_member, "yara_evaluation_member_invalid", maximum=512))
        object.__setattr__(self, "marker", bytes(self.marker))
        object.__setattr__(self, "family_labels", _ordered_labels(self.family_labels, "yara_evaluation_family_labels_invalid"))
        object.__setattr__(self, "behavior_labels", _ordered_labels(self.behavior_labels, "yara_evaluation_behavior_labels_invalid"))


@dataclass(frozen=True, slots=True)
class YaraEvaluationSample:
    package_kind: str
    sample_id: str
    label: str
    payload: bytes
    expected_families: tuple[str, ...]
    expected_behaviors: tuple[str, ...]
    non_yara_detected: bool

    def __post_init__(self) -> None:
        if type(self) is not YaraEvaluationSample:
            raise TypeError("yara_evaluation_sample_owner_invalid")
        package = _exact_text(self.package_kind, "yara_evaluation_package_invalid", maximum=16)
        if package not in _PACKAGE_KINDS:
            raise ValueError("yara_evaluation_package_invalid")
        label = _exact_text(self.label, "yara_evaluation_label_invalid", maximum=16)
        if label not in _LABELS:
            raise ValueError("yara_evaluation_label_invalid")
        if type(self.payload) is not bytes or not self.payload or len(self.payload) > _MAX_PAYLOAD_BYTES:
            raise ValueError("yara_evaluation_payload_invalid")
        if type(self.non_yara_detected) is not bool:
            raise TypeError("yara_evaluation_non_yara_state_invalid")
        families = _ordered_labels(self.expected_families, "yara_evaluation_expected_families_invalid")
        behaviors = _ordered_labels(self.expected_behaviors, "yara_evaluation_expected_behaviors_invalid")
        if label == "benign" and (families or behaviors):
            raise ValueError("yara_evaluation_benign_labels_invalid")
        if label == "malicious" and not (families or behaviors):
            raise ValueError("yara_evaluation_malicious_labels_missing")
        object.__setattr__(self, "package_kind", package)
        object.__setattr__(self, "sample_id", _exact_text(self.sample_id, "yara_evaluation_sample_id_invalid", maximum=160))
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "payload", bytes(self.payload))
        object.__setattr__(self, "expected_families", families)
        object.__setattr__(self, "expected_behaviors", behaviors)


@dataclass(frozen=True, slots=True)
class YaraEvaluationCorpus:
    package_kind: str
    load_result: YaraRuleLoadResult
    rules: tuple[YaraEvaluationRule, ...]
    samples: tuple[YaraEvaluationSample, ...]
    current_review_ordinal: int
    stale_after_ordinals: int
    provenance: str

    def __post_init__(self) -> None:
        if type(self) is not YaraEvaluationCorpus:
            raise TypeError("yara_evaluation_corpus_owner_invalid")
        package = _exact_text(self.package_kind, "yara_evaluation_package_invalid", maximum=16)
        if package not in _PACKAGE_KINDS:
            raise ValueError("yara_evaluation_package_invalid")
        if type(self.load_result) is not YaraRuleLoadResult:
            raise TypeError("yara_evaluation_load_result_invalid")
        if type(self.rules) is not tuple or not self.rules or any(type(item) is not YaraEvaluationRule for item in self.rules):
            raise TypeError("yara_evaluation_rules_invalid")
        if type(self.samples) is not tuple or not self.samples or any(type(item) is not YaraEvaluationSample for item in self.samples):
            raise TypeError("yara_evaluation_samples_invalid")
        if any(item.package_kind != package for item in self.rules + self.samples):
            raise ValueError("yara_evaluation_package_partition_invalid")
        sample_ids = tuple(item.sample_id for item in self.samples)
        if sample_ids != tuple(sorted(sample_ids)) or len(sample_ids) != len(set(sample_ids)):
            raise ValueError("yara_evaluation_sample_order_invalid")
        if type(self.current_review_ordinal) is not int or type(self.current_review_ordinal) is bool or self.current_review_ordinal < 1:
            raise ValueError("yara_evaluation_current_review_ordinal_invalid")
        if type(self.stale_after_ordinals) is not int or type(self.stale_after_ordinals) is bool or self.stale_after_ordinals < 1:
            raise ValueError("yara_evaluation_stale_window_invalid")
        object.__setattr__(self, "package_kind", package)
        object.__setattr__(self, "provenance", _exact_text(self.provenance, "yara_evaluation_provenance_invalid", maximum=256))


class _InertMatch:
    """Primitive match carrier for the canonical physical YARA boundary."""

    __slots__ = ("meta", "namespace", "rule", "tags")

    def __init__(self, rule: str) -> None:
        self.rule = rule
        self.namespace = "inert_evaluation_fixture"
        self.meta = {}
        self.tags = ()


class _InertCompiledRules:
    """Evaluation fixture implementing only the yara-python ``match`` surface."""

    __slots__ = ("_rules",)

    def __init__(self, rules: tuple[YaraEvaluationRule, ...]) -> None:
        if type(rules) is not tuple or any(type(item) is not YaraEvaluationRule for item in rules):
            raise TypeError("yara_evaluation_compiled_rules_invalid")
        self._rules = rules

    def match(self, path: object) -> tuple[str, ...]:
        if type(path) is not str:
            raise TypeError("yara_evaluation_scan_path_invalid")
        payload = Path(path).read_bytes()
        return tuple(
            _InertMatch(rule.rule_id)
            for rule in self._rules
            if rule.marker in payload
        )


def _ratio(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else round(numerator / denominator, 6)


def _percentile(values: tuple[int, ...], percentile: float) -> int:
    if not values:
        return 0
    ordered = tuple(sorted(values))
    index = max(0, min(len(ordered) - 1, ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def _rule_index(rules: tuple[YaraEvaluationRule, ...]) -> dict[str, tuple[YaraEvaluationRule, ...]]:
    grouped: dict[str, list[YaraEvaluationRule]] = {}
    for rule in rules:
        grouped.setdefault(rule.rule_id, []).append(rule)
    return {key: tuple(value) for key, value in sorted(grouped.items())}


def _sample_projection(
    sample: YaraEvaluationSample,
    rules: _InertCompiledRules,
    path: Path,
) -> dict[str, object]:
    path.write_bytes(sample.payload)
    tracemalloc.start()
    started = perf_counter_ns()
    try:
        hits = tuple(normalize_yara_hits(yara_scan(str(path), compiled_rules=rules)))
        elapsed = perf_counter_ns() - started
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "sample_id": sample.sample_id,
        "label": sample.label,
        "expected_families": sample.expected_families,
        "expected_behaviors": sample.expected_behaviors,
        "non_yara_detected": sample.non_yara_detected,
        "hits": hits,
        "latency_ns": elapsed,
        "peak_memory_bytes": peak,
    }


def _semantic_row(row: dict[str, object]) -> dict[str, object]:
    return {
        key: value for key, value in row.items()
        if key not in ("latency_ns", "peak_memory_bytes")
    }


def _evaluate_corpus(corpus: YaraEvaluationCorpus) -> dict[str, object]:
    compiled = _InertCompiledRules(corpus.rules)
    with TemporaryDirectory(prefix=f"yara-{corpus.package_kind}-evaluation-") as temporary:
        root = Path(temporary)
        rows = tuple(
            _sample_projection(sample, compiled, root / f"sample-{index}.bin")
            for index, sample in enumerate(corpus.samples)
        )
    index = _rule_index(corpus.rules)
    rule_ids = tuple(rule.rule_id for rule in corpus.rules)
    duplicates = tuple(rule_id for rule_id, entries in index.items() if len(entries) > 1)
    observed = tuple(sorted({hit for row in rows for hit in row["hits"]}))
    unreachable = tuple(sorted(set(rule_ids) - set(observed)))
    stale_floor = corpus.current_review_ordinal - corpus.stale_after_ordinals
    stale = tuple(sorted({rule.rule_id for rule in corpus.rules if rule.review_ordinal < stale_floor}))

    true_positive = sum(row["label"] == "malicious" and bool(row["hits"]) for row in rows)
    false_positive = sum(row["label"] == "benign" and bool(row["hits"]) for row in rows)
    true_negative = sum(row["label"] == "benign" and not row["hits"] for row in rows)
    false_negative = sum(row["label"] == "malicious" and not row["hits"] for row in rows)

    expected_family_count = 0
    covered_family_count = 0
    expected_behavior_count = 0
    covered_behavior_count = 0
    for row in rows:
        hit_rules = tuple(rule for hit in row["hits"] for rule in index.get(hit, ()))
        hit_families = {label for rule in hit_rules for label in rule.family_labels}
        hit_behaviors = {label for rule in hit_rules for label in rule.behavior_labels}
        expected_families = tuple(row["expected_families"])
        expected_behaviors = tuple(row["expected_behaviors"])
        expected_family_count += len(expected_families)
        covered_family_count += sum(label in hit_families for label in expected_families)
        expected_behavior_count += len(expected_behaviors)
        covered_behavior_count += sum(label in hit_behaviors for label in expected_behaviors)

    malicious_rows = tuple(row for row in rows if row["label"] == "malicious")
    baseline_detected = sum(bool(row["non_yara_detected"]) for row in malicious_rows)
    combined_detected = sum(bool(row["non_yara_detected"]) or bool(row["hits"]) for row in malicious_rows)
    yara_only = sum(not row["non_yara_detected"] and bool(row["hits"]) for row in malicious_rows)

    latencies = tuple(int(row["latency_ns"]) for row in rows)
    memories = tuple(int(row["peak_memory_bytes"]) for row in rows)
    total = corpus.load_result.total_members
    semantic_rows = tuple(_semantic_row(row) for row in rows)
    semantic_payload = {
        "package_kind": corpus.package_kind,
        "compile": {
            "state": corpus.load_result.state,
            "total_members": total,
            "compiled_members": corpus.load_result.compiled_members,
            "failed_members": corpus.load_result.failed_members,
        },
        "rules": tuple({
            "rule_id": rule.rule_id,
            "source_member": rule.source_member,
            "family_labels": rule.family_labels,
            "behavior_labels": rule.behavior_labels,
            "review_ordinal": rule.review_ordinal,
            "marker_sha256": sha256(rule.marker).hexdigest(),
        } for rule in corpus.rules),
        "rows": semantic_rows,
        "duplicate_rule_identifiers": duplicates,
        "stale_rule_identifiers": stale,
        "unreachable_rule_identifiers": unreachable,
    }
    return {
        "package_kind": corpus.package_kind,
        "provenance": corpus.provenance,
        "corpus_quality_scope": "inert_fixture_contract_only",
        "external_rule_corpus_quality_claimed": False,
        "compile": {
            "state": corpus.load_result.state,
            "total_members": total,
            "compiled_members": corpus.load_result.compiled_members,
            "failed_members": corpus.load_result.failed_members,
            "success_rate": _ratio(corpus.load_result.compiled_members, total),
            "failure_samples": corpus.load_result.failure_samples,
        },
        "rule_identity": {
            "record_count": len(corpus.rules),
            "unique_rule_identifier_count": len(index),
            "duplicate_rule_identifier_count": len(duplicates),
            "duplicate_rule_identifiers": duplicates,
        },
        "classification": {
            "sample_count": len(rows),
            "malicious_count": len(malicious_rows),
            "benign_count": len(rows) - len(malicious_rows),
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "precision": _ratio(true_positive, true_positive + false_positive),
            "recall": _ratio(true_positive, true_positive + false_negative),
            "benign_false_positive_rate": _ratio(false_positive, false_positive + true_negative),
        },
        "coverage": {
            "expected_family_label_count": expected_family_count,
            "covered_family_label_count": covered_family_count,
            "family_coverage_rate": _ratio(covered_family_count, expected_family_count),
            "expected_behavior_label_count": expected_behavior_count,
            "covered_behavior_label_count": covered_behavior_count,
            "behavior_coverage_rate": _ratio(covered_behavior_count, expected_behavior_count),
        },
        "incremental_benefit": {
            "malicious_sample_count": len(malicious_rows),
            "non_yara_detected_count": baseline_detected,
            "combined_detected_count": combined_detected,
            "yara_only_detected_count": yara_only,
            "non_yara_recall": _ratio(baseline_detected, len(malicious_rows)),
            "combined_recall": _ratio(combined_detected, len(malicious_rows)),
            "recall_delta": round(
                _ratio(combined_detected, len(malicious_rows))
                - _ratio(baseline_detected, len(malicious_rows)), 6,
            ),
        },
        "rule_health_indicators": {
            "current_review_ordinal": corpus.current_review_ordinal,
            "stale_after_ordinals": corpus.stale_after_ordinals,
            "stale_rule_count": len(stale),
            "stale_rule_identifiers": stale,
            "unreachable_rule_count": len(unreachable),
            "unreachable_rule_identifiers": unreachable,
            "stale_and_unreachable_identifiers": tuple(sorted(set(stale) & set(unreachable))),
        },
        "latency": {
            "sample_count": len(latencies),
            "minimum_ns": min(latencies, default=0),
            "median_ns": int(median(latencies)) if latencies else 0,
            "p95_ns": _percentile(latencies, 0.95),
            "maximum_ns": max(latencies, default=0),
        },
        "memory": {
            "sample_count": len(memories),
            "maximum_peak_bytes": max(memories, default=0),
            "median_peak_bytes": int(median(memories)) if memories else 0,
        },
        "sample_results": semantic_rows,
        "semantic_digest": sha256(json.dumps(
            semantic_payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest(),
    }


def _load_result(total: int) -> YaraRuleLoadResult:
    return YaraRuleLoadResult(
        state="fully_compiled",
        ready=True,
        total_members=total,
        compiled_members=total,
        failed_members=0,
        acceptance_threshold=0.80,
        failure_samples=(),
        reason="",
    )


def _fixture_corpora() -> tuple[YaraEvaluationCorpus, YaraEvaluationCorpus]:
    full_rules = (
        YaraEvaluationRule("full", "full_alpha_signature", "full/alpha.yar", b"UMIGE_YARA_EVAL_ALPHA", ("family_alpha",), ("payload_marker",), 9),
        YaraEvaluationRule("full", "full_beta_signature", "full/beta.yar", b"UMIGE_YARA_EVAL_BETA", ("family_beta",), ("script_marker",), 9),
        YaraEvaluationRule("full", "full_shared_behavior", "full/shared.yar", b"UMIGE_YARA_EVAL_SHARED", ("family_alpha", "family_beta"), ("shared_behavior",), 8),
        YaraEvaluationRule("full", "full_unreachable_legacy", "full/legacy.yar", b"UMIGE_YARA_EVAL_UNUSED_FULL", ("legacy_fixture",), ("legacy_behavior",), 1),
    )
    full_samples = tuple(sorted((
        YaraEvaluationSample("full", "full-benign-document", "benign", b"approved benign document control", (), (), False),
        YaraEvaluationSample("full", "full-benign-image", "benign", b"approved benign image metadata control", (), (), False),
        YaraEvaluationSample("full", "full-malicious-alpha", "malicious", b"inert fixture UMIGE_YARA_EVAL_ALPHA", ("family_alpha",), ("payload_marker",), False),
        YaraEvaluationSample("full", "full-malicious-beta", "malicious", b"inert fixture UMIGE_YARA_EVAL_BETA", ("family_beta",), ("script_marker",), True),
        YaraEvaluationSample("full", "full-malicious-shared", "malicious", b"inert fixture UMIGE_YARA_EVAL_SHARED", ("family_alpha", "family_beta"), ("shared_behavior",), False),
    ), key=lambda item: item.sample_id))
    light_rules = (
        YaraEvaluationRule("light", "light_alpha_signature", "light/alpha.yar", b"UMIGE_YARA_EVAL_ALPHA", ("family_alpha",), ("payload_marker",), 9),
        YaraEvaluationRule("light", "light_shared_behavior", "light/shared.yar", b"UMIGE_YARA_EVAL_SHARED", ("family_alpha", "family_beta"), ("shared_behavior",), 8),
        YaraEvaluationRule("light", "light_unreachable_legacy", "light/legacy.yar", b"UMIGE_YARA_EVAL_UNUSED_LIGHT", ("legacy_fixture",), ("legacy_behavior",), 1),
    )
    light_samples = tuple(sorted((
        YaraEvaluationSample("light", "light-benign-document", "benign", b"approved benign light document control", (), (), False),
        YaraEvaluationSample("light", "light-benign-image", "benign", b"approved benign light image control", (), (), False),
        YaraEvaluationSample("light", "light-malicious-alpha", "malicious", b"inert fixture UMIGE_YARA_EVAL_ALPHA", ("family_alpha",), ("payload_marker",), False),
        YaraEvaluationSample("light", "light-malicious-shared", "malicious", b"inert fixture UMIGE_YARA_EVAL_SHARED", ("family_alpha", "family_beta"), ("shared_behavior",), True),
    ), key=lambda item: item.sample_id))
    provenance = "approved_inert_metadata_no_live_malware"
    return (
        YaraEvaluationCorpus("full", _load_result(len(full_rules)), full_rules, full_samples, 10, 4, provenance),
        YaraEvaluationCorpus("light", _load_result(len(light_rules)), light_rules, light_samples, 10, 4, provenance),
    )


def acceptance(report: dict[str, object]) -> dict[str, bool]:
    if type(report) is not dict:
        raise TypeError("yara_evaluation_report_invalid")
    packages = report.get("packages")
    if type(packages) is not dict:
        raise TypeError("yara_evaluation_packages_invalid")
    rows = tuple(packages[kind] for kind in _PACKAGE_KINDS)
    return {
        "full_and_light_reported_separately": tuple(sorted(packages)) == _PACKAGE_KINDS,
        "fixture_scope_is_explicit": all(
            row["corpus_quality_scope"] == "inert_fixture_contract_only"
            and row["external_rule_corpus_quality_claimed"] is False
            for row in rows
        ),
        "compile_success": all(row["compile"]["success_rate"] == 1.0 for row in rows),
        "duplicate_rule_identifiers": all(row["rule_identity"]["duplicate_rule_identifier_count"] == 0 for row in rows),
        "benign_precision": all(
            row["classification"]["precision"] == 1.0
            and row["classification"]["benign_false_positive_rate"] == 0.0
            for row in rows
        ),
        "family_coverage": all(row["coverage"]["family_coverage_rate"] == 1.0 for row in rows),
        "behavior_coverage": all(row["coverage"]["behavior_coverage_rate"] == 1.0 for row in rows),
        "incremental_benefit": all(row["incremental_benefit"]["recall_delta"] > 0.0 for row in rows),
        "stale_and_unreachable_indicators": all(
            row["rule_health_indicators"]["stale_rule_count"] > 0
            and row["rule_health_indicators"]["unreachable_rule_count"] > 0
            and row["rule_health_indicators"]["stale_and_unreachable_identifiers"]
            for row in rows
        ),
        "latency_bound": all(row["latency"]["maximum_ns"] < 1_000_000_000 for row in rows),
        "memory_bound": all(row["memory"]["maximum_peak_bytes"] < 16 * 1024 * 1024 for row in rows),
    }


def evaluate_yara_rules() -> dict[str, object]:
    corpora = _fixture_corpora()
    packages = {corpus.package_kind: _evaluate_corpus(corpus) for corpus in corpora}
    manifest = {
        "evaluation_version": EVALUATION_VERSION,
        "corpus_version": CORPUS_VERSION,
        "fixture_provenance": "approved_inert_metadata_no_live_malware",
        "production_entry_point": "Virus_Scan.yara.match.yara_scan",
        "evaluation_owner": "tools.evaluation.evaluate_yara_rules",
        "runtime_state_mutated": False,
        "packages": packages,
    }
    stable_payload = {
        "evaluation_version": manifest["evaluation_version"],
        "corpus_version": manifest["corpus_version"],
        "fixture_provenance": manifest["fixture_provenance"],
        "production_entry_point": manifest["production_entry_point"],
        "evaluation_owner": manifest["evaluation_owner"],
        "runtime_state_mutated": manifest["runtime_state_mutated"],
        "packages": {
            kind: {
                key: value for key, value in packages[kind].items()
                if key not in _RUNTIME_EXCLUDED_FIELDS
            }
            for kind in _PACKAGE_KINDS
        },
    }
    manifest["manifest_digest"] = sha256(json.dumps(
        stable_payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()
    gates = acceptance(manifest)
    manifest["acceptance"] = gates
    manifest["all_acceptance_passed"] = all(gates.values())
    return manifest


def main() -> int:
    report = evaluate_yara_rules()
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0 if report["all_acceptance_passed"] else 1


__all__ = (
    "CORPUS_VERSION",
    "EVALUATION_VERSION",
    "YaraEvaluationCorpus",
    "YaraEvaluationRule",
    "YaraEvaluationSample",
    "acceptance",
    "evaluate_yara_rules",
    "main",
)


if __name__ == "__main__":
    raise SystemExit(main())
