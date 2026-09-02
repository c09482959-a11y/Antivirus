"""Deterministic evaluation of the canonical attack-intelligence ensemble.

The evaluator owns fixtures, partitions, and metrics only. Classifier evidence,
calibration, YARA integrity, correlation grouping, and aggregation are exercised
through the production owners.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from math import fsum
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.contracts.yara_hits import YaraHit, YaraRuleIdentity, YaraScanResult
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_policy import (
    ATTACK_ENSEMBLE_POLICY, ATTACK_INTELLIGENCE_CALIBRATION_VERSION,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_inputs import (
    AttackIntelligenceYaraFamilyAlignment,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIERS,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)

EVALUATION_VERSION = "stage2636_11020_attack_intelligence_evaluation_v4"
CORPUS_VERSION = "stage2636_11020_atomic_family_source_corpus_v2"
_SPLITS = ("train", "validation", "holdout")


@dataclass(frozen=True, slots=True)
class AttackFixture:
    sample_id: str
    partition: str
    source_family: str
    expected_families: tuple[str, ...]
    tags: tuple[str, ...]


def _fixture(
    sample_id: str,
    partition: str,
    source_family: str,
    expected_families: tuple[str, ...],
    tags: tuple[str, ...],
) -> AttackFixture:
    return AttackFixture(sample_id, partition, source_family, expected_families, tags)


def _family_fixtures() -> tuple[AttackFixture, ...]:
    """Return group-isolated atomic-evidence family fixtures."""
    rows = (
        ("train", "lateral_movement", ("lateral_movement",), ("admin_share_access", "remote_service_creation")),
        ("train", "lateral_movement", ("lateral_movement",), ("admin_share_access", "remote_service_creation", "psexec_usage")),
        ("validation", "lateral_movement", ("lateral_movement",), ("admin_share_access", "remote_service_creation", "winrm_exec")),
        ("validation", "lateral_movement", ("lateral_movement",), ("admin_share_access", "remote_service_creation", "impacket_exec")),
        ("holdout", "lateral_movement", ("lateral_movement",), ("admin_share_access", "remote_service_creation", "smb_activity")),
        ("holdout", "lateral_movement", ("lateral_movement",), ("admin_share_access", "remote_service_creation", "rdp_enable_or_use")),
        ("train", "defense_evasion", ("defense_evasion",), ("defender_disable",)),
        ("train", "defense_evasion", ("defense_evasion",), ("security_service_disable",)),
        ("validation", "defense_evasion", ("defense_evasion",), ("tamper_protection_disable",)),
        ("validation", "defense_evasion", ("defense_evasion",), ("defender_disable", "log_clearing")),
        ("holdout", "defense_evasion", ("defense_evasion",), ("security_process_kill",)),
        ("holdout", "defense_evasion", ("defense_evasion",), ("security_service_disable", "shadowcopy_delete")),
        ("train", "exfiltration", ("exfiltration",), ("http_upload", "dns_tunneling")),
        ("train", "exfiltration", ("exfiltration",), ("http_upload", "dns_tunneling", "file_collection")),
        ("validation", "exfiltration", ("exfiltration",), ("http_upload", "dns_tunneling", "token_secret_access")),
        ("validation", "exfiltration", ("exfiltration",), ("http_upload", "dns_tunneling", "browser_profile_access")),
        ("holdout", "exfiltration", ("exfiltration",), ("http_upload", "dns_tunneling", "clipboard_access")),
        ("holdout", "exfiltration", ("exfiltration",), ("http_upload", "dns_tunneling", "screen_capture")),
        ("train", "packed_dropper", ("packed_dropper",), ("memory_allocate", "memory_write", "memory_protect")),
        ("train", "packed_dropper", ("packed_dropper",), ("network_download", "file_write", "thread_execution")),
        ("validation", "packed_dropper", ("packed_dropper",), ("memory_allocate", "memory_write", "memory_protect", "thread_execution")),
        ("validation", "packed_dropper", ("packed_dropper",), ("network_download", "file_write", "memory_write", "thread_execution")),
        ("holdout", "packed_dropper", ("packed_dropper",), ("memory_allocate", "memory_write", "memory_protect", "file_write")),
        ("holdout", "packed_dropper", ("packed_dropper",), ("network_download", "file_write", "thread_execution", "memory_protect")),
        ("train", "fileless_loading", ("fileless_loading",), ("memory_allocate", "memory_write", "thread_execution")),
        ("train", "fileless_loading", ("fileless_loading",), ("encoded_powershell",)),
        ("validation", "fileless_loading", ("fileless_loading",), ("encoded_powershell", "powershell_exec")),
        ("validation", "fileless_loading", ("fileless_loading",), ("memory_allocate", "memory_write", "thread_execution", "powershell_exec")),
        ("holdout", "fileless_loading", ("fileless_loading",), ("encoded_powershell", "network_download")),
        ("holdout", "fileless_loading", ("fileless_loading",), ("memory_allocate", "memory_write", "thread_execution", "etw_bypass_attempt")),
        ("train", "bytecode_scripts", ("bytecode_scripts",), ("bytecode_subprocess",)),
        ("train", "bytecode_scripts", ("bytecode_scripts",), ("rpa_pickle_usage", "rpa_opcode_execution")),
        ("validation", "bytecode_scripts", ("bytecode_scripts",), ("bytecode_eval", "bytecode_socket")),
        ("validation", "bytecode_scripts", ("bytecode_scripts",), ("bytecode_subprocess", "bytecode_socket")),
        ("holdout", "bytecode_scripts", ("bytecode_scripts",), ("rpa_pickle_usage", "rpa_opcode_execution", "bytecode_socket")),
        ("holdout", "bytecode_scripts", ("bytecode_scripts",), ("bytecode_eval", "bytecode_socket", "bytecode_exec")),
        ("train", "dotnet_behavior", ("dotnet_behavior",), ("dotnet_obfuscated_or_packed",)),
        ("train", "dotnet_behavior", ("dotnet_behavior",), ("dotnet_obfuscated_or_packed", "dotnet_pe")),
        ("validation", "dotnet_behavior", ("dotnet_behavior",), ("dotnet_obfuscated_or_packed", "clr_runtime_present")),
        ("validation", "dotnet_behavior", ("dotnet_behavior",), ("dotnet_obfuscated_or_packed", "dotnet_x64")),
        ("holdout", "dotnet_behavior", ("dotnet_behavior",), ("dotnet_obfuscated_or_packed", "dotnet_pe", "clr_runtime_present")),
        ("holdout", "dotnet_behavior", ("dotnet_behavior",), ("dotnet_obfuscated_or_packed", "dotnet", "dotnet_x64")),
        ("train", "credential_theft", ("credential_theft",), ("lsass_access", "credential_dump_attempt")),
        ("train", "credential_theft", ("credential_theft",), ("browser_profile_access", "browser_extraction")),
        ("validation", "credential_theft", ("credential_theft",), ("keylogging_behavior", "input_capture")),
        ("validation", "credential_theft", ("credential_theft",), ("credential_memory_access",)),
        ("holdout", "credential_theft", ("credential_theft",), ("lsass_access", "credential_dump_attempt", "credential_memory_access")),
        ("holdout", "credential_theft", ("credential_theft",), ("browser_profile_access", "browser_extraction", "dpapi_access")),
    )
    counters: dict[tuple[str, str], int] = {}
    fixtures: list[AttackFixture] = []
    for partition, family, expected, tags in rows:
        key = (partition, family)
        index = counters.get(key, 0)
        counters[key] = index + 1
        fixtures.append(_fixture(
            f"{partition}:{family}:source_{index}", partition, family, expected, tags,
        ))
    return tuple(fixtures)


def _benign_fixtures() -> tuple[AttackFixture, ...]:
    controls = {
        "train": ((), ("file_read",), ("file_write",), ("process_exec",), ("network_activity",), ("dotnet",)),
        "validation": (("script_execution",), ("powershell_exec",), ("collection",), ("clipboard_access",), ("screenshot_capture",), ("network_download",)),
        "holdout": (("registry_mod",), ("memory_allocate",), ("clr_runtime_present",), ("bytecode_socket",), ("admin_share_access",), ("remote_service_creation",)),
    }
    return tuple(
        _fixture(f"{partition}:benign:source_{index}", partition, "benign", (), tags)
        for partition in _SPLITS
        for index, tags in enumerate(controls[partition])
    )


_CORPUS = _family_fixtures() + _benign_fixtures()
_FAMILIES = tuple(spec.family for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
_THRESHOLDS = {spec.family: spec.production_threshold for spec in ATTACK_INTELLIGENCE_CLASSIFIERS}


def _physical_tag_evidence(
    tags: tuple[str, ...], *, sample_id: str = "evaluation",
):
    """Build deterministic scoreable observations for controlled evaluator inputs."""
    observations = tuple(
        DetectionObservation.create(
            tag=tag,
            producer_id="attack_intelligence_evaluation",
            stage_id="controlled_fixture",
            modality="static_structure",
            artifact_identity="fixture:" + sample_id,
            source_location=ObservationSourceLocation(
                "fixture_event", locator=sample_id, event_id=tag,
            ),
            integrity_status="verified",
            directness="direct",
            confidence=1.0,
        )
        for tag in sorted(set(tags))
    )
    return normalize_tag_evidence(
        observations,
        source_detector="attack_intelligence_evaluation",
        source_stage="controlled_fixture",
    )


def _production_row(fixture: AttackFixture) -> dict[str, object]:
    evidence = compute_attack_intelligence(_physical_tag_evidence(fixture.tags, sample_id=fixture.sample_id), ())
    classifier_records = {
        record["family"]: record for record in evidence["classifier_records"]
    }
    return {
        "sample_id": fixture.sample_id,
        "partition": fixture.partition,
        "source_family": fixture.source_family,
        "expected_families": fixture.expected_families,
        "tags": fixture.tags,
        "aggregate_probability": float(evidence["aggregate_probability"]),
        "aggregate_uncertainty": float(evidence["aggregate_uncertainty"]),
        "best_family": evidence["best_family"],
        "family_probabilities": {
            family: float(evidence["family_probabilities"][family])
            for family in _FAMILIES
        },
        "raw_scores": {
            family: float(classifier_records[family]["raw_score"])
            for family in _FAMILIES
        },
    }


def _binary_rows(
    rows: tuple[dict[str, object], ...], family: str, partition: str,
) -> tuple[tuple[int, float], ...]:
    return tuple(
        (
            1 if family in row["expected_families"] else 0,
            float(row["family_probabilities"][family]),
        )
        for row in rows if row["partition"] == partition
    )


def _threshold_metrics(rows: tuple[tuple[int, float], ...], threshold: float) -> dict[str, float | int]:
    tp = sum(1 for label, score in rows if label == 1 and score >= threshold)
    fp = sum(1 for label, score in rows if label == 0 and score >= threshold)
    fn = sum(1 for label, score in rows if label == 1 and score < threshold)
    tn = sum(1 for label, score in rows if label == 0 and score < threshold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "threshold": round(threshold, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(fpr, 6),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
    }


def _roc_auc(rows: tuple[tuple[int, float], ...]) -> float:
    positives = tuple(score for label, score in rows if label == 1)
    negatives = tuple(score for label, score in rows if label == 0)
    if not positives or not negatives:
        return 0.0
    wins = fsum(
        1.0 if positive > negative else 0.5 if positive == negative else 0.0
        for positive in positives for negative in negatives
    )
    return round(wins / (len(positives) * len(negatives)), 6)


def _pr_auc(rows: tuple[tuple[int, float], ...]) -> float:
    positives = sum(label for label, _score in rows)
    if positives == 0:
        return 0.0
    ordered = sorted(rows, key=lambda item: (-item[1], -item[0]))
    true_positive = 0
    precision_sum = 0.0
    for index, (label, _score) in enumerate(ordered, start=1):
        if label:
            true_positive += 1
            precision_sum += true_positive / index
    return round(precision_sum / positives, 6)


def _brier(rows: tuple[tuple[int, float], ...]) -> float:
    return round(fsum((score - label) ** 2 for label, score in rows) / max(1, len(rows)), 6)


def _ece(rows: tuple[tuple[int, float], ...], bins: int = 5) -> float:
    total = max(1, len(rows))
    error = 0.0
    for bin_index in range(bins):
        low = bin_index / bins
        high = (bin_index + 1) / bins
        selected = tuple(
            (label, score) for label, score in rows
            if low <= score < high or (bin_index == bins - 1 and score == 1.0)
        )
        if not selected:
            continue
        confidence = fsum(score for _label, score in selected) / len(selected)
        accuracy = fsum(label for label, _score in selected) / len(selected)
        error += len(selected) / total * abs(confidence - accuracy)
    return round(error, 6)


def _legacy_global_brier(
    rows: tuple[dict[str, object], ...], family: str, partition: str,
) -> float:
    pairs = tuple(
        (
            1 if family in row["expected_families"] else 0,
            min(1.0, float(row["raw_scores"][family]) / 60.0),
        )
        for row in rows if row["partition"] == partition
    )
    return _brier(pairs)


def _family_metrics(rows: tuple[dict[str, object], ...]) -> dict[str, object]:
    metrics: dict[str, object] = {}
    for family in _FAMILIES:
        family_result: dict[str, object] = {}
        for partition in _SPLITS:
            pairs = _binary_rows(rows, family, partition)
            family_result[partition] = {
                **_threshold_metrics(pairs, _THRESHOLDS[family]),
                "roc_auc": _roc_auc(pairs),
                "pr_auc": _pr_auc(pairs),
                "brier_score": _brier(pairs),
                "expected_calibration_error": _ece(pairs),
                "legacy_global_normalization_brier": _legacy_global_brier(
                    rows, family, partition,
                ),
            }
        metrics[family] = family_result
    return metrics


def _aggregate_metrics(rows: tuple[dict[str, object], ...], partition: str) -> dict[str, object]:
    pairs = tuple(
        (
            1 if row["expected_families"] else 0,
            float(row["aggregate_probability"]),
        )
        for row in rows if row["partition"] == partition
    )
    selected = tuple(row for row in rows if row["partition"] == partition)
    correctly_explained = sum(
        1 for row in selected
        if not row["expected_families"]
        or row["best_family"] in row["expected_families"]
    )
    return {
        **_threshold_metrics(pairs, ATTACK_ENSEMBLE_POLICY.aggregate_threshold),
        "roc_auc": _roc_auc(pairs),
        "pr_auc": _pr_auc(pairs),
        "brier_score": _brier(pairs),
        "expected_calibration_error": _ece(pairs),
        "best_family_explanation_accuracy": round(
            correctly_explained / max(1, len(selected)), 6,
        ),
    }


def _predicted_family(row: dict[str, object]) -> str:
    probability = float(row["aggregate_probability"])
    best_family = row["best_family"]
    if probability < ATTACK_ENSEMBLE_POLICY.aggregate_threshold:
        return "benign"
    if type(best_family) is str and best_family in _FAMILIES:
        return best_family
    return "unavailable"


def _family_confusion(
    rows: tuple[dict[str, object], ...], partition: str,
) -> dict[str, object]:
    labels = ("benign", *_FAMILIES, "unavailable")
    matrix = {source: {predicted: 0 for predicted in labels} for source in labels}
    selected = tuple(row for row in rows if row["partition"] == partition)
    correct = 0
    off_diagonal = 0
    for row in selected:
        source = str(row["source_family"])
        predicted = _predicted_family(row)
        matrix[source][predicted] += 1
        if source == predicted:
            correct += 1
        else:
            off_diagonal += 1
    return {
        "partition": partition,
        "labels": labels,
        "matrix": matrix,
        "sample_count": len(selected),
        "correct_count": correct,
        "off_diagonal_count": off_diagonal,
        "accuracy": round(correct / max(1, len(selected)), 6),
    }


_RUNTIME_CONTROL_TAGS = frozenset({
    "bytecode_socket", "clr_runtime_present", "dotnet", "powershell_exec",
    "process_exec", "script_execution",
})


def _benign_runtime_controls(rows: tuple[dict[str, object], ...]) -> dict[str, object]:
    selected = tuple(
        row for row in rows
        if row["source_family"] == "benign"
        and _RUNTIME_CONTROL_TAGS.intersection(row["tags"])
    )
    false_positives = tuple(
        row for row in selected
        if float(row["aggregate_probability"]) >= ATTACK_ENSEMBLE_POLICY.aggregate_threshold
    )
    samples = tuple({
        "sample_id": row["sample_id"],
        "partition": row["partition"],
        "tags": row["tags"],
        "aggregate_probability": row["aggregate_probability"],
        "best_family": row["best_family"],
    } for row in selected)
    return {
        "sample_count": len(selected),
        "false_positive_count": len(false_positives),
        "false_positive_rate": round(len(false_positives) / max(1, len(selected)), 6),
        "maximum_probability": round(max(
            (float(row["aggregate_probability"]) for row in selected), default=0.0,
        ), 6),
        "samples": samples,
    }


def _process_projection(seed: int) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[2]
    program = """
import json
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import compute_attack_intelligence
from tools.evaluation.evaluate_attack_intelligence import _physical_tag_evidence
result = compute_attack_intelligence(
    _physical_tag_evidence(("remote_service_creation", "admin_share_access"), sample_id="process_projection"), (),
)
payload = {
    "aggregate_probability": result["aggregate_probability"],
    "aggregate_uncertainty": result["aggregate_uncertainty"],
    "best_family": result["best_family"],
    "family_probabilities": result["family_probabilities"],
    "hits": result["hits"],
    "independent_classifier_ids": result["independent_classifier_ids"],
    "classifier_records": result["classifier_records"],
}
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
"""
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = str(seed)
    environment["PYTHONPATH"] = str(repo_root)
    completed = subprocess.run(
        (sys.executable, "-c", program),
        cwd=repo_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = completed.stdout.strip()
    return {
        "seed": seed,
        "exit_code": completed.returncode,
        "output_digest": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "stderr_tail": completed.stderr[-500:],
    }


def _process_determinism() -> dict[str, object]:
    projections = (_process_projection(1), _process_projection(987654))
    return {
        "projections": projections,
        "all_exit_zero": all(item["exit_code"] == 0 for item in projections),
        "output_equal": len({item["output_digest"] for item in projections}) == 1,
    }


def _evaluation_yara_result(
    family: str, *, verified: bool,
) -> tuple[YaraScanResult, AttackIntelligenceYaraFamilyAlignment | None]:
    rule_name = "stage2636_verified_" + family
    source_digest = "a" * 64 if verified else ""
    cache_digest = "b" * 64 if verified else ""
    catalog_digest = "d" * 64 if verified else ""
    identity = YaraRuleIdentity(
        package_kind="custom" if verified else "unavailable",
        rule_source_digest=source_digest,
        compiled_cache_digest=cache_digest,
        rule_catalog_digest=catalog_digest,
        source_member="evaluation/rules.yar" if verified else "",
        compiler_namespace="ns_evaluation" if verified else "",
        rule_name=rule_name,
        metadata_id="stage2636-evaluation-" + family,
        logic_hash="e" * 64,
        semantic_metadata_digest="f" * 64,
        rule_tags=("evaluation",),
    )
    artifact_identity = "content_sha256:" + hashlib.sha256(
        ("attack-intelligence-evaluation-artifact:" + family).encode("utf-8")
    ).hexdigest()
    location = ObservationSourceLocation(
        "fixture_yara_match", locator="yara_benefit", event_id=identity.digest,
    )
    root = "obs_" + hashlib.sha256(
        (artifact_identity + identity.digest).encode("utf-8")
    ).hexdigest()
    hit = YaraHit(
        rule_identity=identity,
        root_observation_id=root,
        integrity_status="verified" if verified else "unverified",
        source_trust="custom_verified" if verified else "custom_unverified",
        release_id=0,
        release_tag="",
        compile_policy_version="stage2636_evaluation_compile_policy_v1",
        artifact_identity=artifact_identity,
        source_location=location,
        unavailable_reason="" if verified else "yara_execution_provenance_unverified",
    )
    result = YaraScanResult(
        status="complete",
        scan_pass_id="yscan_" + hashlib.sha256(root.encode("utf-8")).hexdigest(),
        physical_target_identity=artifact_identity,
        package_kind="custom" if verified else "unavailable",
        rule_source_digest=source_digest,
        compiled_cache_digest=cache_digest,
        rule_catalog_digest=catalog_digest,
        hits=(hit,),
        total_match_count=1,
        retained_match_count=1,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )
    if not verified:
        return result, None
    alignment = AttackIntelligenceYaraFamilyAlignment(
        family=family,
        package_kind=identity.package_kind,
        rule_source_digest=identity.rule_source_digest,
        rule_catalog_digest=identity.rule_catalog_digest,
        source_member=identity.source_member,
        compiler_namespace=identity.compiler_namespace,
        rule_name=identity.rule_name,
        metadata_id=identity.metadata_id,
        logic_hash=identity.logic_hash,
        interpretation_provenance="reviewed_attack_intelligence_evaluation_mapping",
    )
    return result, alignment


def _verified_no_match_result() -> YaraScanResult:
    return YaraScanResult(
        status="complete_no_match",
        scan_pass_id="yscan_" + "9" * 64,
        physical_target_identity="content_sha256:" + "c" * 64,
        package_kind="custom",
        rule_source_digest="a" * 64,
        compiled_cache_digest="b" * 64,
        rule_catalog_digest="d" * 64,
        hits=(),
        total_match_count=0,
        retained_match_count=0,
        duplicate_match_count=0,
        truncated_match_count=0,
        archive_member_count=0,
        scanned_member_count=0,
        failed_member_count=0,
    )


def _yara_benefit() -> dict[str, object]:
    tags = _physical_tag_evidence(("collection", "http_upload"), sample_id="yara_benefit")
    baseline = compute_attack_intelligence(tags, _verified_no_match_result())
    unverified_result, _unused = _evaluation_yara_result("exfiltration", verified=False)
    verified_result, verified_alignment = _evaluation_yara_result("exfiltration", verified=True)
    conflict_result, conflict_alignment = _evaluation_yara_result("credential_theft", verified=True)
    assert verified_alignment is not None and conflict_alignment is not None
    unverified = compute_attack_intelligence(tags, unverified_result)
    verified = compute_attack_intelligence(
        tags, verified_result, yara_family_alignments=(verified_alignment,),
    )
    conflict = compute_attack_intelligence(
        tags, conflict_result, yara_family_alignments=(conflict_alignment,),
    )
    return {
        "baseline_probability": baseline["family_probabilities"]["exfiltration"],
        "unverified_probability": unverified["family_probabilities"]["exfiltration"],
        "verified_probability": verified["family_probabilities"]["exfiltration"],
        "verified_benefit": round(
            verified["family_probabilities"]["exfiltration"]
            - baseline["family_probabilities"]["exfiltration"], 6,
        ),
        "unverified_state": unverified["yara_state"],
        "verified_state": verified["yara_state"],
        "conflicting_record_state": next(
            record["yara_state"] for record in conflict["classifier_records"]
            if record["family"] == "exfiltration"
        ),
    }


def _incremental_value() -> dict[str, float]:
    cases = (
        ("lateral_movement", ("admin_share_access", "remote_service_creation")),
        ("defense_evasion", ("shadowcopy_delete", "recovery_disable")),
        ("exfiltration", ("http_upload", "dns_tunneling")),
        ("packed_dropper", ("network_download", "file_write", "thread_execution")),
        ("fileless_loading", ("memory_allocate", "memory_write", "thread_execution")),
        ("bytecode_scripts", ("rpa_pickle_usage", "rpa_opcode_execution")),
        ("dotnet_behavior", ("dotnet_obfuscated_or_packed", "dotnet_pe")),
        ("credential_theft", ("dpapi_access", "browser_profile_access")),
    )
    margins: dict[str, float] = {}
    for family, tags in cases:
        combined = compute_attack_intelligence(
            _physical_tag_evidence(tags, sample_id="incremental:" + family), (),
        )["family_probabilities"][family]
        strongest_single = max(
            compute_attack_intelligence(
                _physical_tag_evidence((tag,), sample_id="incremental:" + family + ":" + tag), (),
            )["family_probabilities"][family]
            for tag in tags
        )
        margins[family] = round(combined - strongest_single, 6)
    return margins


def _stability_and_degraded() -> dict[str, object]:
    duplicate = compute_attack_intelligence(
        _physical_tag_evidence(("shadowcopy_delete", "shadowcopy_delete"), sample_id="stability:duplicate"), (),
    )
    single = compute_attack_intelligence(
        _physical_tag_evidence(("shadowcopy_delete",), sample_id="stability:duplicate"), (),
    )
    forward = compute_attack_intelligence(
        _physical_tag_evidence(("admin_share_access", "remote_service_creation"), sample_id="stability:order"), (),
    )
    reverse = compute_attack_intelligence(
        _physical_tag_evidence(("remote_service_creation", "admin_share_access"), sample_id="stability:order"), (),
    )
    degraded = compute_attack_intelligence(object(), object())
    return {
        "duplicate_probability_equal": (
            duplicate["family_probabilities"]["defense_evasion"]
            == single["family_probabilities"]["defense_evasion"]
        ),
        "duplicate_support_equal": duplicate["aggregate_support"] == single["aggregate_support"],
        "order_probability_equal": forward["aggregate_probability"] == reverse["aggregate_probability"],
        "order_explanations_equal": forward["hits"] == reverse["hits"],
        "degraded_ready": degraded["ready"],
        "degraded": degraded["degraded"],
        "degraded_probability": degraded["aggregate_probability"],
    }


def _corpus_digest() -> str:
    payload = json.dumps(
        [
            {
                "sample_id": row.sample_id,
                "partition": row.partition,
                "source_family": row.source_family,
                "expected_families": row.expected_families,
                "tags": row.tags,
            }
            for row in _CORPUS
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def evaluate() -> dict[str, object]:
    started = perf_counter()
    rows = tuple(_production_row(fixture) for fixture in _CORPUS)
    family_metrics = _family_metrics(rows)
    aggregate = {partition: _aggregate_metrics(rows, partition) for partition in _SPLITS}
    manifest = {
        "evaluation_version": EVALUATION_VERSION,
        "corpus_version": CORPUS_VERSION,
        "corpus_digest": _corpus_digest(),
        "sample_count": len(rows),
        "partition_counts": {
            partition: sum(1 for row in rows if row["partition"] == partition)
            for partition in _SPLITS
        },
        "evidence_version": ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
        "policy_version": ATTACK_ENSEMBLE_POLICY.version,
        "policy_evaluation_provenance": ATTACK_ENSEMBLE_POLICY.evaluation_provenance,
        "calibration_version": ATTACK_INTELLIGENCE_CALIBRATION_VERSION,
        "aggregate_method": ATTACK_ENSEMBLE_POLICY.aggregate_method,
        "aggregate_threshold": ATTACK_ENSEMBLE_POLICY.aggregate_threshold,
        "family_thresholds": dict(sorted(_THRESHOLDS.items())),
        "family_metrics": family_metrics,
        "aggregate_metrics": aggregate,
        "family_confusion": {
            partition: _family_confusion(rows, partition)
            for partition in _SPLITS
        },
        "benign_engine_runtime_controls": _benign_runtime_controls(rows),
        "process_determinism": _process_determinism(),
        "incremental_value_over_single_tags": _incremental_value(),
        "yara_corroboration": _yara_benefit(),
        "stability_and_degraded": _stability_and_degraded(),
        "elapsed_seconds": round(perf_counter() - started, 6),
    }
    digest_payload = dict(manifest)
    digest_payload.pop("elapsed_seconds")
    manifest["manifest_digest"] = hashlib.sha256(json.dumps(
        digest_payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return manifest


def acceptance(manifest: dict[str, object]) -> dict[str, bool]:
    holdout = manifest["aggregate_metrics"]["holdout"]
    family_metrics = manifest["family_metrics"]
    family_holdout = tuple(family_metrics[family]["holdout"] for family in _FAMILIES)
    incremental = manifest["incremental_value_over_single_tags"]
    yara = manifest["yara_corroboration"]
    stability = manifest["stability_and_degraded"]
    confusion = manifest["family_confusion"]["holdout"]
    benign_runtime = manifest["benign_engine_runtime_controls"]
    process_determinism = manifest["process_determinism"]
    return {
        "aggregate_holdout_precision": holdout["precision"] >= 0.95,
        "aggregate_holdout_recall": holdout["recall"] >= 0.95,
        "aggregate_holdout_fpr": holdout["false_positive_rate"] <= 0.05,
        "family_holdout_recall": all(row["recall"] >= 0.95 for row in family_holdout),
        "family_holdout_fpr": all(row["false_positive_rate"] <= 0.05 for row in family_holdout),
        "family_holdout_pr_auc": all(row["pr_auc"] >= 0.95 for row in family_holdout),
        "family_probability_beats_global_normalization": all(
            row["brier_score"] <= row["legacy_global_normalization_brier"]
            for row in family_holdout
        ),
        "multi_signal_incremental_value": all(value > 0.0 for value in incremental.values()),
        "family_confusion_is_diagonal": (
            confusion["off_diagonal_count"] == 0
            and confusion["accuracy"] == 1.0
        ),
        "benign_engine_runtime_false_positives": (
            benign_runtime["sample_count"] > 0
            and benign_runtime["false_positive_count"] == 0
            and benign_runtime["maximum_probability"]
            < ATTACK_ENSEMBLE_POLICY.aggregate_threshold
        ),
        "serial_process_determinism": (
            process_determinism["all_exit_zero"]
            and process_determinism["output_equal"]
        ),
        "verified_yara_only_corroborates": (
            yara["verified_benefit"] > 0.0
            and yara["unverified_probability"] == yara["baseline_probability"]
            and yara["conflicting_record_state"] == "verified_conflicting_or_rejected"
        ),
        "duplicate_and_order_stability": (
            stability["duplicate_probability_equal"]
            and stability["duplicate_support_equal"]
            and stability["order_probability_equal"]
            and stability["order_explanations_equal"]
        ),
        "degraded_fails_closed": (
            stability["degraded"] is True
            and stability["degraded_ready"] is False
            and stability["degraded_probability"] == 0.0
        ),
    }


def main() -> int:
    manifest = evaluate()
    gates = acceptance(manifest)
    print(json.dumps({"manifest": manifest, "acceptance": gates}, indent=2, sort_keys=True))
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
