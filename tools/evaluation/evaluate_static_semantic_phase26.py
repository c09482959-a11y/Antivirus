"""Phase 26 static-semantic validity and cold production-runtime matrix.

This module is evaluation-only.  Raw artifacts enter the production router and
canonical language frontend; public ATT&CK outcomes enter through the existing
runtime and strict reconciliation owners.  Oracle data never enters scanner
inputs or production state.
"""
from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path, PosixPath, WindowsPath
import shutil
from typing import Iterator

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_DATA_FLOW_EDGE_KINDS,
    STATIC_NON_OBSERVATION_OPERATION_KINDS,
)
from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.detection.attack.evaluation_contracts import (
    AttackEvaluationCorpusManifest,
    AttackEvaluationSample,
)
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.orchestration.scan_session import build_scan_session_snapshot
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.runtime.config_state import configure_profiles_dir, get_profiles_dir
from Virus_Scan.scanners.api.static_program_analysis_contracts import (
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
)
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.stress.static_semantic_evaluation import (
    StaticSemanticEvaluationMetrics,
    StaticSemanticEvaluationRow,
)
from Virus_Scan.stress.static_semantic_corpus import STATIC_SEMANTIC_SIDECAR_FILENAMES
from Virus_Scan.stress.static_semantic_schema import (
    ArtifactEvidenceTruth,
    StaticFlowTruth,
    StaticReachabilityTruth,
)
from tools.evaluation.attack_production_reconciliation import (
    reconcile_production_runtime,
)
from tools.evaluation.attack_production_runtime import (
    ALL_PARTITIONS,
    run_production_runtime,
)

PHASE26_EVALUATION_SCHEMA_VERSION = "stage2636_11020_phase26_evaluation_v1"
_PATH_TYPES = (PosixPath, WindowsPath)


def _resolved_artifact_path(
    corpus_root: Path,
    sample: AttackEvaluationSample,
) -> Path:
    if type(corpus_root) not in _PATH_TYPES:
        raise TypeError("phase26_corpus_root_invalid")
    if type(sample) is not AttackEvaluationSample:
        raise TypeError("phase26_sample_invalid")
    root = corpus_root.absolute()
    if path_contains_filesystem_alias(root) or not root.is_dir():
        raise ValueError("phase26_corpus_root_invalid")
    relative = Path(sample.artifact_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.parts[0] != "artifacts"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("phase26_sample_artifact_path_not_portable")
    candidate = root / relative
    if path_contains_filesystem_alias(candidate) or not candidate.is_file():
        raise ValueError("phase26_sample_artifact_file_invalid")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("phase26_sample_artifact_path_escape")
    return resolved


def _execution_corpus(
    corpus: AttackEvaluationCorpusManifest,
    corpus_root: Path,
) -> AttackEvaluationCorpusManifest:
    return replace(
        corpus,
        samples=tuple(
            replace(sample, artifact_path=str(_resolved_artifact_path(corpus_root, sample)))
            for sample in corpus.samples
        ),
    )


def _strict_manifest(path: Path) -> AttackEvaluationCorpusManifest:
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise ValueError("phase26_manifest_file_invalid")
    return AttackEvaluationCorpusManifest.from_path(path)


def _reject_json_constant(_value: str) -> object:
    raise ValueError("phase26_oracle_json_nonfinite")


def _reject_json_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in items:
        if type(key) is not str or key in out:
            raise ValueError("phase26_oracle_json_duplicate_key")
        out[key] = value
    return out


def _plain_record(value: object, reason: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise TypeError(reason)
    return value


def _plain_list(value: object, reason: str) -> list[object]:
    if type(value) is not list:
        raise TypeError(reason)
    return value


def _text_tuple(value: object, reason: str) -> tuple[str, ...]:
    items = _plain_list(value, reason)
    if any(type(item) is not str for item in items):
        raise TypeError(reason)
    return tuple(items)


def _truth_from_record(value: object) -> ArtifactEvidenceTruth:
    record = _plain_record(value, "phase26_artifact_truth_record_invalid")
    reachability = tuple(
        StaticReachabilityTruth(
            operation_kind=_plain_record(item, "phase26_artifact_truth_reachability_invalid")["operation_kind"],
            reachability_state=_plain_record(item, "phase26_artifact_truth_reachability_invalid")["reachability_state"],
            minimum_count=_plain_record(item, "phase26_artifact_truth_reachability_invalid")["minimum_count"],
        )
        for item in _plain_list(record.get("reachability"), "phase26_artifact_truth_reachability_invalid")
    )
    flow = tuple(
        StaticFlowTruth(
            source_operation_kind=_plain_record(item, "phase26_artifact_truth_flow_invalid")["source_operation_kind"],
            sink_operation_kind=_plain_record(item, "phase26_artifact_truth_flow_invalid")["sink_operation_kind"],
            connected=_plain_record(item, "phase26_artifact_truth_flow_invalid")["connected"],
            same_resource=_plain_record(item, "phase26_artifact_truth_flow_invalid")["same_resource"],
        )
        for item in _plain_list(record.get("flow"), "phase26_artifact_truth_flow_invalid")
    )
    truth = ArtifactEvidenceTruth(
        sample_id=record.get("sample_id"),
        artifact_sha256=record.get("artifact_sha256"),
        artifact_size=record.get("artifact_size"),
        artifact_format=record.get("artifact_format"),
        platform=record.get("platform"),
        parser_status=record.get("parser_status"),
        operation_kinds=_text_tuple(record.get("operation_kinds"), "phase26_artifact_truth_operations_invalid"),
        reachability=reachability,
        flow=flow,
        resource_identities=_text_tuple(record.get("resource_identities"), "phase26_artifact_truth_resources_invalid"),
        resolved_call_identities=_text_tuple(record.get("resolved_call_identities"), "phase26_artifact_truth_calls_invalid"),
        resolved_import_identities=_text_tuple(record.get("resolved_import_identities"), "phase26_artifact_truth_imports_invalid"),
        resolved_syscall_identities=_text_tuple(record.get("resolved_syscall_identities"), "phase26_artifact_truth_syscalls_invalid"),
        analysis_limitations=_text_tuple(record.get("analysis_limitations"), "phase26_artifact_truth_limitations_invalid"),
        evidence_completeness=record.get("evidence_completeness"),
    )
    if record.get("artifact_evidence_digest") != truth.digest:
        raise ValueError("phase26_artifact_truth_digest_mismatch")
    return truth


def _artifact_truth_by_sample_id(corpus_root: Path) -> dict[str, ArtifactEvidenceTruth]:
    path = corpus_root / STATIC_SEMANTIC_SIDECAR_FILENAMES[1]
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise ValueError("phase26_artifact_truth_manifest_file_invalid")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_json_pairs, parse_constant=_reject_json_constant)
    report = _plain_record(value, "phase26_artifact_truth_manifest_invalid")
    report_without_digest = {key: item for key, item in report.items() if key != "digest"}
    if report.get("digest") != canonical_json_sha256(report_without_digest):
        raise ValueError("phase26_artifact_truth_manifest_digest_mismatch")
    records = tuple(_truth_from_record(item) for item in _plain_list(report.get("records"), "phase26_artifact_truth_records_invalid"))
    if report.get("record_count") != len(records):
        raise ValueError("phase26_artifact_truth_record_count_mismatch")
    by_id = {item.sample_id: item for item in records}
    if len(by_id) != len(records):
        raise ValueError("phase26_artifact_truth_sample_duplicate")
    return by_id


def _generation_id_by_sample_id(corpus_root: Path) -> dict[str, str]:
    path = corpus_root / STATIC_SEMANTIC_SIDECAR_FILENAMES[0]
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_json_pairs, parse_constant=_reject_json_constant)
    report = _plain_record(value, "phase26_generation_manifest_invalid")
    records = _plain_list(report.get("records"), "phase26_generation_records_invalid")
    out = {}
    for item in records:
        record = _plain_record(item, "phase26_generation_record_invalid")
        fixture = _plain_record(record.get("fixture_definition"), "phase26_generation_fixture_invalid")
        intent = _plain_record(fixture.get("generation_intent"), "phase26_generation_intent_invalid")
        sample_id = record.get("sample_id"); generation_id = intent.get("generation_id")
        if type(sample_id) is not str or type(generation_id) is not str or sample_id in out:
            raise ValueError("phase26_generation_identity_invalid")
        out[sample_id] = generation_id
    return out


def _artifact_truth(sample: AttackEvaluationSample, path: Path, truth_by_sample_id: dict[str, ArtifactEvidenceTruth]) -> ArtifactEvidenceTruth:
    truth = truth_by_sample_id.get(sample.sample_id)
    if truth is None:
        raise ValueError("phase26_sample_artifact_truth_missing")
    if truth.artifact_sha256 != sample.artifact_sha256 or truth.artifact_size != sample.artifact_size:
        raise ValueError("phase26_sample_artifact_truth_identity_mismatch")
    if path.stat().st_size != sample.artifact_size:
        raise ValueError("phase26_sample_size_mismatch")
    return truth


@contextmanager
def _isolated_runtime(root: Path) -> Iterator[Path]:
    if root.exists():
        raise ValueError("phase26_runtime_root_not_clean")
    previous_base_dir = os.environ.get("UMIGE_BASE_DIR")
    previous_profiles_dir = get_profiles_dir(None)
    profiles_dir = root / "profiles"
    sqlite_lifecycle().close()
    os.environ["UMIGE_BASE_DIR"] = str(root)
    configure_profiles_dir(profiles_dir)
    try:
        scan_cache_repository().configure(profiles_dir, enabled=True)
        yield root
    finally:
        scan_cache_repository().configure(profiles_dir, enabled=False)
        sqlite_lifecycle().close()
        configure_profiles_dir(previous_profiles_dir)
        if previous_base_dir is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous_base_dir


def _data_flow_path_observed(analysis: object, source: object, target: object) -> bool:
    if any(
        edge.edge_kind == "source_to_sink"
        and edge.source_operation_id == source.operation_id
        and edge.target_operation_id == target.operation_id
        and edge.resolution_state == "resolved"
        and edge.integrity_status != "unavailable"
        for edge in analysis.flow_edges
    ):
        return True
    source_values = tuple(source.output_value_ids)
    target_values = frozenset(target.input_value_ids)
    if not source_values or not target_values:
        return False
    adjacency: dict[str, set[str]] = {}
    direct_targets: dict[str, set[str]] = {}
    for edge in analysis.flow_edges:
        if (
            edge.edge_kind not in STATIC_DATA_FLOW_EDGE_KINDS
            or edge.resolution_state != "resolved"
            or edge.integrity_status == "unavailable"
            or not edge.source_value_id
            or not edge.target_value_id
        ):
            continue
        adjacency.setdefault(edge.source_value_id, set()).add(edge.target_value_id)
        if edge.target_operation_id:
            direct_targets.setdefault(edge.source_value_id, set()).add(
                edge.target_operation_id,
            )
    queue = deque(sorted(source_values))
    seen = set(source_values)
    while queue:
        current = queue.popleft()
        if target.operation_id in direct_targets.get(current, ()):
            return True
        for successor in sorted(adjacency.get(current, ())):
            if successor in target_values:
                return True
            if successor not in seen:
                seen.add(successor)
                queue.append(successor)
    return False


def _same_resource_state(source: object, target: object) -> bool | None:
    source_resource = source.target_resource_identity
    target_resource = target.target_resource_identity
    if not source_resource or not target_resource:
        return None
    return source_resource == target_resource


def _flow_truth_matches(analysis: object, truth: StaticFlowTruth) -> bool:
    sources = tuple(
        item for item in analysis.operations
        if item.operation_kind == truth.source_operation_kind
    )
    targets = tuple(
        item for item in analysis.operations
        if item.operation_kind == truth.sink_operation_kind
    )
    pairs = tuple((source, target) for source in sources for target in targets)
    connected_pairs = tuple(
        (source, target) for source, target in pairs
        if _data_flow_path_observed(analysis, source, target)
    )
    if bool(connected_pairs) is not truth.connected:
        return False
    if truth.same_resource is None:
        return True
    candidates = connected_pairs if truth.connected else pairs
    return any(
        _same_resource_state(source, target) is truth.same_resource
        for source, target in candidates
    )


def _row(
    sample: AttackEvaluationSample,
    path: Path,
    scan_session_snapshot: ScanSessionSnapshot,
    truth_by_sample_id: dict[str, ArtifactEvidenceTruth],
    generation_id_by_sample_id: dict[str, str],
) -> StaticSemanticEvaluationRow:
    truth = _artifact_truth(sample, path, truth_by_sample_id)
    generation_id = generation_id_by_sample_id.get(sample.sample_id)
    if generation_id is None:
        raise ValueError("phase26_sample_generation_identity_missing")
    snapshot = build_artifact_read_snapshot(path)
    outcome = scan_file_by_type(
        str(path),
        scan_session_snapshot=scan_session_snapshot,
        artifact_read_snapshot=snapshot,
    )
    identity = route_identity_record(outcome.identity)
    if identity is None:
        raise ValueError("phase26_router_identity_unavailable")
    summary = dict(identity["static_program_analysis"])
    scanner_id = str(summary.get("scanner_id") or "")
    analysis = None
    cache_source = str(summary.get("cache_source") or "not_applicable")
    unavailable_reason = ""
    if scanner_id:
        frontend = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID.get(scanner_id)
        if frontend is None:
            raise ValueError("phase26_static_frontend_missing")
        result = frontend.analyzer(snapshot)
        analysis = result.analysis
        cache_source = result.cache_source
        if analysis.semantic_digest != summary.get("semantic_digest"):
            raise ValueError("phase26_router_frontend_semantic_digest_mismatch")
    elif sample.file_type.startswith("nested_zip:"):
        unavailable_reason = "archive_member_ir_not_published_at_container_boundary"
    else:
        unavailable_reason = "static_frontend_not_applicable"

    if analysis is None:
        return StaticSemanticEvaluationRow(
            sample_id=sample.sample_id,
            partition=sample.partition,
            malware_class=sample.malware_class,
            generation_id=generation_id,
            artifact_sha256=sample.artifact_sha256,
            expected_parser_status=truth.parser_status,
            observed_parser_status="unavailable",
            analysis_available=False,
            unavailable_reason=unavailable_reason,
            scanner_id="",
            cache_source=cache_source,
            semantic_digest="",
            expected_operation_kinds=tuple(sorted(truth.operation_kinds)),
            observed_operation_kinds=(),
            matched_operation_kinds=(),
            missing_operation_kinds=tuple(sorted(truth.operation_kinds)),
            unexpected_operation_kinds=(),
            forbidden_operation_kinds_observed=(),
            reachability_truth_count=len(truth.reachability),
            reachability_match_count=0,
            flow_truth_count=len(truth.flow),
            flow_match_count=0,
            operation_count=0,
            flow_edge_count=0,
            route_tag_count=len(outcome.tags),
        )

    observed = tuple(sorted({
        item.operation_kind
        for item in analysis.operations
        if item.operation_kind not in STATIC_NON_OBSERVATION_OPERATION_KINDS
    }))
    expected = tuple(sorted(truth.operation_kinds))
    expected_set = set(expected)
    observed_set = set(observed)
    forbidden_observed: tuple[str, ...] = ()
    reachability_matches = 0
    for reachability_truth in truth.reachability:
        count = sum(
            item.operation_kind == reachability_truth.operation_kind
            and item.reachability_state == reachability_truth.reachability_state
            for item in analysis.operations
        )
        reachability_matches += count >= reachability_truth.minimum_count
    flow_matches = sum(
        _flow_truth_matches(analysis, flow_truth)
        for flow_truth in truth.flow
    )
    return StaticSemanticEvaluationRow(
        sample_id=sample.sample_id,
        partition=sample.partition,
        malware_class=sample.malware_class,
        generation_id=generation_id,
        artifact_sha256=sample.artifact_sha256,
        expected_parser_status=truth.parser_status,
        observed_parser_status=analysis.parser_status,
        analysis_available=True,
        unavailable_reason="",
        scanner_id=scanner_id,
        cache_source=cache_source,
        semantic_digest=analysis.semantic_digest,
        expected_operation_kinds=expected,
        observed_operation_kinds=observed,
        matched_operation_kinds=tuple(sorted(expected_set & observed_set)),
        missing_operation_kinds=tuple(sorted(expected_set - observed_set)),
        unexpected_operation_kinds=tuple(sorted(observed_set - expected_set)),
        forbidden_operation_kinds_observed=forbidden_observed,
        reachability_truth_count=len(truth.reachability),
        reachability_match_count=reachability_matches,
        flow_truth_count=len(truth.flow),
        flow_match_count=flow_matches,
        operation_count=len(analysis.operations),
        flow_edge_count=len(analysis.flow_edges),
        route_tag_count=len(outcome.tags),
    )


def evaluate_static_semantic_ir(
    corpus: AttackEvaluationCorpusManifest,
    *,
    corpus_root: Path,
    runtime_root: Path,
) -> tuple[tuple[StaticSemanticEvaluationRow, ...], StaticSemanticEvaluationMetrics]:
    """Evaluate all raw artifacts through router-selected canonical frontends."""
    if type(corpus) is not AttackEvaluationCorpusManifest:
        raise TypeError("phase26_corpus_invalid")
    rows: list[StaticSemanticEvaluationRow] = []
    truth_by_sample_id = _artifact_truth_by_sample_id(corpus_root)
    generation_id_by_sample_id = _generation_id_by_sample_id(corpus_root)
    sample_ids = {sample.sample_id for sample in corpus.samples}
    if set(truth_by_sample_id) != sample_ids or set(generation_id_by_sample_id) != sample_ids:
        raise ValueError("phase26_artifact_truth_corpus_membership_mismatch")
    with _isolated_runtime(runtime_root):
        scan_session_snapshot = build_scan_session_snapshot(
            compiled_rules=None,
            yara_enabled=False,
            scan_mode="serial",
            worker_count=1,
        )
        for sample in sorted(corpus.samples, key=lambda item: item.sample_id):
            rows.append(
                _row(
                    sample,
                    _resolved_artifact_path(corpus_root, sample),
                    scan_session_snapshot,
                    truth_by_sample_id,
                    generation_id_by_sample_id,
                )
            )
    ordered = tuple(rows)
    return ordered, StaticSemanticEvaluationMetrics.from_rows(ordered)


def _normalized_public_rows(rows: tuple[object, ...]) -> tuple[dict[str, object], ...]:
    normalized = []
    for row in rows:
        record = row.to_record()
        normalized.append({
            "classification": record["classification"],
            "degraded_reasons": record["degraded_reasons"],
            "final_status": record["final_status"],
            "outcomes": record["outcomes"],
            "sample_id": record["sample_id"],
        })
    return tuple(sorted(normalized, key=lambda item: str(item["sample_id"])))


def run_cold_public_matrix(
    *,
    repository_root: Path,
    corpus: AttackEvaluationCorpusManifest,
    corpus_root: Path,
    run_root: Path,
    bundle_path: Path,
    limit: int,
    timeout_seconds: int,
) -> tuple[dict[str, object], ...]:
    """Run disabled/core/extended x serial/process through existing owners."""
    if run_root.exists():
        raise ValueError("phase26_matrix_root_not_clean")
    run_root.mkdir(parents=True)
    execution_corpus = _execution_corpus(corpus, corpus_root)
    records: list[dict[str, object]] = []
    for yara_mode in ("disabled", "core", "extended"):
        for scheduler in ("serial", "process"):
            identity = yara_mode + "_" + scheduler
            runtime = run_production_runtime(
                repository_root=repository_root,
                corpus=execution_corpus,
                partition=ALL_PARTITIONS,
                limit=limit,
                run_root=run_root / identity,
                bundle_path=bundle_path,
                scheduler=scheduler,
                timeout_seconds=timeout_seconds,
                yara_mode=yara_mode,
            )
            rows, metrics = reconcile_production_runtime(
                corpus=execution_corpus, runtime=runtime,
            )
            normalized = _normalized_public_rows(rows)
            records.append({
                "engineering_metrics": metrics.to_record(),
                "identity": identity,
                "normalized_semantic_digest": canonical_json_sha256(normalized),
                "resource_metrics": runtime.resource_metrics.to_record(),
                "row_count": len(rows),
                "rows": normalized,
                "scheduler": scheduler,
                "yara_mode": yara_mode,
                "yara_source_sha256": runtime.yara_source_sha256,
            })
    return tuple(records)


def evaluate(
    *,
    corpus_manifest_path: Path,
    repository_root: Path,
    output_root: Path,
    bundle_path: Path,
    public_limit: int = 20,
    timeout_seconds: int = 900,
    run_public_matrix: bool = True,
) -> dict[str, object]:
    if output_root.exists():
        raise ValueError("phase26_output_root_not_clean")
    output_root.mkdir(parents=True)
    corpus = _strict_manifest(corpus_manifest_path)
    corpus_root = corpus_manifest_path.resolve().parent
    rows, metrics = evaluate_static_semantic_ir(
        corpus,
        corpus_root=corpus_root,
        runtime_root=output_root / "deep_runtime_state",
    )
    public = (
        run_cold_public_matrix(
            repository_root=repository_root,
            corpus=corpus,
            corpus_root=corpus_root,
            run_root=output_root / "public_cold_matrix",
            bundle_path=bundle_path,
            limit=public_limit,
            timeout_seconds=timeout_seconds,
        )
        if run_public_matrix else ()
    )
    base = {
        "corpus_digest": corpus.digest,
        "deep_semantic_metrics": metrics.to_record(),
        "deep_semantic_rows": tuple(row.to_record() for row in rows),
        "evidence_domain": "synthetic_engineering",
        "eligible_for_confirmation": False,
        "eligible_for_policy_promotion": False,
        "eligible_for_probability": False,
        "phase": 26,
        "production_authority": False,
        "public_cold_matrix": public,
        "schema_version": PHASE26_EVALUATION_SCHEMA_VERSION,
        "stage": "Stage2636.11020",
    }
    result = {**base, "evaluation_digest": canonical_json_sha256(base)}
    (output_root / "phase26_evaluation.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-manifest", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--public-limit", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--deep-only", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    evaluate(
        corpus_manifest_path=args.corpus_manifest,
        repository_root=args.repository_root,
        output_root=args.output_root,
        bundle_path=args.bundle,
        public_limit=args.public_limit,
        timeout_seconds=args.timeout_seconds,
        run_public_matrix=not args.deep_only,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "PHASE26_EVALUATION_SCHEMA_VERSION",
    "evaluate",
    "evaluate_static_semantic_ir",
    "run_cold_public_matrix",
)
