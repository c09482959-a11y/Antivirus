"""Phase 26 semantic-evaluation and cross-language equivalence regressions."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from Virus_Scan.detection.attack.evaluation_contracts import AttackEvaluationCorpusManifest
from Virus_Scan.runtime.config_state import configure_profiles_dir, get_profiles_dir
from Virus_Scan.stress.static_semantic_corpus import materialize_static_semantic_corpus
from Virus_Scan.storage import scan_cache_repository
from Virus_Scan.stress.static_semantic_evaluation import (
    STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION,
    StaticSemanticEvaluationMetrics,
    StaticSemanticEvaluationRow,
)
from tools.evaluation.evaluate_static_semantic_phase26 import evaluate_static_semantic_ir

_REPOSITORY_DIGEST = "a" * 64


@pytest.fixture(scope="module")
def phase26_deep_results(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("phase26_static_semantic")
    corpus_root = root / "corpus"
    materialize_static_semantic_corpus(
        corpus_root,
        repository_digest=_REPOSITORY_DIGEST,
    )
    corpus = AttackEvaluationCorpusManifest.from_path(
        corpus_root / "attack_evaluation_corpus_manifest.json"
    )
    first_rows, first_metrics = evaluate_static_semantic_ir(
        corpus,
        corpus_root=corpus_root,
        runtime_root=root / "runtime_first",
    )
    second_rows, second_metrics = evaluate_static_semantic_ir(
        corpus,
        corpus_root=corpus_root,
        runtime_root=root / "runtime_second",
    )
    return first_rows, first_metrics, second_rows, second_metrics


def test_phase26_static_semantic_evaluation_contract_is_zero_authority(
    phase26_deep_results,
) -> None:
    first_rows, first_metrics, _second_rows, _second_metrics = phase26_deep_results
    row = first_rows[0]
    assert type(row) is StaticSemanticEvaluationRow
    assert row.schema_version == STATIC_SEMANTIC_EVALUATION_SCHEMA_VERSION
    assert row.execution_observed is False
    assert row.eligible_for_confirmation is False
    assert row.eligible_for_probability is False
    assert first_metrics.production_authority is False
    assert first_metrics.execution_observed_count == 0
    with pytest.raises(ValueError, match="authority_invalid"):
        replace(row, eligible_for_probability=True)
    with pytest.raises(ValueError, match="authority_invalid"):
        replace(first_metrics, production_authority=True)


def test_phase26_full_static_semantic_oracle_is_exact_and_deterministic(
    phase26_deep_results,
) -> None:
    first_rows, first_metrics, second_rows, second_metrics = phase26_deep_results
    assert first_metrics == second_metrics
    assert tuple(row.to_record() for row in first_rows) == tuple(
        row.to_record() for row in second_rows
    )
    record = first_metrics.to_record()
    assert record["row_count"] == 96
    assert record["analysis_available_count"] == 84
    assert record["unavailable_count"] == 12
    assert record["parser_match_count"] == 96
    assert record["parser_accuracy"] == 1.0
    assert record["operation_kind_precision"] == 1.0
    assert record["operation_kind_recall"] == 1.0
    assert record["unexpected_operation_kind_count"] == 0
    assert record["forbidden_operation_violation_count"] == 0
    assert record["control_forbidden_operation_violation_count"] == 0
    assert record["reachability_accuracy"] == 1.0
    assert record["flow_accuracy"] == 1.0
    injection_rows = tuple(
        row for row in first_rows
        if row.generation_id == "python_process_injection_sequence"
    )
    assert len(injection_rows) == 4
    assert all(row.flow_truth_count == 2 for row in injection_rows)
    assert all(row.flow_match_count == 2 for row in injection_rows)


def test_phase26_unavailable_archive_and_unsupported_language_abstain_exactly(
    phase26_deep_results,
) -> None:
    rows, _metrics, _second_rows, _second_metrics = phase26_deep_results
    unavailable = tuple(row for row in rows if not row.analysis_available)
    archive_rows = tuple(
        row for row in unavailable
        if row.unavailable_reason == "archive_member_ir_not_published_at_container_boundary"
    )
    unsupported_rows = tuple(
        row for row in unavailable
        if row.unavailable_reason == "static_frontend_not_applicable"
    )
    assert len(archive_rows) == 8
    assert len(unsupported_rows) == 4
    assert all(row.execution_observed is False for row in unavailable)
    assert all(row.eligible_for_confirmation is False for row in unavailable)
    assert all(row.eligible_for_probability is False for row in unavailable)
    assert all(row.observed_operation_kinds == () for row in unavailable)


def test_phase26_cross_language_upload_and_credential_semantics_are_aligned(
    phase26_deep_results,
) -> None:
    rows, _metrics, _second_rows, _second_metrics = phase26_deep_results
    by_generation: dict[str, list[StaticSemanticEvaluationRow]] = {}
    for row in rows:
        by_generation.setdefault(row.generation_id, []).append(row)

    javascript = by_generation["javascript_file_upload"]
    batch = by_generation["batch_file_upload"]
    shell = by_generation["shell_file_upload"]
    assert len(javascript) == len(batch) == len(shell) == 4
    for row in javascript:
        assert {
            "credential_store_discovery", "file_read",
            "network_send", "network_upload",
        }.issubset(row.observed_operation_kinds)
        assert row.flow_match_count == row.flow_truth_count == 1
    for row in (*batch, *shell):
        assert {"file_read", "network_send", "network_upload"}.issubset(
            row.observed_operation_kinds
        )
        assert row.flow_match_count == row.flow_truth_count == 1



def test_phase26_evaluator_explicit_profiles_authority_is_isolated_and_restored(
    tmp_path: Path,
) -> None:
    previous_profiles_dir = get_profiles_dir(None)
    sentinel_profiles = tmp_path / "preexisting_profiles"
    configure_profiles_dir(sentinel_profiles)
    try:
        corpus_root = tmp_path / "corpus"
        materialize_static_semantic_corpus(
            corpus_root,
            repository_digest=_REPOSITORY_DIGEST,
        )
        corpus = AttackEvaluationCorpusManifest.from_path(
            corpus_root / "attack_evaluation_corpus_manifest.json"
        )
        rows, metrics = evaluate_static_semantic_ir(
            corpus,
            corpus_root=corpus_root,
            runtime_root=tmp_path / "runtime",
        )
        assert len(rows) == 96
        assert metrics.row_count == 96
        assert get_profiles_dir(None) == str(sentinel_profiles.resolve())
    finally:
        configure_profiles_dir(previous_profiles_dir)


def test_phase26_evaluator_is_not_imported_by_production_scanners() -> None:
    root = Path(__file__).resolve().parents[2]
    token = "tools.evaluation.evaluate_static_semantic_phase26"
    offenders = []
    for path in (root / "Virus_Scan").rglob("*.py"):
        if "tests" in path.parts:
            continue
        if token in path.read_text(encoding="utf-8", errors="strict"):
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == []


def test_phase26_evaluator_restores_scan_cache_policy(phase26_deep_results) -> None:
    assert phase26_deep_results
    assert scan_cache_repository().enabled() is False
