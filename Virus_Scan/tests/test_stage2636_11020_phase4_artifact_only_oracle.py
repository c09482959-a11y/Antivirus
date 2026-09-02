"""Phase 4 artifact-only ATT&CK oracle authority and independence gates."""
from __future__ import annotations

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture

import ast
from dataclasses import replace
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_contract_repository
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture

from Virus_Scan.stress.artifact_attack_projection import (
    artifact_attack_expectations,
    expected_attack_decision,
)
from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.artifact_evidence_oracle_validator import validate_artifact_evidence_truth
from Virus_Scan.stress.attack_synthetic_templates import (
    SYNTHETIC_ATTACK_FIXTURES,
    SYNTHETIC_ATTACK_TECHNIQUE_IDS,
)
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import CorpusFixtureDefinition

_ROOT = Path(__file__).resolve().parents[2]
_ORACLE_MODULES = (
    _ROOT / "Virus_Scan/stress/artifact_evidence_oracle.py",
    _ROOT / "Virus_Scan/stress/artifact_evidence_oracle_validator.py",
)


def _fixture(generation_id: str):
    return next(
        item for item in SYNTHETIC_ATTACK_FIXTURES
        if item.generation_intent.generation_id == generation_id
    )


def _render(generation_id: str, sample_id: str):
    fixture = _fixture(generation_id)
    renderer = fixture.renderer_specification
    payload = render_static_semantic_artifact(sample_id, renderer)
    return fixture, renderer, payload


def test_phase4_oracle_and_validator_are_structurally_isolated_from_generator_and_production_mapping() -> None:
    forbidden_import_prefixes = (
        "Virus_Scan.routing",
        "Virus_Scan.scanners",
        "Virus_Scan.detection.attack.mapper",
        "Virus_Scan.detection.attack.candidate",
        "Virus_Scan.stress.static_semantic_templates",
        "Virus_Scan.stress.attack_synthetic_templates",
    )
    forbidden_symbols = (
        "CorpusGenerationIntent",
        "CorpusGenerationRecord",
        "TagEvidence",
        "ChainEvidence",
        "map_attack_evidence",
        "mitre_probability_component",
        "retrieve_attack_candidates",
        "desired_technique_ids",
        "malware_class",
        "generation_id",
    )
    for path in _ORACLE_MODULES:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imported_modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
        assert all(
            not module.startswith(prefix)
            for module in imported_modules
            for prefix in forbidden_import_prefixes
        )
        assert all(symbol not in source for symbol in forbidden_symbols)


def test_phase4_same_bytes_are_independent_of_hidden_generator_labels() -> None:
    fixture, renderer, payload = _render(
        "python_process_injection_sequence", "phase4-hidden-label-independence",
    )
    altered_intent = replace(
        fixture.generation_intent,
        generation_id="completely-different-hidden-generation",
        malware_class="control",
        coverage_cohort="adjacent_technique_control",
        desired_technique_ids=("T1003",),
    )
    altered_fixture = CorpusFixtureDefinition(altered_intent, renderer)
    # The byte artifact is fixed before hidden-label mutation; neither oracle sees
    # either intent object.
    assert altered_fixture.renderer_specification is renderer
    truth_a = derive_artifact_evidence_truth(
        "phase4-hidden-label-independence", ".hidden.py", payload,
    )
    truth_b = derive_artifact_evidence_truth(
        "phase4-hidden-label-independence", ".hidden.py", payload,
    )
    expectations_a = artifact_attack_expectations(truth_a, SYNTHETIC_ATTACK_TECHNIQUE_IDS)
    expectations_b = artifact_attack_expectations(truth_b, SYNTHETIC_ATTACK_TECHNIQUE_IDS)
    assert truth_a.to_record() == truth_b.to_record()
    assert expectations_a == expectations_b
    assert validate_artifact_evidence_truth(
        truth_a.sample_id, ".hidden.py", payload, truth_a, expectations_a,
    )["agreement"] is True


def test_phase4_same_bytes_and_changed_hidden_labels_leave_production_mapping_identical(
    tmp_path: Path,
) -> None:
    fixture, renderer, payload = _render(
        "python_process_injection_sequence", "phase4-production-label-independence",
    )
    target = tmp_path / "phase4-production-label-independence.py"
    target.write_bytes(payload)
    runtime_root = tmp_path / "runtime"
    scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
    try:
        def production_mapping_record() -> dict[str, object]:
            outcome = scan_file_by_type(
                str(target),
                scan_session_snapshot=scan_session_snapshot_fixture(),
                artifact_read_snapshot=build_artifact_read_snapshot(target),
            )
            chains = evaluate_chain_evidence(tags=outcome.tag_evidence)
            return map_attack_evidence(
                attack_contract_repository(), attack_mapping_evidence_fixture(outcome.tag_evidence, chains),
            ).to_record()

        mapping_before = production_mapping_record()
        altered_intent = replace(
            fixture.generation_intent,
            generation_id="phase4-production-different-hidden-generation",
            malware_class="control",
            coverage_cohort="adjacent_technique_control",
            desired_technique_ids=("T1003",),
        )
        altered_fixture = CorpusFixtureDefinition(altered_intent, renderer)
        assert altered_fixture.renderer_specification is renderer
        assert target.read_bytes() == payload
        mapping_after = production_mapping_record()
        assert mapping_after == mapping_before
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()


def test_phase4_physical_behavior_mutation_changes_t1055_decision() -> None:
    _fixture_value, _renderer, payload = _render(
        "python_process_injection_sequence", "phase4-t1055-causality",
    )
    original = derive_artifact_evidence_truth(
        "phase4-t1055-causality", "phase4-t1055-causality.py", payload,
    )
    original_expectations = artifact_attack_expectations(
        original, SYNTHETIC_ATTACK_TECHNIQUE_IDS,
    )
    original_by_id = {item.technique_id: item for item in original_expectations}
    assert original_by_id["T1055"].expected_state == "candidate"
    assert validate_artifact_evidence_truth(
        original.sample_id,
        "phase4-t1055-causality.py",
        payload,
        original,
        original_expectations,
    )["agreement"] is True

    mutated = b"\n".join(
        line for line in payload.splitlines()
        if b"CreateRemoteThread" not in line
    ) + b"\n"
    changed = derive_artifact_evidence_truth(
        "phase4-t1055-causality", "phase4-t1055-causality.py", mutated,
    )
    changed_expectations = artifact_attack_expectations(
        changed, SYNTHETIC_ATTACK_TECHNIQUE_IDS,
    )
    changed_by_id = {item.technique_id: item for item in changed_expectations}
    assert "thread_execute" not in changed.operation_kinds
    assert changed_by_id["T1055"].expected_state == "rejected"
    assert validate_artifact_evidence_truth(
        changed.sample_id,
        "phase4-t1055-causality.py",
        mutated,
        changed,
        changed_expectations,
    )["agreement"] is True


def test_phase4_dead_code_cannot_gain_t1055_authority_from_operation_presence() -> None:
    _fixture_value, _renderer, payload = _render(
        "python_injection_dead_code", "phase4-t1055-dead-code",
    )
    truth = derive_artifact_evidence_truth(
        "phase4-t1055-dead-code", "phase4-t1055-dead-code.py", payload,
    )
    expectations = artifact_attack_expectations(truth, SYNTHETIC_ATTACK_TECHNIQUE_IDS)
    by_id = {item.technique_id: item for item in expectations}
    assert set(("process_open", "memory_allocate", "memory_write", "thread_execute")).issubset(
        set(truth.operation_kinds)
    )
    assert all(
        item.reachability_state == "unreachable"
        for item in truth.reachability
        if item.operation_kind in {"process_open", "memory_allocate", "memory_write", "thread_execute"}
    )
    assert by_id["T1055"].expected_state == "rejected"
    validation = validate_artifact_evidence_truth(
        truth.sample_id,
        "phase4-t1055-dead-code.py",
        payload,
        truth,
        expectations,
    )
    assert validation["agreement"] is True


def test_phase4_incomplete_evidence_is_unavailable_even_if_member_behavior_is_present() -> None:
    # The static-semantic nested archive physically contains member behavior but
    # intentionally has an unavailable container claim boundary.
    from Virus_Scan.stress.static_semantic_templates import STATIC_SEMANTIC_FIXTURES

    fixture = next(
        item for item in STATIC_SEMANTIC_FIXTURES
        if item.renderer_specification.renderer_kind == "nested_zip"
        and item.generation_intent.desired_operation_kinds
    )
    sample_id = "phase4-nested-unavailable"
    renderer = fixture.renderer_specification
    payload = render_static_semantic_artifact(sample_id, renderer)
    truth = derive_artifact_evidence_truth(sample_id, sample_id + renderer.extension, payload)
    assert truth.parser_status == "unavailable"
    assert truth.evidence_completeness == "unavailable"
    assert all(
        expected_attack_decision(truth, technique_id).policy_decision == "unavailable"
        for technique_id in SYNTHETIC_ATTACK_TECHNIQUE_IDS
    )
    expectations = artifact_attack_expectations(truth, SYNTHETIC_ATTACK_TECHNIQUE_IDS)
    assert validate_artifact_evidence_truth(
        sample_id, sample_id + renderer.extension, payload, truth, expectations,
    )["agreement"] is True


def test_phase4_superseded_label_driven_oracle_paths_are_deleted() -> None:
    for name in (
        "static_semantic_oracle.py",
        "static_semantic_oracle_validator.py",
        "attack_synthetic_oracle.py",
        "attack_synthetic_oracle_validator.py",
    ):
        assert not (_ROOT / "Virus_Scan/stress" / name).exists()
    production = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (_ROOT / "Virus_Scan").rglob("*.py")
        if "/tests/" not in path.as_posix()
    )
    assert "StaticSemanticOracleRecord" not in production
    assert '"synthetic_oracle"' not in production
