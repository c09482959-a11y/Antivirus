from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys

from tools.evaluation.evaluate_mitre_attack_mapping import evaluate


def test_phase12_evaluator_contains_no_synthetic_mapper_evidence() -> None:
    source = Path("tools/evaluation/evaluate_mitre_attack_mapping.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if type(node) in (ast.Import, ast.ImportFrom)
        for alias in node.names
    }
    called = {
        node.func.id
        for node in ast.walk(tree)
        if type(node) is ast.Call and type(node.func) is ast.Name
    }
    forbidden_evidence_owners = {
        "TagEvidence", "ChainEvidence", "ChainDecision", "map_attack_evidence",
        "_chain_fixture", "_repository",
    }
    assert imported.isdisjoint(forbidden_evidence_owners)
    assert called.isdisjoint(forbidden_evidence_owners)
    # Policy metadata is intentionally read to prove that every unevaluated or
    # unsupported technique remains nonconfirming and zero-authority.  The
    # evaluator must never construct or invoke policy/evidence owners.
    assert "ATTACK_TECHNIQUE_POLICIES" in imported
    assert "ATTACK_TECHNIQUE_POLICIES" not in called


def test_phase12_contract_fixtures_are_test_only() -> None:
    fixture = Path(
        "Virus_Scan/tests/support/attack_mapping_contract_fixtures.py"
    )
    assert fixture.is_file()
    assert not Path("tools/evaluation/attack_mapping_contract_fixtures.py").exists()


def test_phase12_missing_corpus_is_deterministic_and_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"
    first = evaluate(corpus_path=path, include_process=False)
    second = evaluate(corpus_path=path, include_process=False)
    assert first["manifest_digest"] == second["manifest_digest"]
    assert first["confirmed_enabled_count"] == 0
    assert first["production_path_evaluation_available"] is False
    assert first["model_metrics_available"] is False


def test_phase12_subprocess_digest_is_reproducible(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"
    command = [
        sys.executable,
        "-m",
        "tools.evaluation.evaluate_mitre_attack_mapping",
        "--digest-only",
        "--corpus",
        str(path),
    ]
    runs = [
        subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=60,
        )
        for _ in range(2)
    ]
    assert [item.returncode for item in runs] == [0, 0]
    assert runs[0].stdout == runs[1].stdout
