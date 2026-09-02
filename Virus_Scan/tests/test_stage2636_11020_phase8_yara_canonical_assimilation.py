"""Phase 8: reviewed YARA enters ATT&CK authority exactly once via TagEvidence."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.evidence.yara_assimilation import assimilate_reviewed_yara_evidence
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import mitre_probability_component
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import current_attack_mapping_fixture
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    candidate_mitre_alignment,
    canonical_test_yara_result,
)


def _call_sites(root: Path, name: str) -> tuple[str, ...]:
    sites: list[str] = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else ""
            )
            if called == name:
                sites.append(path.relative_to(root).as_posix())
    return tuple(sorted(sites))


def test_phase8_reviewed_yara_hit_is_assimilated_with_same_physical_root() -> None:
    result = canonical_test_yara_result(rule_name="stage2636_encoded_powershell")
    hit = result.hits[0]
    alignment = candidate_mitre_alignment(hit)
    base = normalize_tag_evidence(())

    tags = assimilate_reviewed_yara_evidence(
        base,
        result,
        alignments=(alignment,),
        platform="windows",
        repository_digest=alignment.repository_digest,
    )

    assert tags is not base
    yara_records = tuple(
        record for record in tags.records if record.modality == "yara_match"
    )
    assert len(yara_records) == 1
    assert yara_records[0].root_observation_id == hit.root_observation_id
    assert yara_records[0].canonical_tag_id == alignment.tag_id
    assert yara_records[0].modality == "yara_match"

    chains = evaluate_chain_evidence(tags=tags)
    assert type(chains) is ChainEvidence
    probability, _reason, evidence = mitre_probability_component(current_attack_mapping_fixture(tags, chains))
    assert 0.0 <= probability <= 1.0
    assert evidence["verified_yara_observation_count"] == 0


def test_phase8_unverified_yara_has_zero_authority_effect() -> None:
    result = canonical_test_yara_result(verified=False)
    base = normalize_tag_evidence(())
    tags = assimilate_reviewed_yara_evidence(
        base,
        result,
        alignments=(),
        platform="windows",
        repository_digest="4" * 64,
    )
    assert tags is base
    assert tags.records == ()


def test_phase8_mitre_projection_accepts_only_final_tag_and_chain_evidence() -> None:
    signature = inspect.signature(mitre_probability_component)
    assert tuple(signature.parameters) == ("attack_mapping_result",)
    source = inspect.getsource(mitre_probability_component)
    assert "project_yara_observations" not in source
    assert "evaluate_chain_evidence" not in source
    assert "yara_hits" not in signature.parameters
    assert "yara_alignments" not in signature.parameters


def test_phase8_production_yara_projector_and_assimilation_have_one_call_owner() -> None:
    package_root = Path(__file__).resolve().parents[1]
    projector_sites = _call_sites(package_root, "project_yara_observations")
    assimilation_sites = _call_sites(package_root, "assimilate_reviewed_yara_evidence")

    assert projector_sites == ("detection/evidence/yara_assimilation.py",)
    assert assimilation_sites == ("detection/enrichment/full_analysis/input_stage.py",)


def test_phase8_mitre_scoring_paths_have_no_yara_or_chain_remap() -> None:
    package_root = Path(__file__).resolve().parents[1]
    targets = (
        package_root / "detection/scoring/adaptive/evidence_projection_components.py",
        package_root / "detection/scoring/adaptive/evidence_projection.py",
        package_root / "detection/scoring/full_analysis/score_explained.py",
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in targets)
    assert "project_yara_observations" not in text
    assert "yara_alignments" not in text
    assert "evaluate_chain_evidence(" not in text
