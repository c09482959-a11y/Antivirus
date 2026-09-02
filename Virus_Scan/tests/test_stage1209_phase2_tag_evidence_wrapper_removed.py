from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import import_modules, python_files_under


from pathlib import Path

from Virus_Scan.contracts import tag_evidence
from Virus_Scan.detection.evidence.behavioral import semantics

REMOVED_WRAPPERS = (
    Path("Virus_Scan/detection/evidence/policy.py"),
    Path("Virus_Scan/detection/scoring/weighting/contextual_anchors.py"),
    Path("Virus_Scan/detection/tags/heuristics/dangerous_anchors.py"),
    Path("Virus_Scan/detection/contracts/text_validation.py"),
)


def test_stage1209_tag_evidence_wrappers_removed() -> None:
    for path in REMOVED_WRAPPERS:
        assert not path.exists(), path


def test_stage1209_production_callers_use_root_tag_evidence_contract() -> None:
    forbidden = {
        "Virus_Scan.detection.evidence.policy",
        "Virus_Scan.detection.scoring.weighting.contextual_anchors",
        "Virus_Scan.detection.tags.heuristics.dangerous_anchors",
        "Virus_Scan.detection.contracts.text_validation",
    }
    for path in (*python_files_under("Virus_Scan"), *python_files_under("tests")):
        assert not (set(import_modules(path)) & forbidden), path


def test_stage1209_behavioral_semantics_delegates_evidence_level_to_contract_owner() -> None:
    expected = tag_evidence.evidence_level_for_tag(
        "process_exec", strings_blob="subprocess.Popen(cmd)", api_calls=[], ordered_events=[]
    )
    actual = semantics.evidence_level_for_tag(
        "process_exec", strings_blob="subprocess.Popen(cmd)", api_calls=[], ordered_events=[]
    )
    assert actual == expected == ("reachable_exec", 0.78)


def test_stage1209_contextual_anchor_contract_preserves_high_risk_bucket_behavior() -> None:
    hits = tag_evidence.contextual_dangerous_anchor_hits(["process_exec", "weak_noise_tag"])
    assert "process_exec" in hits
