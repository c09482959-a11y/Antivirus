from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.escalation.high_gate import apply_anchor_chain_high_gate
from Virus_Scan.tests.support.canonical_chain_fixtures import causal_tag_evidence, physical_tag_evidence
from Virus_Scan.detection.scoring.full_analysis.score_explained import (
    ScoreExplainedRequest,
    score_explained,
)
from Virus_Scan.detection.orchestration.full_analysis.pipeline import analyze_file_full_observe_only


def test_stage309_media_profile_learning_uses_media_engine(tmp_path):
    sample = tmp_path / "standalone.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n")
    result = analyze_file_full_observe_only(
        str(sample),
        tags=physical_tag_evidence(("media_asset", "image_file", "asset_fast_triage_clean"), source_detector="stage309"),
        strings_blob="",

        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=artifact_read_snapshot_fixture(sample),
    )
    assert result["profile_selection"] == {"active_profile": "media"}
    learning = result["explanation"].get("learning") or {}
    validation = learning.get("validation") or {}
    assert validation.get("engine") == "media"


def test_stage309_renpy_external_process_exec_has_canonical_high_authority():
    tag_evidence = causal_tag_evidence(
        ("renpy_external_process_exec", "process_exec"),
        correlation_group="renpy_external_process_execution",
        source_detector="stage309",
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    score, explanation = score_explained(
        ScoreExplainedRequest(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            tags=tag_evidence,
            chain_evidence=chain_evidence,
            yara_evidence=None,
            node="game/script.rpy",
        )
    )
    final_score, metadata = apply_anchor_chain_high_gate(
        score,
        chain_evidence,
        tags=tag_evidence,
        path="game/script.rpy",
    )
    assert final_score >= 58.0
    assert "anchor:renpy_external_process_execution" in metadata["explicit_behavior_anchors"]
    assert "canonical_chain_evidence" not in explanation
