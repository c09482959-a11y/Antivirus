from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.escalation.high_gate import apply_anchor_chain_high_gate
from Virus_Scan.detection.scoring.full_analysis.layered_score import compute_layered_detection
from Virus_Scan.tests.support.canonical_chain_fixtures import causal_tag_evidence


def _score_with_canonical_floor(tags):
    tag_evidence = causal_tag_evidence(
        tuple(tags),
        correlation_group="stage375_explicit_anchor",
        source_detector="stage375",
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    layered = compute_layered_detection(
        "payload.dat",
        tag_evidence,
        chain_evidence,
        curr_stage="binary",
    )
    score, metadata = apply_anchor_chain_high_gate(
        layered["score"],
        chain_evidence,
        tags=tag_evidence,
        path="payload.dat",
    )
    return score, metadata


def test_stage375_pe_command_channel_has_canonical_forensic_score_floor():
    score, metadata = _score_with_canonical_floor((
        "pe_file",
        "remote_command_channel",
        "c2_beacon",
        "network_c2",
        "backdoor_or_c2",
        "network_activity",
    ))
    assert score >= 62.0
    assert "anchor:pe_command_channel" in metadata["explicit_behavior_anchors"]


def test_stage375_unity_pe_powershell_network_has_canonical_forensic_score_floor():
    score, metadata = _score_with_canonical_floor((
        "pe_file",
        "pe_dll",
        "unity_dotnet",
        "powershell_exec",
        "url_present",
    ))
    assert score >= 58.0
    assert "anchor:pe_powershell_network" in metadata["explicit_behavior_anchors"]
