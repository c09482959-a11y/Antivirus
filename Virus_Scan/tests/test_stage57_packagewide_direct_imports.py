from Virus_Scan.core.paths import runtime_library_score_cap
from Virus_Scan.detection.chains.composite.attack_authority import has_concrete_attack_chain
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.reporting.result_schema import make_timeout_result, make_terminal_asset_result
from Virus_Scan.reporting.summary import correlation_group_summary, probabilistic_evidence_summary
from Virus_Scan.utils.stages import extract_router_stage


def test_core_paths_runtime_library_score_cap_direct_import_safe():
    score, reasons = runtime_library_score_cap(70, tags=["runtime_library"], path="python311.dll", strings_blob="normal runtime")
    assert score <= 22
    assert "runtime_library_cap_score" in reasons


def test_detection_chains_direct_import_anchor_safe():
    assert has_concrete_attack_chain(evaluate_chain_evidence(tags=physical_tag_evidence(("encoded_powershell",))))
    assert not has_concrete_attack_chain(evaluate_chain_evidence(tags=physical_tag_evidence(("url_present",))))


def test_reporting_result_schema_direct_import_safe():
    timeout = make_timeout_result("x.png", 3)
    assert timeout["class"] == "timeout"
    terminal = make_terminal_asset_result("x.png", ["router_stage_image"])
    assert terminal["fast_path"] is True


def test_reporting_summary_direct_import_safe():
    grouped = correlation_group_summary([{"correlation_group": "network", "confidence": 0.7}])
    assert grouped["network"]["count"] == 1
    summary = probabilistic_evidence_summary([{"correlation_group": "network", "confidence": 0.7}])
    assert summary["ready"] is True


def test_routing_extensions_stage_helper_direct_import_safe():
    assert extract_router_stage(["router_stage_image"]) == "image"
