from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners import rpgm



def test_rpgm_scanner_no_longer_imports_private_core_json_reader(tmp_path):
    source = read_python_file(Path("Virus_Scan/scanners/rpgm.py"))
    assert "Virus_Scan.core.jsonio" not in source
    payload = tmp_path / "queue.json"
    payload.write_text('{"ok": true}', encoding="utf-8")
    assert rpgm._queue_read_json_file(payload, default={}) == {"ok": True}
    assert rpgm._queue_read_json_file(tmp_path / "missing.json", default={"missing": True}) == {"missing": True}


def test_rpgm_engine_threat_failure_emits_scanner_degraded_evidence(tmp_path):
    sample = tmp_path / "www" / "js" / "plugins" / "plugin.js"
    sample.parent.mkdir(parents=True)
    sample.write_text("PluginManager.registerCommand('Menu','Open',()=>{});", encoding="utf-8")

    def fail_engine_threats(*_args, **_kwargs):
        raise OSError("synthetic rpgm engine analyzer failure")

    tags = rpgm.scan_rpgm_file(str(sample), engine_threat_evaluator=fail_engine_threats)
    assert "rpgm" in tags
    assert "scanner_degraded" in tags
    assert "scan_incomplete" in tags
    assert any(str(tag).startswith("scanner_failure") for tag in tags)
