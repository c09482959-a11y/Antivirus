from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.orchestration.lifecycle import attach_direct_audit_fields, report_results
from Virus_Scan.routing.context_identity import classify_engine_context, attach_routing_evidence_to_record, RoutingEvidenceContext


class _Runtime:
    scan_started_at = 0.0
    parent_cli = False

    def __init__(self):
        self._values = {}

    def set(self, key, value):
        self._values[key] = value

    def get(self, key, default=None):
        return self._values.get(key, default)


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_required_cross_engine_and_extension_mismatch_fixtures(tmp_path: Path) -> None:
    renpy_root = tmp_path / "renpy_game"
    _write(renpy_root / "game" / "script.rpy", b"label start:\n    pass\n")
    _write(renpy_root / "game" / "screens.rpy", b"screen main_menu():\n    pass\n")
    _write(renpy_root / "archive.rpa", b"RPA-3.0")
    unity_dll = _write(renpy_root / "Assembly-CSharp.dll", b"MZ" + b"\0" * 128 + b"BSJB mscorlib Assembly-CSharp UnityEngine")

    rpgm_root = tmp_path / "rpgm_game"
    _write(rpgm_root / "www" / "js" / "rpg_core.js", b"function RPGMakerMV(){}")
    _write(rpgm_root / "www" / "data" / "System.json", b'{"gameTitle":"MV"}')
    png_polyglot = _write(rpgm_root / "img" / "enemy.png", b"\x89PNG\r\n\x1a\n" + b"0" * 64 + b"MZpayload")
    renamed_rpgm = _write(rpgm_root / "img" / "encrypted.png", b"RPGMV encrypted asset")

    unity_root = tmp_path / "unity_game"
    _write(unity_root / "UnityPlayer.dll", b"MZUnityPlayer")
    _write(unity_root / "Game_Data" / "globalgamemanagers", b"SerializedFile")
    renpy_bytecode = _write(unity_root / "payload.rpyc", b"RENPY c__builtin__\nexec REDUCE")
    renamed_dll = _write(unity_root / "Assembly-CSharp.dat", b"MZ" + b"\0" * 128 + b"BSJB mscorlib Assembly-CSharp UnityEngine")

    renpy_unity = classify_engine_context(unity_dll, container_root=renpy_root)
    assert renpy_unity.container_engine == "renpy"
    assert renpy_unity.artifact_engine == "unity"
    assert renpy_unity.cross_engine_artifact is True
    assert renpy_unity.engine_mismatch is True
    assert renpy_unity.effective_analysis_engine == "unity_dotnet"
    assert renpy_unity.baseline_key.startswith("renpy::unity::.dll")
    assert renpy_unity.learning_allowed is False

    rpgm_pe_png = classify_engine_context(png_polyglot, container_root=rpgm_root)
    assert rpgm_pe_png.container_engine == "rpgm"
    assert rpgm_pe_png.artifact_engine == "media"
    assert rpgm_pe_png.sniffed_type == "png"
    assert "pe" in rpgm_pe_png.sniffed_embedded_types
    assert rpgm_pe_png.effective_analysis_engine == "embedded_pe_payload"
    assert "rpgm::embedded_pe::.png" in rpgm_pe_png.secondary_baseline_keys
    assert rpgm_pe_png.learning_allowed is False

    unity_renpy = classify_engine_context(renpy_bytecode, container_root=unity_root)
    assert unity_renpy.container_engine == "unity"
    assert unity_renpy.artifact_engine == "renpy"
    assert unity_renpy.effective_analysis_engine == "renpy_bytecode"
    assert unity_renpy.cross_engine_artifact is True
    assert unity_renpy.learning_allowed is False

    dat_dll = classify_engine_context(renamed_dll, container_root=unity_root)
    assert dat_dll.declared_extension == ".dat"
    assert dat_dll.sniffed_type in {"pe", "mono_dotnet_assembly"}
    assert dat_dll.extension_mismatch is True
    assert dat_dll.effective_analysis_engine == "unity_dotnet"
    assert dat_dll.learning_allowed is False

    renamed_asset = classify_engine_context(renamed_rpgm, container_root=rpgm_root)
    assert renamed_asset.declared_extension == ".png"
    assert renamed_asset.sniffed_type == "rpgm_encrypted_asset"
    assert renamed_asset.extension_mismatch is True
    assert renamed_asset.effective_analysis_engine == "rpgm_encrypted_asset"
    assert renamed_asset.learning_allowed is False


def test_reporting_payload_enforcement_accepts_string_embedded_type(tmp_path: Path) -> None:
    sample = _write(tmp_path / "polyglot.png", b"\x89PNG\r\n\x1a\n" + b"0" * 32 + b"MZpayload")
    args = SimpleNamespace(scheduler="serial", engine="auto", dir=str(tmp_path), output=str(tmp_path / "out.json"))
    record = {
        "file": str(sample),
        "path": str(sample),
        "score": 3.0,
        "class": "benign_clean",
        "classification": "benign_clean",
        "tags": ["terminal_clean_asset_triage"],
        "fast_path": True,
    }
    record = attach_routing_evidence_to_record(
        record,
        sample,
        container_root=tmp_path,
        evidence_context=RoutingEvidenceContext.build(tmp_path),
    )
    records = {str(sample): record}

    annotated = attach_direct_audit_fields(args, records, yara_ok=False)
    record = annotated[str(sample)]

    assert record["classification"] == "low_confidence"
    assert record["score"] >= 25.0
    assert record["fast_path"] is False
    assert "embedded_pe_payload" in record["tags"]
    assert any("EmbeddedPayload: PE" in item for item in record["decoded_evidence_snippets"])
