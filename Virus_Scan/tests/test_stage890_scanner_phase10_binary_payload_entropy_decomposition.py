from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners import binary_pe
from Virus_Scan.scanners.binary_appended_payload import scan_appended_payload
from Virus_Scan.scanners.binary_embedded_payloads import validated_embedded_payload_hits
from Virus_Scan.scanners.entropy import detect_packer_entropy_anomaly


def _function_names(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def test_binary_module_no_longer_owns_payload_helpers():
    functions = _function_names("Virus_Scan/scanners/binary.py")
    assert "_scan_appended_payload" not in functions
    assert "_validated_embedded_payload_hits" not in functions


def test_image_and_rpgm_call_canonical_appended_payload_module():
    for path in (Path("Virus_Scan/scanners/image_scan.py"), Path("Virus_Scan/scanners/image_stego.py"), Path("Virus_Scan/scanners/rpgm.py")):
        text = path.read_text(encoding="utf-8")
        assert "Virus_Scan.scanners.binary_appended_payload" in text
        assert "from Virus_Scan.scanners.binary import _scan_appended_payload" not in text


def test_public_binary_contract_uses_canonical_embedded_payload_module():
    text = read_python_file(Path("Virus_Scan/scanners/api/binary_contracts.py"))
    assert "Virus_Scan.scanners.binary_embedded_payloads" in text
    assert "_validated_embedded_payload_hits" not in text


def test_pe_and_entropy_functions_are_decomposed_below_gate():
    targets = [
        "Virus_Scan/scanners/binary_pe.py",
        "Virus_Scan/scanners/binary_pe_headers.py",
        "Virus_Scan/scanners/binary_pe_sections.py",
        "Virus_Scan/scanners/binary_pe_dotnet.py",
        "Virus_Scan/scanners/binary_pe_surface.py",
        "Virus_Scan/scanners/binary_appended_payload.py",
        "Virus_Scan/scanners/binary_embedded_payloads.py",
        "Virus_Scan/scanners/entropy.py",
    ]
    for target in targets:
        tree = ast.parse(Path(target).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                assert node.end_lineno - node.lineno + 1 <= 75, (target, node.name)
        for owner in ast.walk(tree):
            if isinstance(owner, ast.FunctionDef):
                nested_imports = [n for n in ast.walk(owner) if isinstance(n, (ast.Import, ast.ImportFrom))]
                assert not nested_imports, (target, owner.name)


def test_appended_payload_detection_is_canonical_and_evidence_visible():
    payload = b"\x89PNG\r\n\x1a\n" + b"body" + b"IEND\xaeB`\x82" + b"\x00" * 4 + b"MZ" + b"A" * 512
    tags: list[str] = []
    assert scan_appended_payload(payload, tags) is True
    assert "image_appended_data" in tags
    assert "image_payload_confirmed" in tags
    assert "embedded_payload_after_eof" in tags


def test_embedded_payload_validation_uses_single_canonical_path():
    sample = bytearray(b"A" * 64)
    sample.extend(b"MZ")
    sample.extend(b"\x00" * 58)
    sample.extend((0x40).to_bytes(4, "little"))
    sample.extend(b"PE\x00\x00")
    hits = validated_embedded_payload_hits(bytes(sample), min_offset=32)
    assert hits == [(64, "embedded_pe_signature")]


def test_entropy_empty_input_result_still_records_final_json_evidence(tmp_path):
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")
    result = detect_packer_entropy_anomaly(str(sample))
    assert "entropy_final_json_must_record" in set(result.get("tags") or [])
    assert result.get("scan_integrity", {}).get("final_json_must_record") is True


def test_binary_pe_public_contracts_still_resolve():
    assert callable(binary_pe.scan_pure_python_pe_file)
    assert callable(binary_pe.global_raw_pure_pe_header)
    assert callable(binary_pe.extract_dotnet_metadata)
    assert callable(binary_pe.is_dotnet_pe)
