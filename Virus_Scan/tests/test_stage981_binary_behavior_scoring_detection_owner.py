
"""Stage 981: binary behavior scoring belongs to detection scoring, not scanners."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.scoring.behavior.bucket_validation import (
    behavior_bucket_validation,
    credential_family_boost,
)


def test_binary_behavior_scoring_module_removed_from_scanners() -> None:
    assert not Path("Virus_Scan/scanners/binary_behavior_scoring.py").exists()


def test_scanner_binary_public_surface_no_longer_exports_scoring() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary.py"))
    assert "behavior_bucket_validation" not in source
    assert "credential_family_boost" not in source


def test_detection_binary_behavior_scoring_preserves_semantic_output(tmp_path) -> None:
    sample = tmp_path / "payload.dll"
    sample.write_bytes(b"MZ" + b"\0" * 64)
    result = behavior_bucket_validation(
        "unity",
        sample,
        ["process_exec", "network_download", "credential_dump_attempt"],
        strings_blob="Process.Start DownloadString LSASS",
    )
    assert result["version"]
    assert result["records"]
    buckets = {record["bucket"] for record in result["records"]}
    assert {"os_execution", "network", "credential"}.issubset(buckets)
    assert "bucket_anomaly" in result


def test_detection_credential_family_boost_preserves_falsey_string_content() -> None:
    class _FalseyText(str):
        def __new__(cls):
            return str.__new__(cls, "powershell login data cryptunprotectdata lsass minidumpwritedump")

        def __bool__(self):
            return False

        def __str__(self):
            raise RuntimeError("string hooks must not be called")

    result = credential_family_boost([], strings_blob=_FalseyText())
    assert result["score"] > 0.0
    assert "credential_stealer_behavior" in result["tags"]


def test_detection_behavior_scoring_does_not_import_scanner_implementation() -> None:
    path = Path("Virus_Scan/detection/scoring/behavior/bucket_validation.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.scanners"):
            offenders.append((node.lineno, node.module))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("Virus_Scan.scanners"):
                    offenders.append((node.lineno, alias.name))
    assert offenders == []
