
"""Stage 899 Phase 10 strict-fast binary policy ownership tests."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
import json
from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_strict_fast import _strict_fast_file_is_boring_text
from Virus_Scan.scanners.config import ScannerConfigError, load_binary_policy_snapshot
from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings


def test_binary_strict_fast_uses_scanner_binary_policy_not_model_profiles() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_strict_fast.py"))
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }

    assert "Virus_Scan.models.profiles" not in imported_modules
    assert "Virus_Scan.scanners.config" in imported_modules


def test_strict_fast_policy_snapshot_has_immutable_scanner_owned_values() -> None:
    policy = load_binary_policy_snapshot()

    assert ".txt" in policy.strict_fast_benign_extensions
    assert policy.strict_fast_benign_max_bytes == 65536
    assert b"MZ" in policy.strict_fast_benign_binary_magic
    assert b"\x7fELF" in policy.strict_fast_benign_binary_magic
    assert "powershell" in policy.strict_fast_benign_deny_tokens

    with pytest.raises(AttributeError):
        policy.strict_fast_benign_max_bytes = 1  # type: ignore[misc]


def test_invalid_strict_fast_binary_magic_config_fails_visibly(tmp_path: Path) -> None:
    default_path = Path("Virus_Scan/scanners/config/defaults/binary_policy.json")
    data = json.loads(default_path.read_text(encoding="utf-8"))
    data["strict_fast_benign_binary_magic_hex"] = ["not-hex"]
    invalid_path = tmp_path / "binary_policy.json"
    invalid_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ScannerConfigError) as exc_info:
        load_binary_policy_snapshot(invalid_path)

    failure = exc_info.value.failure
    assert failure is not None
    assert failure.config_name == "binary_policy"
    assert "hexadecimal" in failure.reason or "hex" in failure.reason
    assert failure.failure_evidence


def test_strict_fast_benign_text_still_accepts_policy_owned_text_extension(tmp_path: Path) -> None:
    benign = tmp_path / "note.txt"
    benign.write_text("simple readable scanner note\n", encoding="utf-8")

    ok, metadata = _strict_fast_file_is_boring_text(benign)

    assert ok is True
    assert metadata["extension"] == ".txt"
    assert metadata["size"] > 0
    assert "binary_final_json_must_record" not in metadata


def test_policy_table_audit_accepts_strict_fast_binary_config_migration() -> None:
    assert scan_policy_table_config_findings("Virus_Scan/scanners") == ()
