"""Stage 920 Phase 10: falsey scanner inputs must not be erased as clean defaults."""
from __future__ import annotations

from Virus_Scan.scanners.binary_behavior_detectors import detect_ransomware_file_rename_heuristic
from Virus_Scan.detection.scoring.behavior.bucket_validation import credential_family_boost
from Virus_Scan.scanners.binary_behavior_semantics import evidence_level_for_tag, tag_behavior_bucket
from Virus_Scan.scanners.binary_filetype import engine_extension_key
from Virus_Scan.scanners.binary_path_identity import get_binary_scan_extension
from Virus_Scan.scanners.binary_text_signals import binary_text_has_any


class _FalseyText(str):
    def __new__(cls):
        return str.__new__(cls, "powershell login data cryptunprotectdata lsass minidumpwritedump")

    def __bool__(self):
        return False

    def __str__(self):
        raise RuntimeError("string hooks must not be called")


class _FalseyPath:
    def __bool__(self):
        return False

    def __str__(self):
        return "sample.exe"


class _FalseyTag:
    def __bool__(self):
        return False

    def __str__(self):
        return "process_exec"


def test_binary_text_signal_uses_exact_text_content() -> None:
    assert binary_text_has_any("powershell login data", ["powershell"]) is True


def test_detection_behavior_scoring_uses_falsey_string_blob_content() -> None:
    result = credential_family_boost([], strings_blob=_FalseyText())
    assert result["score"] > 0.0
    assert "credential_stealer_behavior" in result["tags"]


def test_ransomware_heuristic_uses_exact_string_blob_content() -> None:
    result = detect_ransomware_file_rename_heuristic("writefile movefile cryptencrypt ransom")
    assert result["score"] > 0.0
    assert result["tags"]
    assert result["failure_evidence_recorded"] is False


def test_behavior_semantics_uses_exact_tag_and_blob_content() -> None:
    assert tag_behavior_bucket("process_exec") == "os_execution"
    evidence, confidence = evidence_level_for_tag("process_exec", strings_blob="process exec marker")
    assert evidence in {"string_or_pattern", "behavior_tag", "high_authority_scanner_tag"}
    assert confidence > 0.0


def test_path_identity_rejects_non_owned_falsey_path_without_hooks() -> None:
    path = _FalseyPath()
    assert get_binary_scan_extension(path) == ""
    assert engine_extension_key("unity", path).endswith(":<no_ext>")
