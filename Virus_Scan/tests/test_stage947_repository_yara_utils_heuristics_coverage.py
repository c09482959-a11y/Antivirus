from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from Virus_Scan.heuristics import evaluate_obfuscation
from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix
from Virus_Scan.utils.pathing import normalize_scan_path, scan_path_text
from Virus_Scan.yara.phase_contracts import (
    normalize_yara_hits,
    normalize_yara_rule_name,
    yara_expected_behavior,
    yara_parallel_group_count,
    yara_rule_count_from_source,
)


class _RuleObject:
    def __init__(self, rule: str):
        self.rule = rule


def test_stage947_yara_phase_contracts_normalize_and_classify_rules(tmp_path: Path) -> None:
    assert normalize_yara_rule_name("  Cred Steal!! Rule  ") == "Cred_Steal_Rule"
    assert normalize_yara_rule_name("x" * 200) == "x" * 160

    hits = normalize_yara_hits([
        _RuleObject("mimikatz credential rule"),
        "dropper/payload rule",
        _RuleObject("mimikatz credential rule"),
        "   ",
    ])
    assert hits == ["dropper/payload_rule", "mimikatz_credential_rule"]

    assert yara_expected_behavior("mimikatz credential rule") == "credential_access"
    assert yara_expected_behavior("ransom locker encrypt") == "destructive_or_ransomware"
    assert yara_expected_behavior("packed payload injector") == "loader_dropper_or_injection"
    assert yara_expected_behavior("backdoor beacon rat") == "c2_or_backdoor"
    assert yara_expected_behavior("benign_context_rule") == "rule_match_context"


def test_stage947_yara_rule_count_and_parallel_group_bounds(tmp_path: Path) -> None:
    rule_file = tmp_path / "rules.yar"
    rule_file.write_text(
        "private rule First { condition: true }\n"
        "global rule Second { condition: true }\n"
        "rule Third { condition: true }\n",
        encoding="utf-8",
    )
    assert yara_rule_count_from_source(rule_file) == 3

    zip_path = tmp_path / "rules.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("one.yar", "rule One { condition: true }")
        zf.writestr("nested/two.yara", "rule Two { condition: true }")
        zf.writestr("notes.txt", "not a yara rule")
    assert yara_rule_count_from_source(zip_path) == 2

    old_groups = os.environ.get("UMIGE_YARA_PARALLEL_GROUPS")
    old_max = os.environ.get("UMIGE_YARA_PARALLEL_GROUPS_MAX")
    try:
        os.environ["UMIGE_YARA_PARALLEL_GROUPS"] = "8"
        os.environ["UMIGE_YARA_PARALLEL_GROUPS_MAX"] = "1"
        assert yara_parallel_group_count(zip_path, default_groups=4, max_groups=16) == 1

        os.environ["UMIGE_YARA_PARALLEL_GROUPS"] = "8"
        os.environ["UMIGE_YARA_PARALLEL_GROUPS_MAX"] = "8"
        assert yara_parallel_group_count(zip_path, default_groups=4, max_groups=16) == 2
    finally:
        if old_groups is None:
            os.environ.pop("UMIGE_YARA_PARALLEL_GROUPS", None)
        else:
            os.environ["UMIGE_YARA_PARALLEL_GROUPS"] = old_groups
        if old_max is None:
            os.environ.pop("UMIGE_YARA_PARALLEL_GROUPS_MAX", None)
        else:
            os.environ["UMIGE_YARA_PARALLEL_GROUPS_MAX"] = old_max

    assert yara_rule_count_from_source(tmp_path / "missing.yar") is None
    assert yara_parallel_group_count(tmp_path / "missing.zip") == 1


def test_stage947_pathing_helpers_normalize_read_and_fail_closed(tmp_path: Path) -> None:
    sample = tmp_path / "MixedCase.BIN"
    sample.write_bytes(b"abcdef")

    normalized = normalize_scan_path(sample, require_exists=True)
    assert Path(normalized).is_absolute()
    assert Path(normalized).name == "MixedCase.BIN"

    assert read_artifact_prefix(sample, 3) == b"abc"
    with pytest.raises(ValueError, match="artifact_prefix_read_limit_invalid"):
        read_artifact_prefix(sample, -5)
    with pytest.raises(OSError):
        read_artifact_prefix(tmp_path / "missing.bin", 8192)

    text_path = scan_path_text(sample)
    assert "mixedcase.bin" in text_path
    assert "\\" not in text_path


def test_stage947_obfuscation_heuristic_detects_bytes_and_combined_payloads() -> None:
    result = evaluate_obfuscation(
        b"prefix \x1f\x8b\x08 trailer " + b"A" * 88,
        source="payload.bin",
    )

    assert result["source"] == "payload.bin"
    assert result["families"] == ["base64", "gzip"]
    assert result["tags"] == [
        "encoded_data_context",
        "embedded_gzip_payload",
        "encoded_payload_candidate",
    ]
