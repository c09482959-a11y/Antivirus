from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.utils.entropy import entropy_from_counts, shannon_entropy_bytes
from Virus_Scan.detection.contracts.file_read import read_file_bytes
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.profile_baselines import ensure_extension_model_fields
from Virus_Scan.contracts.yara_hits import normalize_yara_hits, normalize_yara_rule_name


class _YaraLikeHit:
    def __init__(self, rule: str | None = None, name: str | None = None) -> None:
        self.rule = rule
        self.name = name


def test_stage957_detection_file_read_contract_is_bounded_and_does_not_hide_missing_files(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    target.write_bytes(b"abcdef")

    assert read_file_bytes(target, max_size=3) == b"abc"
    assert read_file_bytes(target, max_size=0) == b""
    assert read_file_bytes(target, max_size=None) == b"abcdef"
    assert read_file_bytes(target, max_size=-1) == b"abcdef"

    with pytest.raises(FileNotFoundError):
        read_file_bytes(tmp_path / "missing.bin", max_size=4)


def test_stage957_yara_hit_contract_normalizes_dedupes_and_sorts_mixed_hit_shapes() -> None:
    hits = [
        {"rule": " SuspiciousRule "},
        {"name": "FallbackName"},
        {"id": "RuleId"},
        _YaraLikeHit(rule="SuspiciousRule"),
        _YaraLikeHit(rule=None, name="ObjectName"),
        " raw_scalar ",
        {"rule": ""},
        None,
    ]

    assert normalize_yara_rule_name("  DemoRule  ") == "DemoRule"
    assert normalize_yara_hits(hits) == [
        "FallbackName",
        "ObjectName",
        "RuleId",
        "SuspiciousRule",
        "raw_scalar",
    ]


def test_stage957_detection_path_identity_preserves_rpgm_encrypted_asset_extensions_without_trusting_suffix_only() -> None:
    assert get_scan_extension("Audio/BGM/theme.ogg_") == ".ogg"
    assert get_scan_extension("www/img/picture.PNG_") == ".png"
    assert get_scan_extension("Game.rgss3a") == ".rgss3a"
    assert get_scan_extension("archive.unknown_") == ".unknown_"
    assert get_scan_extension("") == ""


def test_stage957_profile_baseline_contract_adds_nested_defaults_without_replacing_existing_state() -> None:
    existing_vector = {"count": 7, "mean": [1.0], "m2": [0.5], "variance": [0.25], "feature_names": ["score"]}
    existing_timeline = {"sample_count": 2, "event_counts": {"network": 1}}
    baseline = {"vector_baseline": existing_vector, "timeline_baseline": existing_timeline, "tags": {"known": 1}}

    returned = ensure_extension_model_fields(baseline)

    assert returned is baseline
    assert returned["vector_baseline"] is existing_vector
    assert returned["timeline_baseline"] is existing_timeline
    assert returned["timeline_baseline"]["event_counts"] == {"network": 1}
    assert returned["timeline_baseline"]["transition_counts"] == {}
    assert returned["timeline_baseline"]["max_sequence_len"] == 0
    assert returned["learning_gate"] == {"accepted": 0, "rejected": 0, "last_rejection_reason": ""}
    assert returned["tags"] == {"known": 1}


def test_stage957_canonical_entropy_contract_handles_empty_uniform_and_count_inputs() -> None:
    assert shannon_entropy_bytes(b"") == 0.0
    assert shannon_entropy_bytes(None) == 0.0
    assert shannon_entropy_bytes(b"aaaa") == pytest.approx(0.0, abs=1e-9)
    assert shannon_entropy_bytes(b"\x00\x01") == pytest.approx(1.0, abs=1e-9)
    assert entropy_from_counts([1, 1], 2) == pytest.approx(1.0, abs=1e-9)
    assert entropy_from_counts([2, 0, None], 2) == pytest.approx(0.0, abs=1e-9)
    assert entropy_from_counts([1, 1], 0) == 0.0


def test_stage957_detection_contract_modules_keep_static_import_boundaries() -> None:
    for module_path in (
        Path("Virus_Scan/detection/contracts/file_read.py"),
        Path("Virus_Scan/contracts/path_identity.py"),
        Path("Virus_Scan/detection/contracts/profile_baselines.py"),
        Path("Virus_Scan/utils/entropy.py"),
    ):
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "importlib" for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert node.level == 0
                assert node.module != "importlib"
                assert node.module not in {"Virus_Scan.scanners", "Virus_Scan.scheduler", "Virus_Scan.reporting"}
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert not any(isinstance(child, (ast.Import, ast.ImportFrom)) for child in ast.walk(node))
