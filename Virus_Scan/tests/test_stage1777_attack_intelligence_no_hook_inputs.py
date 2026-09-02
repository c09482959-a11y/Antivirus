
"""Stage 1777 attack-intelligence no-hook input boundary regressions."""
from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_no_match_result
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import compute_attack_intelligence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


class HostileAttackValue:
    str_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("hostile __str__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("hostile __bool__ must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("hostile __iter__ must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("hostile __float__ must not execute")


def _reset() -> None:
    HostileAttackValue.str_calls = 0
    HostileAttackValue.bool_calls = 0
    HostileAttackValue.iter_calls = 0
    HostileAttackValue.float_calls = 0


def _assert_no_hooks() -> None:
    assert HostileAttackValue.str_calls == 0
    assert HostileAttackValue.bool_calls == 0
    assert HostileAttackValue.iter_calls == 0
    assert HostileAttackValue.float_calls == 0


def _failure_stages(result: dict) -> set[str]:
    return {failure["stage_name"] for failure in result["failure_evidence"]}


def test_attack_intelligence_rejects_hostile_tag_container_without_hooks() -> None:
    _reset()

    result = compute_attack_intelligence(HostileAttackValue(), yara_hits=(), strings_blob="")

    _assert_no_hooks()
    assert result["degraded"] is True
    assert "attack_intelligence_tag_context" in _failure_stages(result)
    assert "attack_intelligence_failure_evidence_recorded" in result["hits"]


def test_attack_intelligence_rejects_hostile_strings_blob_without_hooks() -> None:
    _reset()

    result = compute_attack_intelligence(physical_tag_evidence(("credential_access",)), yara_hits=(), strings_blob=HostileAttackValue())

    _assert_no_hooks()
    assert result["degraded"] is True
    assert "attack_intelligence_text_context" in _failure_stages(result)
    assert result["best_family"] is None
    assert result["aggregate_probability"] == 0.0


def test_attack_intelligence_rejects_hostile_yara_hits_without_hooks() -> None:
    _reset()

    result = compute_attack_intelligence(physical_tag_evidence(("process_exec",)), yara_hits=HostileAttackValue(), strings_blob="")

    _assert_no_hooks()
    assert result["degraded"] is True
    assert "attack_intelligence_yara_context" in _failure_stages(result)


def test_attack_intelligence_preserves_valid_detection_flow() -> None:
    tags = physical_tag_evidence((
        "http_upload", "dns_tunneling", "file_collection",
    ))
    result = compute_attack_intelligence(
        tags,
        yara_hits=canonical_test_yara_no_match_result(),
        strings_blob="powershell http://example.test payload",
    )

    assert result["aggregate_probability"] > 0.0
    assert result["best_family"] == "exfiltration"
    assert result["classifier_records"]
    assert "chain_evidence" not in result
    assert result["degraded"] is False


def test_stage1777_attack_intelligence_source_blocks_hookable_input_conversions() -> None:
    source = read_python_file(Path("Virus_Scan/detection/correlation/multi_signal/attack_intelligence.py"))
    forbidden = (
        "normalize_tags(tags or [])",
        "strings_blob = strings_blob or ''",
        "normalize_yara_hits(yara_hits or [])",
        "float(score or 0.0)",
        "hits.extend(detector_hits or [])",
        "getattr(detector, '__name__'",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
