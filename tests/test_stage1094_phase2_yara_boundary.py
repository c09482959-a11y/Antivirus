"""Stage 1094 Phase 2 generic YARA authority removal regressions."""
from __future__ import annotations

from Virus_Scan.yara import constants as yara_constants
from Virus_Scan.yara import match as yara_match
from Virus_Scan.detection.scoring.yara.context_evidence import generic_yara_evidence_context
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result


def test_generic_yara_name_authority_owner_is_removed() -> None:
    assert not hasattr(yara_constants, "YARA_HIGH_GATE_AUTHORITY_KEYWORDS")
    assert not hasattr(yara_match, "_high_gate_yara_authority")


def test_generic_yara_context_is_descriptive_and_zero_authority() -> None:
    context = generic_yara_evidence_context(
        canonical_test_yara_result(rule_name="Win_Trojan_Mimikatz_Stealer")
    )

    assert context.probability_authority is False
    assert context.probability_unavailable_reason == "yara_production_calibration_unavailable"
    assert context.rule_names == ("Win_Trojan_Mimikatz_Stealer",)
