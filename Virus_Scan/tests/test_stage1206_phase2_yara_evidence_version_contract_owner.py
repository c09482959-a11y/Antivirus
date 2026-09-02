"""Stage 1206: YARA context versions are neutral contracts."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts import yara_hits as neutral_yara_hits
from Virus_Scan.detection.scoring.yara import context_evidence
from Virus_Scan.yara import constants as yara_constants


def test_yara_context_uses_neutral_physical_scan_contract() -> None:
    source = Path(context_evidence.__file__).read_text(encoding="utf-8")
    assert "Virus_Scan.yara.constants" not in source
    assert "Virus_Scan.contracts.yara_hits" in source
    assert context_evidence.GENERIC_YARA_EVIDENCE_CONTEXT_SCHEMA_VERSION.startswith(
        "stage2636_11008_"
    )


def test_yara_domain_reexports_neutral_evidence_version_without_duplication() -> None:
    source = Path(yara_constants.__file__).read_text(encoding="utf-8")
    assert "ANALYTICAL_EVIDENCE_SCHEMA_VERSION = 1" not in source
    assert "YARA_CALIBRATION_VERSION = 1" not in source
    assert yara_constants.YARA_CALIBRATION_VERSION == neutral_yara_hits.YARA_CALIBRATION_VERSION
    assert yara_constants.ANALYTICAL_EVIDENCE_SCHEMA_VERSION == neutral_yara_hits.ANALYTICAL_EVIDENCE_SCHEMA_VERSION


def test_yara_hit_contract_keeps_stable_rule_identity_semantics() -> None:
    hits = [{"rule": " Bad Rule!! "}, type("Hit", (), {"rule": "Other.Rule"})()]
    assert neutral_yara_hits.normalize_yara_hits(hits) == ["Bad_Rule", "Other.Rule"]
    assert neutral_yara_hits.yara_expected_behavior("MimikatzCredential") == "credential_access"
