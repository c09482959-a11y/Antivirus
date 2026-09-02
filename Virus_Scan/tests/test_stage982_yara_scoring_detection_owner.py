from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.scoring.yara.context_evidence import (
    GenericYaraEvidenceContext,
    generic_yara_evidence_context,
)
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result

ROOT = Path(__file__).resolve().parents[1]


def test_generic_yara_context_is_detection_owned_without_calibration_alias() -> None:
    assert not (ROOT / "yara" / "scoring.py").exists()
    assert (ROOT / "detection" / "scoring" / "yara" / "context_evidence.py").exists()
    assert not (ROOT / "detection" / "scoring" / "yara" / "evidence_calibration.py").exists()


def test_detection_owned_yara_context_preserves_physical_roots_without_probability() -> None:
    result = canonical_test_yara_result(rule_name="Malware_Loader")
    context = generic_yara_evidence_context(result)
    assert type(context) is GenericYaraEvidenceContext
    assert context.root_observation_ids == (result.hits[0].root_observation_id,)
    assert context.rule_identity_digests == (result.hits[0].rule_identity.digest,)
    assert context.rule_names == ("Malware_Loader",)
    assert context.probability_authority is False
    assert context.probability_unavailable_reason == "yara_production_calibration_unavailable"


def test_core_cache_no_longer_owns_dead_fast_scoring_surface() -> None:
    source = (ROOT / "core" / "cache.py").read_text(encoding="utf-8")
    assert "def score_fast(" not in source
    assert "yara_weight(" not in source
