from Virus_Scan.contracts.yara_hits import (
    YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE,
    normalize_yara_hits,
    normalize_yara_rule_name,
    yara_expected_behavior,
)
from Virus_Scan.detection.correlation.behavioral.cluster_context import (
    cluster_kind_for_tags,
    cluster_relevant_tags,
    high_gate_norm,
)
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE
from Virus_Scan.yara.phase_contracts import normalize_yara_hits as phase_normalize_yara_hits


class HostileYaraText:
    def __str__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("raw __str__ should not be used for YARA model evidence")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("truthiness should not decide YARA evidence availability")


class HostileIterable:
    def __iter__(self):  # pragma: no cover - handled as unavailable evidence
        raise RuntimeError("YARA hits iterator unavailable")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("truthiness should not decide YARA hit iteration")


class RuleAttr:
    rule = " Credential Stealer Rule! "


class TextHolder:
    text = "Ransom Locker Rule"


def test_neutral_yara_contract_detaches_rule_identity_without_hostile_str():
    assert normalize_yara_rule_name(RuleAttr()) == "Credential_Stealer_Rule"
    assert normalize_yara_rule_name(TextHolder()) == "Ransom_Locker_Rule"
    assert normalize_yara_rule_name(HostileYaraText()) == ""
    assert yara_expected_behavior(HostileYaraText()) == "rule_match_unavailable"


def test_yara_hit_sequences_emit_failure_evidence_without_truthiness_or_raw_str():
    assert normalize_yara_hits([HostileYaraText(), RuleAttr(), b"dropper payload"]) == [
        "Credential_Stealer_Rule",
        "dropper_payload",
        YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE,
    ]
    assert normalize_yara_hits(HostileIterable()) == [YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE]
    assert phase_normalize_yara_hits([HostileYaraText(), "mimikatz credential"]) == [
        "mimikatz_credential",
        YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE,
    ]


def test_yara_names_do_not_grant_high_gate_or_cluster_authority():
    assert cluster_kind_for_tags([HostileYaraText()]) == "benign"
    assert "detection_observation_unavailable" in cluster_relevant_tags([HostileYaraText(), "script_execution"])
    assert high_gate_norm(HostileIterable()) == {"detection_observation_unavailable"}
