"""Stage 1002 classifier registry immutability and behavior contracts."""
from __future__ import annotations


from Virus_Scan.contracts.runtime_function_identity import is_runtime_native_function
from Virus_Scan.detection.correlation.multi_signal import attack_intelligence
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    AttackClassifierSpec,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIERS,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1002_attack_intelligence_registry_is_frozen_and_callable_bound() -> None:
    assert attack_intelligence.ATTACK_INTELLIGENCE_CLASSIFIERS is ATTACK_INTELLIGENCE_CLASSIFIERS
    assert type(ATTACK_INTELLIGENCE_CLASSIFIERS) is tuple
    assert len(ATTACK_INTELLIGENCE_CLASSIFIERS) == 8
    assert all(type(spec) is AttackClassifierSpec for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
    assert all(is_runtime_native_function(spec.detector) for spec in ATTACK_INTELLIGENCE_CLASSIFIERS)
    assert len({spec.classifier_id for spec in ATTACK_INTELLIGENCE_CLASSIFIERS}) == 8
    assert len({spec.family for spec in ATTACK_INTELLIGENCE_CLASSIFIERS}) == 8
    assert not hasattr(attack_intelligence, "_iter_attack_intelligence_classifiers")
    assert not hasattr(attack_intelligence, "_ATTACK_INTELLIGENCE_CLASSIFIER_NAMES")


def test_stage1002_attack_intelligence_registry_preserves_behavior() -> None:
    tags = physical_tag_evidence((
        "lateral_movement",
        "file_write",
        "process_exec",
        "admin_share_access",
        "remote_service_creation",
        "network_exfiltration",
        "credential_access",
    ))
    result = compute_attack_intelligence(tags, ())

    assert result["aggregate_probability"] > 0.0
    assert result["best_family"] == "lateral_movement"
    assert len(result["classifier_records"]) == len(ATTACK_INTELLIGENCE_CLASSIFIERS)
    assert any("lateral" in hit.lower() for hit in result["hits"])
    assert result["degraded"] is False
    assert "chain_probability" not in result
    assert "mitre_probability" not in result
