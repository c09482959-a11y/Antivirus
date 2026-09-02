from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.registries.chain_registry import (
    CANONICAL_CHAIN_RULES,
    CHAIN_REGISTRY_DIGEST,
    CHAIN_RULE_INDEX,
    chain_registry_manifest,
)
from Virus_Scan.detection.scoring.weighting.chain_bonus import calibrated_chain_bonus
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1578_chain_score_policy_has_one_immutable_registry_owner() -> None:
    assert isinstance(CANONICAL_CHAIN_RULES, tuple)
    assert isinstance(CHAIN_RULE_INDEX, MappingProxyType)
    assert CHAIN_REGISTRY_DIGEST == chain_registry_manifest()["digest"]
    assert not Path("Virus_Scan/detection/chains/composite/boost_rules.py").exists()
    assert not Path("Virus_Scan/detection/chains/composite/boost_policy.py").exists()


def test_stage1578_chain_bonus_uses_distinct_roots_and_family_deduplication() -> None:
    single_root_score, _single_hits = calibrated_chain_bonus(
        evaluate_chain_evidence(tags=physical_tag_evidence(("bitsadmin_exec",)))
    )
    corroborated_score, corroborated_hits = calibrated_chain_bonus(
        evaluate_chain_evidence(tags=physical_tag_evidence((
            "bitsadmin_exec",
            "background_transfer",
            "network_download",
        )))
    )
    assert single_root_score == 0.0
    assert corroborated_score > single_root_score
    assert all(hit.startswith("chain_bonus:") for hit in corroborated_hits)


def test_stage1578_chain_registry_projection_is_deterministic() -> None:
    first = tuple(rule.to_record() for rule in CANONICAL_CHAIN_RULES)
    second = tuple(rule.to_record() for rule in CANONICAL_CHAIN_RULES)
    assert first == second
