"""Phase 14 evidence-backed positive/control challenge corpus gates."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.api import release_yara_runtime, yara_rules_state
from Virus_Scan.stress import attack_synthetic_corpus as corpus
from Virus_Scan.stress.artifact_attack_projection import artifact_behavior_satisfied
from Virus_Scan.stress.artifact_evidence_oracle import derive_artifact_evidence_truth
from Virus_Scan.stress.attack_synthetic_challenges import (
    validate_synthetic_attack_challenge_pair,
)
from Virus_Scan.stress.attack_synthetic_schema import SYNTHETIC_REQUIRED_CHALLENGE_KINDS
from Virus_Scan.stress.attack_synthetic_templates import SYNTHETIC_ATTACK_CHALLENGE_PAIRS
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import CorpusFixtureDefinition
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.loader import load_yara_rules, load_yaralight_rules
from Virus_Scan.yara.match import yara_scan

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CORE_ARCHIVE = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-core.zip"
_EXTENDED_ARCHIVE = _REPOSITORY_ROOT / "Yara" / "yara-forge-rules-extended.zip"
_CORE_SHA256 = "3ad85d8518e5e968d930c93dadae9dcd7d215d0911d8d8f02717f15922c8529f"
_EXTENDED_SHA256 = "756bd295a87603d78f1c879ecb7d217c91c1bcb03461c34e604fa20a4a0acae5"
_YARA_RULE = "GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13"


def _pair(challenge_id: str):
    return next(item for item in SYNTHETIC_ATTACK_CHALLENGE_PAIRS if item.challenge_id == challenge_id)


def _truth(fixture, sample_id: str):
    renderer = fixture.renderer_specification
    payload = render_static_semantic_artifact(sample_id, renderer)
    truth = derive_artifact_evidence_truth(sample_id, sample_id + renderer.extension, payload)
    return payload, truth


def _rule_names(result) -> set[str]:
    return {item.rule_identity.rule_name for item in result.hits}


def test_phase14_registry_covers_every_required_adversarial_challenge() -> None:
    covered = {kind for pair in SYNTHETIC_ATTACK_CHALLENGE_PAIRS for kind in pair.challenge_kinds}
    assert set(SYNTHETIC_REQUIRED_CHALLENGE_KINDS) <= covered
    assert len({pair.challenge_id for pair in SYNTHETIC_ATTACK_CHALLENGE_PAIRS}) == len(SYNTHETIC_ATTACK_CHALLENGE_PAIRS)
    assert all(pair.positive_fixture.generation_intent.malware_class == "malware" for pair in SYNTHETIC_ATTACK_CHALLENGE_PAIRS)
    assert all(pair.control_fixture.generation_intent.malware_class == "control" for pair in SYNTHETIC_ATTACK_CHALLENGE_PAIRS)


def test_phase14_native_controls_change_causality_not_vocabulary() -> None:
    positive = _truth(_pair("native_disconnected_value_flow").positive_fixture, "native-positive")[1]
    disconnected = _truth(_pair("native_disconnected_value_flow").control_fixture, "native-disconnected")[1]
    wrong_target = _truth(_pair("native_wrong_target_resource").control_fixture, "native-wrong-target")[1]
    unresolved = _truth(_pair("native_unresolved_indirect").control_fixture, "native-unresolved")[1]
    assert set(positive.operation_kinds) == set(disconnected.operation_kinds)
    assert {(item.source_operation_kind, item.sink_operation_kind, item.connected) for item in positive.flow} == {("file_read", "network_send", True)}
    assert {(item.source_operation_kind, item.sink_operation_kind, item.connected) for item in disconnected.flow} == {("file_read", "network_send", False)}
    assert set(positive.operation_kinds) == set(wrong_target.operation_kinds)
    assert set(positive.resource_identities) != set(wrong_target.resource_identities)
    assert unresolved.evidence_completeness == "partial"
    assert "unresolved_indirect_native_call" in unresolved.analysis_limitations


def test_phase14_reviewed_yara_hit_cannot_rescue_behaviorless_control(tmp_path: Path) -> None:
    pair = _pair("t1059_001_reviewed_yara_corroboration")
    positive_payload, positive_truth = _truth(pair.positive_fixture, "yara-positive")
    control_payload, control_truth = _truth(pair.control_fixture, "yara-control")
    positive_path, control_path = tmp_path / "positive.ps1", tmp_path / "control.ps1"
    positive_path.write_bytes(positive_payload)
    control_path.write_bytes(control_payload)
    assert artifact_behavior_satisfied(positive_truth, "T1059.001") is True
    assert artifact_behavior_satisfied(control_truth, "T1059.001") is False
    config = YaraConfig(full_expected_sha256=_EXTENDED_SHA256, light_expected_sha256=_CORE_SHA256)
    try:
        core = load_yaralight_rules(str(_CORE_ARCHIVE), auto_download=False, use_cache=False, config=config, allow_cache_write=False)
        assert core.load_result.ready is True
        assert _YARA_RULE in _rule_names(yara_scan(positive_path, compiled_rules=yara_rules_state().light_snapshot()))
        assert _YARA_RULE in _rule_names(yara_scan(control_path, compiled_rules=yara_rules_state().light_snapshot()))
        extended = load_yara_rules(str(_EXTENDED_ARCHIVE), auto_download=False, use_cache=False, config=config, allow_cache_write=False)
        assert extended.load_result.ready is True
        assert _YARA_RULE in _rule_names(yara_scan(positive_path, compiled_rules=yara_rules_state().primary_snapshot()))
        assert _YARA_RULE in _rule_names(yara_scan(control_path, compiled_rules=yara_rules_state().primary_snapshot()))
    finally:
        release_yara_runtime()


def test_phase14_pair_validator_rejects_missing_wrong_target_contrast(tmp_path: Path) -> None:
    pair = _pair("native_wrong_target_resource")
    positive_sample = corpus._sample(tmp_path, pair.positive_fixture, 0)
    same_behavior = corpus._sample(tmp_path, pair.positive_fixture, 1)
    try:
        validate_synthetic_attack_challenge_pair(
            pair, positive_sample[-1], same_behavior[-1], positive_sample[0].technique_expectations,
        )
    except ValueError as exc:
        assert "resource_identity_not_changed" in str(exc)
    else:
        raise AssertionError("wrong-target pair accepted without a target change")


def test_phase14_sample_build_fails_when_positive_behavior_does_not_survive_rendering(
    tmp_path: Path,
) -> None:
    pair = _pair("t1003_lsass_documentation")
    corrupted_fixture = CorpusFixtureDefinition(
        generation_intent=pair.positive_fixture.generation_intent,
        renderer_specification=pair.control_fixture.renderer_specification,
    )
    try:
        corpus._sample(tmp_path / "artifacts", corrupted_fixture, 0)
    except ValueError as exc:
        assert "synthetic_attack_generation_behavior_missing" in str(exc)
    else:
        raise AssertionError("sample build accepted a positive with missing physical behavior")
