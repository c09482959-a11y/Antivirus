from __future__ import annotations

from types import MappingProxyType, ModuleType

from Virus_Scan.detection.contracts import filetype_context
from Virus_Scan.detection.enrichment.pe_analysis import il2cpp_static
from Virus_Scan.detection.registries import snapshot
from Virus_Scan.detection.scoring.adaptive import log_odds_fusion


class HostilePolicyObject:
    __slots__ = ()

    def __iter__(self):
        raise RuntimeError("iteration must not be used")

    def __str__(self):
        raise RuntimeError("string conversion must not be used")


class HostileTags:
    def __iter__(self):
        raise RuntimeError("tag iteration failed")


def test_stage2065_filetype_policy_helpers_return_typed_unavailable_evidence() -> None:
    mapping_result = filetype_context._policy_mapping_items(HostilePolicyObject())
    sequence_result = filetype_context._policy_sequence_items(HostilePolicyObject())

    assert type(mapping_result) is filetype_context.FiletypePolicyUnavailable
    assert mapping_result.as_evidence()["filetype_policy_unavailable"] is True
    assert mapping_result.as_evidence()["reason"] == "plain_instance_backing_unavailable"
    assert type(sequence_result) is filetype_context.FiletypePolicyUnavailable
    assert sequence_result.as_evidence()["field_name"] == "_values"


def test_stage2065_il2cpp_unsupported_signature_registry_emits_typed_failure_tag(tmp_path) -> None:
    unavailable = il2cpp_static._il_signature_items(object())

    assert type(unavailable) is il2cpp_static.ILSignatureRegistryUnavailable
    assert unavailable.reason == "il_signature_registry_unsupported"
    assert unavailable.as_tag() == "il2cpp_signature_registry_unavailable"


def test_stage2065_detection_registry_snapshot_unavailable_module_dict_is_replayable() -> None:
    unavailable = snapshot._module_registry_unavailable("module_dict_unavailable", ModuleType("x"))

    assert unavailable[0][0] == "DETECTION_REGISTRY_UNAVAILABLE"
    evidence = unavailable[0][1]
    assert type(evidence) is MappingProxyType
    assert evidence["detection_registry_unavailable"] is True
    assert evidence["reason"] == "module_dict_unavailable"
    assert evidence["replay_must_record"] is True


def test_stage2065_log_odds_concrete_count_status_publishes_unavailable_reason() -> None:
    def broken_count(_tags):
        raise RuntimeError("count unavailable")

    original_count = log_odds_fusion.concrete_score_count
    log_odds_fusion.concrete_score_count = broken_count
    try:
        status = log_odds_fusion.log_odds_concrete_count_status(HostileTags())

        assert type(status) is log_odds_fusion.ConcreteCountUnavailable
        assert status.count == 0
        evidence = status.as_evidence()
        assert evidence["concrete_scoreable_evidence_count_unavailable"] is True
        assert evidence["reason"] == "concrete_score_count_unavailable"
        assert log_odds_fusion.log_odds_concrete_count(HostileTags()) == 0
    finally:
        log_odds_fusion.concrete_score_count = original_count
