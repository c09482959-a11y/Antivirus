from Virus_Scan.contracts.api_behavior import (
    API_NAME_TEXT_UNAVAILABLE,
    api_to_timeline_tag,
    build_api_regex as build_contract_api_regex,
    canonical_api_text,
    map_api_to_group,
)
from Virus_Scan.detection.tags.heuristics.primary_behavior import primary_behavior_for_tag
from Virus_Scan.detection.tags.process.api_tags import infer_tags_from_api as detection_infer_tags_from_api
from Virus_Scan.detection.tags.process.spyware_gate import gate_spyware_collection_chains as detection_gate_spyware
from Virus_Scan.scanners.text_api_mapping import infer_tags_from_api as scanner_infer_tags_from_api
from Virus_Scan.scanners.text_spyware_gate import gate_spyware_collection_chains as scanner_gate_spyware
from Virus_Scan.scanners.text_api_policy import build_api_regex as build_scanner_api_regex
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE


class HostileText:
    def __str__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("raw __str__ should not be used for API/tag model evidence")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("truthiness should not decide API/tag model evidence")


class HostileIterable:
    def __iter__(self):  # pragma: no cover - handled as unavailable evidence
        raise RuntimeError("api iterator unavailable")

    def __bool__(self):  # pragma: no cover - test fails if invoked
        raise AssertionError("truthiness should not decide API input availability")


def test_api_behavior_contract_detaches_hostile_api_text_without_clean_default():
    hostile = HostileText()

    assert canonical_api_text(hostile) == API_NAME_TEXT_UNAVAILABLE
    assert map_api_to_group(hostile) == "unknown"
    assert api_to_timeline_tag(hostile) == "api_call"


def test_detection_api_tags_emit_degraded_evidence_for_hostile_api_and_tag_inputs():
    tags = detection_infer_tags_from_api(
        [HostileText(), "GetAsyncKeyState"],
        tags=[HostileText(), "credential_access"],
    )

    assert "keylogging_behavior" in tags
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in tags
    assert DETECTION_STAGE_DEGRADED_TAG in tags


def test_detection_spyware_gate_and_primary_behavior_do_not_stringify_hostile_tags():
    gated = detection_gate_spyware([HostileText(), "spyware_behavior"], strings_blob=HostileText())

    assert "spyware_chain_intent_gate_suppressed" in gated
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in gated
    assert primary_behavior_for_tag(HostileText()) == TAG_NORMALIZATION_FAILURE_EVIDENCE


def test_scanner_api_mapping_and_spyware_gate_emit_degraded_evidence_for_hostile_inputs():
    tags = scanner_infer_tags_from_api(HostileIterable(), tags=[HostileText(), "credential_access"])
    gated = scanner_gate_spyware([HostileText(), "spyware_behavior"], strings_blob=HostileText())

    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in tags
    assert DETECTION_STAGE_DEGRADED_TAG in tags
    assert TAG_NORMALIZATION_FAILURE_EVIDENCE in gated
    assert "spyware_chain_intent_gate_suppressed" in gated


def test_api_regex_policy_builders_do_not_stringify_hostile_policy_values():
    contract_regex = build_contract_api_regex({HostileText(): (HostileText(), b"CreateFile")})
    scanner_regex = build_scanner_api_regex({HostileText(): (HostileText(), b"CreateFile")})

    assert contract_regex.search("CreateFile")
    assert scanner_regex.search("CreateFile")
