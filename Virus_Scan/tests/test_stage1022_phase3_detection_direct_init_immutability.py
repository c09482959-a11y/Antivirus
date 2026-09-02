from types import MappingProxyType

import pytest

from Virus_Scan.detection.models.enriched_stage_outputs import DetectionEvidenceFacts, EnrichedDetectionFacts
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.model_context_fixtures import model_context_snapshot_fixture
from Virus_Scan.detection.models.evidence import StageCollectorMerge
from Virus_Scan.detection.models.evidence_stage_outputs import ChainEvidence, TagEvidence
from Virus_Scan.detection.models.input_stage_outputs import NormalizedFacts, RawScanFacts
from Virus_Scan.contracts.yara_hits import YaraScanResult
from Virus_Scan.tests.support.canonical_yara_fixtures import canonical_test_yara_result
from Virus_Scan.detection.models.result_stage_outputs import DetectionResult
from Virus_Scan.detection.models.stage_value_utils import freeze_detection_value, thaw_detection_value
from Virus_Scan.detection.profiles.contracts import DetectionProfileContext, DetectionProfileSnapshot
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import DetectionDecision, ScoreBreakdown


def test_detection_freeze_helpers_deep_freeze_mappingproxy_inputs():
    nested = {"items": ["one"]}
    frozen = freeze_detection_value(MappingProxyType({"nested": nested}))
    nested["items"].append("two")

    assert frozen["nested"]["items"] == ("one",)
    with pytest.raises(TypeError):
        frozen["nested"]["items"] += ("three",)

    registry_nested = {"tags": ["alpha"]}
    registry_frozen = freeze_registry_value(MappingProxyType({"profile": registry_nested}))
    registry_nested["tags"].append("beta")
    assert registry_frozen["profile"]["tags"] == ("alpha",)

    first_registry = freeze_registry_value({"z": ("b", "a"), "a": {"nested": ("two", "one")}})
    second_registry = freeze_registry_value({"a": {"nested": ("two", "one")}, "z": ("b", "a")})
    assert tuple(first_registry.keys()) == ("a", "z")
    assert tuple(first_registry["a"].keys()) == ("nested",)
    assert first_registry == second_registry


def test_detection_freeze_helpers_canonicalize_mapping_and_set_order_for_replay():
    first = freeze_detection_value({"z": {"b", "a"}, "a": {"nested": {"two", "one"}}})
    second = freeze_detection_value({"a": {"nested": {"one", "two"}}, "z": {"a", "b"}})

    assert tuple(first.keys()) == ("a", "z")
    assert thaw_detection_value(first) == thaw_detection_value(second)
    assert thaw_detection_value(first) == {"a": {"nested": ["one", "two"]}, "z": ["a", "b"]}

    result = DetectionResult({"tags": {"beta", "alpha"}, "metadata": {"b": 2, "a": 1}})
    assert result.as_result_record() == {"metadata": {"a": 1, "b": 2}, "tags": ["alpha", "beta"]}


def test_detection_input_stage_outputs_deep_freeze_direct_constructor_values():
    tags = [{"tag": ["a"]}]
    result_record = canonical_test_yara_result().to_record()
    raw = RawScanFacts(
        path="sample.py",
        tags=tags,
        yara_hits=result_record,
        curr_stage="scan",
        strings_blob="abc",
        strings_already_enriched=False,
        failure_evidence=({"stage_name": "raw", "state": ["degraded"]},),
    )
    normalized = NormalizedFacts(
        path="sample.py",
        node="sample.py",
        tags=tags,
        yara_hits=("stage2636_exfiltration",),
        curr_stage="scan",
        strings_blob="abc",
        strings_already_enriched=False,
        yara_evidence=result_record,
        failure_evidence=({"stage_name": "norm", "state": ["degraded"]},),
    )

    tags[0]["tag"].append("b")
    result_record["hits"][0]["rule_identity"]["rule_name"] = "mutated"

    assert raw.tags[0]["tag"] == ("a",)
    assert type(raw.yara_hits) is YaraScanResult
    assert raw.yara_hits.hits[0].rule_identity.rule_name == "stage2636_exfiltration"
    assert normalized.tags[0]["tag"] == ("a",)
    assert normalized.yara_hits == ("stage2636_exfiltration",)
    assert normalized.yara_evidence.hits[0].rule_identity.rule_name == "stage2636_exfiltration"


def test_detection_enriched_and_result_outputs_deep_freeze_direct_constructor_values():
    api_result = {"calls": ["open"]}
    tag_evidence = normalize_tag_evidence(
        ("tag",), source_detector="stage1022", source_stage="constructor",
    )
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    evidence = DetectionEvidenceFacts(
        api_result=api_result,
        behavior_timeline=[{"event": ["start"]}],
        ordered_events=[],
        tag_evidence=tag_evidence,
        chain_evidence=chain_evidence,
        attack_info={},
        baseline_maturity={},
        evidence_provenance={},
        heur={},
    )
    facts = EnrichedDetectionFacts.from_evidence(
        evidence,
        model_context_snapshot_fixture(profile_context={
            "active_profile": "renpy",
            "engine_confidence": {"active_profile": "renpy", "failure_evidence": ()},
        }),
    )
    result_payload = {"evidence": {"tags": ["initial"]}}
    result = DetectionResult(result_payload)

    api_result["calls"].append("eval")
    result_payload["evidence"]["tags"].append("mutated")

    assert facts.api_result["calls"] == ("open",)
    assert facts.behavior_timeline[0]["event"] == ("start",)
    assert result.payload["evidence"]["tags"] == ("initial",)
    assert result.as_result_record()["evidence"]["tags"] == ["initial"]


from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


def test_detection_scoring_and_evidence_outputs_deep_freeze_direct_constructor_values():
    explanation = {"reasons": ["r1"]}
    breakdown = ScoreBreakdown(
        7,
        explanation,
        normalize_tag_evidence(("tag",), source_detector="stage1022", source_stage="constructor"),
        ({"stage_name": "score", "state": ["degraded"]},),
    )
    decision_layer = {"layers": ["graph"]}
    decision = DetectionDecision(
        8,
        explanation,
        "suspicious",
        decision_layer,
        {"calibration": ["a"]},
        ({"stage_name": "decision", "state": ["degraded"]},),
    )
    merge_metadata = {"evidence": ["m1"]}
    merge = StageCollectorMerge(tags=["a"], metadata=merge_metadata, suspicious=True, errors=["err"])

    explanation["reasons"].append("r2")
    decision_layer["layers"].append("score")
    merge_metadata["evidence"].append("m2")

    assert breakdown.explanation["reasons"] == ("r1",)
    assert decision.explanation["reasons"] == ("r1",)
    assert decision.layer_report["layers"] == ("graph",)
    assert merge.metadata["evidence"] == ("m1",)
    assert merge.as_tuple()[1]["evidence"] == ["m1"]


def test_detection_profile_context_deep_freezes_direct_constructor_mappings():
    snapshot = DetectionProfileSnapshot(
        name="RenPy",
        aliases=["Ren'Py"],
        tag_markers=["rpy"],
        file_extensions=[".RPY"],
        baseline_suppression_profile="renpy",
        selected_engine_context_key="renpy",
    )
    engine_context = {"weights": [0.9]}
    context = DetectionProfileContext(
        active_profile="renpy",
        selected_profile=snapshot,
        engine_context=engine_context,
        engine_confidence={"reasons": ["marker"]},
        selection_reasons=["selected"],
    )

    engine_context["weights"].append(0.1)

    assert snapshot.name == "renpy"
    assert snapshot.file_extensions == frozenset({".rpy"})
    assert context.engine_context["weights"] == (0.9,)
    assert context.to_record()["engine_context"]["weights"] == (0.9,)


def test_tag_and_chain_evidence_accept_mutable_inputs_without_sharing():
    chains = [{"chain": ["a"]}]
    tag_reasons = {"why": ["x"]}
    chain_evidence = ChainEvidence(chains=chains, reasoning=chains)
    tag_evidence = TagEvidence(tags=["tag"], reasons=tag_reasons)

    chains[0]["chain"].append("b")
    tag_reasons["why"].append("y")

    assert chain_evidence.chains[0]["chain"] == ("a",)
    assert chain_evidence.reasoning[0]["chain"] == ("a",)
    assert tag_evidence.tags == ("tag",)
    assert tag_evidence.reasons["why"] == ("x",)

from Virus_Scan.detection.registries.publication import freeze_registry_publication
from Virus_Scan.runtime.init_state import freeze_init_value
from Virus_Scan.runtime.scan_integrity_state import RuntimeScanIntegrityState


def test_runtime_and_registry_mappingproxy_inputs_are_deep_frozen():
    init_nested = {"values": ["before"]}
    frozen_init = freeze_init_value(MappingProxyType({"runtime": init_nested}))
    init_nested["values"].append("after")
    assert frozen_init["runtime"]["values"] == ("before",)

    publication_nested = {"aliases": ["one"]}
    frozen_publication = freeze_registry_publication(MappingProxyType({"registry": publication_nested}))
    publication_nested["aliases"].append("two")
    assert frozen_publication["registry"]["aliases"] == ("one",)

    integrity_nested = {"evidence": ["initial"]}
    state = RuntimeScanIntegrityState()
    state.set("sample", MappingProxyType({"scan": integrity_nested}))
    integrity_nested["evidence"].append("mutated")
    assert state.get("sample")["scan"]["evidence"] == ("initial",)
