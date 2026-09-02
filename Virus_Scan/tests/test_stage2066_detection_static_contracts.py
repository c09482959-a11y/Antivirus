from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
"""Stage2066 detection static-contract regression coverage."""

from types import MappingProxyType

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    _dominant_engine_context,
)
from Virus_Scan.detection.enrichment.strings.contextual.decoded_payloads import (
    decoded_payload_tags,
)
from Virus_Scan.detection.models.stage_value_utils import (
    _plain_backing_sequence_items as detection_plain_backing_sequence_items,
)
from Virus_Scan.detection.profiles.contracts import DetectionProfileContext
from Virus_Scan.detection.profiles.engine_context import select_active_profile_engine
from Virus_Scan.detection.scoring.adaptive.availability import (
    availability_aware_layer_probability_summary,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_mapping_field,
    adaptive_public_node_reference,
)
from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    _plain_backing_sequence_items as full_analysis_plain_backing_sequence_items,
)
from Virus_Scan.detection.scoring.full_analysis.classification import (
    classify_detection_score,
)
from Virus_Scan.detection.scoring.weighting.chain_bonus import calibrated_chain_bonus


class _PlainBackedValues:
    def __init__(self, values):
        self._values = values


class _HostileFloat:
    def __float__(self):
        raise RuntimeError("caller float hook should not be used")


def test_stage2066_detection_max_key_contracts_do_not_depend_on_dict_get_overloads():
    tags = physical_tag_evidence((
        "lsass_access", "credential_dump_attempt", "process_injection",
    ))
    attack = compute_attack_intelligence(tags, ())
    assert attack["best_family"] == "credential_theft"
    assert _dominant_engine_context({"unity": 0.25, "renpy": 0.9}) == "renpy"
    assert select_active_profile_engine({"unity": 0.95, "renpy": 0.1}) == "unity"


def test_stage2066_detection_boundaries_preserve_non_string_replacements_and_frozensets():
    tags = decoded_payload_tags(
        "",
        decoded_payloads={"text": "powershell iex", "decode_chain": ("base64",)},
    )
    assert {"payload_decode_confirmed", "script_execution", "process_exec"} <= set(tags)
    assert "decoded_base64_execution_chain" not in tags
    chain_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    assert any(
        decision.candidate.chain_id == "probable_payload_execution_chain"
        and decision.status == "candidate"
        for decision in chain_evidence.decisions
    )
    failed_tags = decoded_payload_tags("", decoded_payloads={"failure_tags": ("decode_failed",)})
    assert "decoded_payload_failure_evidence" in failed_tags

    context = DetectionProfileContext(
        active_profile="other",
        selected_profile=object(),
        engine_context={},
        engine_confidence={},
        selection_reasons=(),
    )
    assert isinstance(context.selected_profile.tag_markers, frozenset)
    assert isinstance(context.selected_profile.file_extensions, frozenset)


def test_stage2066_detection_materializers_keep_plain_backing_sequences_typed():
    assert detection_plain_backing_sequence_items(_PlainBackedValues({"b", "a"})) == ("a", "b")
    assert full_analysis_plain_backing_sequence_items(
        _PlainBackedValues(frozenset(("b", "a")))
    ) == ("a", "b")


def test_stage2066_adaptive_public_contracts_return_dict_backed_records():
    mapping = MappingProxyType({"node": "sample.exe", "child": {"score": 1.0}})
    node, reason = adaptive_public_node_reference(mapping)
    assert node == "sample.exe"
    assert reason is None
    child = adaptive_public_mapping_field(mapping, "child")
    assert dict.get(child, "score") == 1.0

    summary = availability_aware_layer_probability_summary(
        {"graph": {"unavailable_reason": "graph_missing"}}
    )
    assert summary["adaptive_input_state"] == "adaptive_input_available"
    assert summary["graph_unavailable_reason"] == "graph_missing"


def test_stage2066_detection_numeric_contracts_narrow_before_float_conversion():
    assert classify_detection_score("80.0") == ("malicious", 0.95)
    assert classify_detection_score(_HostileFloat()) == ("score_unavailable", 0.0)
    chain_evidence = evaluate_chain_evidence(tags=physical_tag_evidence((
        "network_download", "file_write", "process_exec", "scheduled_task",
    )))
    score, hits = calibrated_chain_bonus(chain_evidence)
    assert score > 0.0
    assert any(
        hit.startswith(
            "chain_bonus:confirmed_os_persistence_execution@stage2636_11020_chain_registry_v5:candidate"
        )
        for hit in hits
    )
