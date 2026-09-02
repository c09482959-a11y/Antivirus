"""Stage 1423: detection stage models must not truthiness-probe caller-owned values."""

from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.detection.models.enriched_stage_outputs import DetectionEvidenceFacts, EnrichedDetectionFacts
from Virus_Scan.detection.models.evidence import StageCollectorMerge
from Virus_Scan.detection.models.evidence_stage_outputs import ChainEvidence, TagEvidence
from Virus_Scan.detection.models.input_stage_outputs import NormalizedFacts, RawScanFacts
from Virus_Scan.detection.models.result_stage_outputs import DetectionResult
from Virus_Scan.detection.models.stage_value_utils import thaw_detection_value
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.model_context_fixtures import model_context_snapshot_fixture


class HostileBoolIterable:
    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("truthiness unavailable")

    def __iter__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("iteration unavailable")


class HostileBoolMapping(Mapping):
    def __bool__(self):  # pragma: no cover - old value-or-default code probed this
        raise RuntimeError("mapping truthiness unavailable")

    def __iter__(self):
        return iter(("alpha",))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        if key == "alpha":
            return 7
        raise KeyError(key)


class UnreadableMapping(Mapping):
    def __bool__(self):  # pragma: no cover - old value-or-default code probed this
        raise RuntimeError("mapping truthiness unavailable")

    def __iter__(self):
        raise RuntimeError("mapping iteration unavailable")

    def __len__(self):
        raise RuntimeError("mapping length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("mapping item unavailable")

    def keys(self):
        raise RuntimeError("mapping keys unavailable")


class HostileText:
    def __bool__(self):  # pragma: no cover - old string defaults probed this
        raise RuntimeError("text truthiness unavailable")

    def __str__(self):  # pragma: no cover - safe text should convert to evidence
        raise RuntimeError("text unavailable")


class HostileBool:
    def __bool__(self):  # pragma: no cover - exercised by safe bool
        raise RuntimeError("bool unavailable")


def _failure_reasons(facts) -> set[str]:
    thawed = thaw_detection_value(facts.failure_evidence)
    return {item.get("unavailable_reason") for item in thawed if isinstance(item, dict)}


def test_stage1423_raw_and_normalized_facts_record_hostile_boundary_values() -> None:
    raw = RawScanFacts.from_inputs(
        path="sample.py",
        tags=HostileBoolIterable(),
        yara_hits=HostileBoolIterable(),
        curr_stage="scan",
        strings_blob=HostileText(),
        strings_already_enriched=HostileBool(),
    )
    normalized = NormalizedFacts.from_values(
        path=HostileText(),
        node=HostileText(),
        tags=HostileBoolIterable(),
        yara_hits=HostileBoolIterable(),
        curr_stage=HostileText(),
        strings_blob=HostileText(),
        strings_already_enriched=HostileBool(),
    )

    assert raw.tags[0]["unavailable_reason"] == "detection_iterable_unavailable"
    assert raw.yara_hits.status == "unavailable"
    assert raw.yara_hits.unavailable_reason == "yara_scan_result_invalid"
    assert {"raw_scan_strings_blob_unavailable", "raw_scan_strings_already_enriched_unavailable"} <= _failure_reasons(raw)
    assert raw.strings_blob == ""
    assert raw.strings_already_enriched is False

    reasons = _failure_reasons(normalized)
    assert {
        "normalized_path_unavailable",
        "normalized_node_unavailable",
        "normalized_stage_unavailable",
        "normalized_strings_blob_unavailable",
        "normalized_strings_already_enriched_unavailable",
    } <= reasons
    assert normalized.curr_stage == "unknown"


def test_stage1423_enriched_facts_freeze_hostile_evidence_boundaries() -> None:
    tag_evidence = TagEvidence(tags=HostileBoolIterable(), reasons=UnreadableMapping())
    chain_evidence = evaluate_chain_evidence(tags=tag_evidence)
    evidence = DetectionEvidenceFacts(
        api_result=HostileBoolMapping(),
        behavior_timeline=HostileBoolIterable(),
        ordered_events=HostileBoolIterable(),
        tag_evidence=tag_evidence,
        chain_evidence=chain_evidence,
        attack_info=HostileBoolMapping(),
        baseline_maturity=HostileBoolMapping(),
        evidence_provenance=HostileBoolMapping(),
        heur=HostileBoolMapping(),
    )
    facts = EnrichedDetectionFacts.from_evidence(
        evidence, model_context_snapshot_fixture(graph_features={"risk": 0.0}),
    )

    assert facts.tags[0]["unavailable_reason"] == "detection_iterable_unavailable"
    assert thaw_detection_value(facts.api_result)["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert facts.graph_features["risk"] == 0.0
    assert facts.active_profile == "other"


def test_stage1423_evidence_and_result_models_do_not_probe_hostile_truthiness() -> None:
    chain = ChainEvidence(chains=HostileBoolIterable(), reasoning=HostileBoolIterable())
    tag = TagEvidence(tags=HostileBoolIterable(), reasons=UnreadableMapping())
    result = DetectionResult.from_mapping(UnreadableMapping())
    merge = StageCollectorMerge(
        tags=HostileBoolIterable(),
        metadata=UnreadableMapping(),
        suspicious=HostileBool(),
        errors=HostileBoolIterable(),
    )

    assert chain.chains[0]["unavailable_reason"] == "detection_iterable_unavailable"
    assert chain.reasoning[0]["unavailable_reason"] == "detection_iterable_unavailable"
    assert tag.tags[0]["unavailable_reason"] == "detection_iterable_unavailable"
    assert tag.reasons["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert result.payload["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert merge.suspicious is False
    assert any(
        isinstance(item, Mapping) and item.get("unavailable_reason") == "stage_collector_suspicious_unavailable"
        for item in merge.errors
    )
    assert any(
        isinstance(item, Mapping) and item.get("source_unavailable_reason") == "detection_iterable_unavailable"
        for item in merge.errors
    )
