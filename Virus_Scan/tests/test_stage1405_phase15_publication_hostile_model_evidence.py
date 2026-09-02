"""Stage 1405: publication final-JSON projection preserves hostile model evidence."""

from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


class HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("mapping iteration unavailable")

    def __len__(self):
        raise RuntimeError("mapping length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("mapping item unavailable")

    def get(self, key, default=None):
        raise RuntimeError("mapping get unavailable")

    def keys(self):
        raise RuntimeError("mapping keys unavailable")

    def items(self):
        raise RuntimeError("mapping items unavailable")

    def values(self):
        raise RuntimeError("mapping values unavailable")

    def __repr__(self):
        return "<HostileMapping>"


def _evidence_for(record: Mapping[str, object]) -> Mapping[str, object]:
    projected = build_model_evidence_final_json_fields(record)
    assert "model_evidence" in projected
    evidence = projected["model_evidence"]
    assert isinstance(evidence, Mapping)
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["model_failures"]
    assert evidence["unavailable_reasons"]
    return evidence


def test_stage1405_publication_absorbs_hostile_root_model_evidence_and_feature_probabilities() -> None:
    model_evidence = _evidence_for({"model_evidence": HostileMapping()})
    assert model_evidence["unavailable_reasons"]["model_evidence"] == "unreadable_model_evidence_record"

    feature_probabilities = _evidence_for({"feature_probabilities": HostileMapping()})
    assert feature_probabilities["unavailable_reasons"]["feature_probabilities"] == "unreadable_feature_probability_record"


def test_stage1405_publication_absorbs_hostile_model_signal_mappings() -> None:
    score_metadata = _evidence_for({"score_metadata": HostileMapping()})
    assert score_metadata["unavailable_reasons"]["score_metadata"] == "unreadable_model_evidence_mapping"

    model_context = _evidence_for({"model_context": HostileMapping()})
    assert model_context["unavailable_reasons"]["model_context"] == "unreadable_model_evidence_mapping"


def test_stage1405_publication_absorbs_hostile_nested_evidence_and_contract_records() -> None:
    unavailable = _evidence_for({"model_evidence": {"unavailable_reasons": HostileMapping()}})
    assert unavailable["unavailable_reasons"]["model_evidence.unavailable_reasons"] == "unreadable_model_evidence_mapping"

    failure = _evidence_for({"model_failure": [HostileMapping()]})
    assert failure["unavailable_reasons"]["model_failure"] == "unreadable_model_failure_record"

    comparison = _evidence_for({"replay_model_comparison": HostileMapping()})
    assert comparison["unavailable_reasons"]["replay_model_comparison"] == "unreadable_model_evidence_mapping"
