"""Success-path context assembly for compact final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.cli.exit_codes import exit_code_for_score
from Virus_Scan.runtime.api import profile_persistence_state
from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_list,
    canonical_tag_list,
    record_sample_id,
    record_sha256,
    reporting_canonical_tags,
    stable_record_path,
)
from Virus_Scan.publication.json_finalization.model_metric_projection import bounded_probability_mapping_for_final_json
from Virus_Scan.publication.json_finalization.projection_text import final_json_mapping_get
from Virus_Scan.publication.json_finalization.record_fields import (
    extension_mismatch_evidence,
    record_duration_seconds,
    record_extension,
    record_extension_mismatch,
    record_json_status,
)
from Virus_Scan.publication.json_finalization.scheduler_projection import existing_scheduler_final_json_fields
from Virus_Scan.publication.json_finalization.signal_projection import (
    audit_evidence_snippets,
    decoded_evidence,
    functional_findings,
    signal_summary,
    tag_signals,
)


from Virus_Scan.publication.json_finalization.truthiness import (
    any_signal_present,
    first_present_value,
)

def compact_record_tags(record: Mapping[str, object]) -> dict[str, object]:
    """Collect canonical explanation/tag state for compact final JSON."""
    raw_explanation = final_json_mapping_get(record, "explanation")
    explanation = {} if raw_explanation is None else bounded_dict(raw_explanation, 32)
    raw_feature_probabilities = final_json_mapping_get(raw_explanation, "feature_probabilities") if raw_explanation is not None else None
    if raw_feature_probabilities is not None:
        explanation["feature_probabilities"] = bounded_probability_mapping_for_final_json(raw_feature_probabilities, 12)
    reason_values = final_json_mapping_get(explanation, "reasons")
    reasons = bounded_list(reason_values, 24) if reason_values is not None else []
    raw_tag_values = final_json_mapping_get(record, "tags")
    raw_tags = canonical_tag_list(raw_tag_values, 128)
    tags = reporting_canonical_tags(raw_tag_values, 128)
    if record_extension_mismatch(record, raw_tags) and "extension_mismatch" not in tags:
        tags = canonical_tag_list([*tags, "extension_mismatch"], 128)
    return {
        "explanation": explanation,
        "reasons": reasons,
        "raw_tags": raw_tags,
        "tags": tags,
        "extension_mismatch_evidence": extension_mismatch_evidence(record, raw_tags),
    }


def compact_exit_code(record: Mapping[str, object], explanation: Mapping[str, object]) -> object:
    exit_code = final_json_mapping_get(record, "exit_code")
    if exit_code is None:
        exit_code = final_json_mapping_get(explanation, "exit_code")
    if exit_code is not None:
        return exit_code
    return exit_code_for_score(
        final_json_mapping_get(record, "score", 0.0),
        had_error=any_signal_present(record, "error", "errors", "detector_errors"),
    )


def compact_signal_context(record: Mapping[str, object], tags: list[object], reasons: list[object]) -> dict[str, object]:
    """Collect bounded scanner/detection signal projections for final JSON."""
    decoded_evidence_snippets = decoded_evidence(record, reasons)
    temporal_signals = signal_summary(record, "temporal_signals", "temporal_features")
    markov_sequence_signals = signal_summary(record, "markov_sequence_signals", "markov_features")
    clustering_signals = signal_summary(record, "clustering_signals", "cluster_features", "clustering_features")
    graph_signals = signal_summary(record, "graph_signals", "graph_features")
    yara_signals = bounded_list(first_present_value(record, "yara_signals", "yara_hits"), 32)
    entropy_signals = bounded_list(final_json_mapping_get(record, "entropy_signals"), 32)
    if len(entropy_signals) == 0:
        entropy_signals = tag_signals(tags, ("entropy", "packed", "encrypted", "encoded"))
    archive_container_signals = bounded_list(final_json_mapping_get(record, "archive_container_signals"), 32)
    if len(archive_container_signals) == 0:
        archive_container_signals = tag_signals(tags, ("archive", "container", "zip", "tar", "rpa", "embedded_archive"))
    return {
        "temporal_signals": temporal_signals,
        "markov_sequence_signals": markov_sequence_signals,
        "clustering_signals": clustering_signals,
        "graph_signals": graph_signals,
        "yara_signals": yara_signals,
        "entropy_signals": entropy_signals,
        "archive_container_signals": archive_container_signals,
        "decoded_evidence_snippets": decoded_evidence_snippets,
    }


def compact_success_context(record: Mapping[str, object]) -> dict[str, object]:
    tag_context = compact_record_tags(record)
    explanation = tag_context["explanation"]
    tags = tag_context["tags"]
    reasons = tag_context["reasons"]
    exit_code = compact_exit_code(record, explanation)
    signal_context = compact_signal_context(record, tags, reasons)
    decoded = signal_context["decoded_evidence_snippets"]
    profile_events = profile_persistence_state().profile_corruption_events_snapshot()
    worker_id = final_json_mapping_get(record, "worker_id")
    scheduler_mode = final_json_mapping_get(record, "scheduler_mode")
    scheduler_mode_text = str.__str__(scheduler_mode) if type(scheduler_mode) is str else ""
    queue_claim_id = first_present_value(record, "queue_claim_id", "claim_id")
    return {
        **tag_context,
        **signal_context,
        "classification": first_present_value(record, "classification", "class"),
        "exit_code": exit_code,
        "scan_duration_seconds": record_duration_seconds(record),
        "record_extension": record_extension(record),
        "audit_evidence_snippets": audit_evidence_snippets(record, reasons, decoded, tags),
        "functional_findings": functional_findings(record, tags, decoded),
        "profile_events": profile_events,
        "stable_path": stable_record_path(record),
        "sample_id": record_sample_id(record),
        "sha256": record_sha256(record),
        "final_status": record_json_status(record, exit_code=exit_code),
        "serial_execution_marker": "serial_execution"
        if (worker_id is None and scheduler_mode_text == "serial")
        else None,
        "queue_claim_id": queue_claim_id
        if queue_claim_id is not None
        else ("serial-no-queue-claim" if scheduler_mode_text == "serial" else None),
        "scheduler_fields": existing_scheduler_final_json_fields(record),
    }


__all__ = (
    'compact_exit_code',
    'compact_record_tags',
    'compact_signal_context',
    'compact_success_context',
)
