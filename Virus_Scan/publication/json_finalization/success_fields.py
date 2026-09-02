"""Success-path compact final JSON field groups."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.yara_hits import yara_scan_result_record

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_list,
    canonical_chain_list,
    canonical_text_list,
)
from Virus_Scan.publication.json_finalization.model_evidence_boundary import safe_model_evidence_final_json_fields
from Virus_Scan.publication.json_finalization.summary_fields import append_compact_summaries
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_mapping_items,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    bounded_text_value,
)
from Virus_Scan.publication.json_finalization.record_fields import (
    crash_traceback,
    record_declared_extension,
    record_errors,
    record_extension_mismatch,
    record_filename,
    routing_engine_context,
)
from Virus_Scan.publication.json_finalization.scheduler_projection import timeout_evidence_projection
from Virus_Scan.publication.json_finalization.signal_projection import (
    contextual_signal_frame,
    functional_diagnostic_warnings,
)
from Virus_Scan.publication.json_finalization.success_context import compact_success_context
from Virus_Scan.routing.static_analysis_summary import (
    STATIC_ANALYSIS_SUMMARY_FIELD,
    static_analysis_summary_record,
)


from Virus_Scan.publication.json_finalization.truthiness import (
    boolean_field_true,
    first_present_value,
)

def compact_success_identity_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    stable_path = context["stable_path"]
    return {
        "schema_version": "scan_result_compact_v2",
        "json_schema_version": "scan_result_compact_v2",
        "sample_id": context["sample_id"],
        "sha256": context["sha256"],
        "final_sha256": context["sha256"],
        "original_path": stable_path,
        "normalized_path": stable_path,
        "final_classification": context["classification"],
        "media_type": first_present_value(record, "media_type", "sniffed_type", "sniffed_file_type"),
        "magic_type": first_present_value(record, "magic_type", "sniffed_type", "sniffed_file_type"),
        "extension_type": context["record_extension"],
        "mismatch_flag": record_extension_mismatch(record, context["tags"]),
        "scanner_path": first_present_value(record, "scanner_path", "scheduler_mode") if first_present_value(record, "scanner_path", "scheduler_mode") is not None else "unknown",
        "serial_execution_marker": context["serial_execution_marker"],
        "queue_claim_id": context["queue_claim_id"],
        "errors_warnings": [*record_errors(record), *functional_diagnostic_warnings(record, context["tags"])],
        "final_status": context["final_status"],
        "timestamp_or_deterministic_run_marker": first_present_value(record, "timestamp", "deterministic_run_marker")
        if first_present_value(record, "timestamp", "deterministic_run_marker") is not None
        else "deterministic-final-json-v1",
        "replay_checkpoint_reference": first_present_value(record, "replay_checkpoint_reference", "checkpoint_reference")
        if first_present_value(record, "replay_checkpoint_reference", "checkpoint_reference") is not None
        else "not-emitted-for-current-scan-mode",
        "profile_corruption_events": bounded_list(context["profile_events"], 8),
        "profile_schema_error": bool(context["profile_events"]),
        "node": stable_path,
        "file": stable_path,
        "path": stable_path,
        "input_file_path": stable_path,
        "filename": record_filename(record),
    }


def compact_success_classification_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    classification = context["classification"]
    return {
        "score": final_json_mapping_get(record, "score", 0.0),
        "verdict": classification,
        "class": classification,
        "classification": classification,
        "exit_code": context["exit_code"],
        "confidence": final_json_mapping_get(record, "confidence"),
        "extension": context["record_extension"],
    }


def compact_success_routing_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    tags = context["tags"]
    routing_evidence = final_json_mapping_get(record, "routing_evidence")
    return {
        "detected_engine": final_json_mapping_get(record, "detected_engine"),
        "expected_engine": final_json_mapping_get(record, "expected_engine"),
        "container_engine": final_json_mapping_get(record, "container_engine"),
        "container_engine_confidence": final_json_mapping_get(record, "container_engine_confidence"),
        "artifact_engine": final_json_mapping_get(record, "artifact_engine"),
        "artifact_engine_confidence": final_json_mapping_get(record, "artifact_engine_confidence"),
        "declared_extension": record_declared_extension(record),
        "sniffed_type": final_json_mapping_get(record, "sniffed_type"),
        "sniffed_file_type": first_present_value(record, "sniffed_file_type", "sniffed_type"),
        "sniffed_embedded_types": bounded_list(final_json_mapping_get(record, "sniffed_embedded_types"), 16),
        "embedded_payloads": canonical_text_list(first_present_value(record, "embedded_payloads", "sniffed_embedded_types"), 24, width=512),
        "extension_mismatch": record_extension_mismatch(record, tags),
        "extension_mismatch_evidence": context["extension_mismatch_evidence"],
        "cross_engine_artifact": boolean_field_true(final_json_mapping_get(record, "cross_engine_artifact", False)),
        "engine_mismatch": boolean_field_true(final_json_mapping_get(record, "engine_mismatch", False)),
        "effective_analysis_engine": final_json_mapping_get(record, "effective_analysis_engine"),
        "baseline_key": final_json_mapping_get(record, "baseline_key"),
        "engine_baseline_key": first_present_value(record, "engine_baseline_key", "baseline_key"),
        "extension_baseline": final_json_mapping_get(record, "extension_baseline"),
        "extension_baseline_key": first_present_value(record, "extension_baseline_key", "extension_baseline"),
        "engine_context": routing_engine_context(record, tags),
        "routing_evidence": routing_engine_context(record, tags)
        if routing_evidence is None
        else bounded_dict(routing_evidence, 32),
        "contextual_baseline": final_json_mapping_get(record, "contextual_baseline"),
        "container_extension_baseline": final_json_mapping_get(record, "container_extension_baseline"),
        "secondary_baseline_keys": bounded_list(final_json_mapping_get(record, "secondary_baseline_keys"), 24),
        "baseline_lookup_order": bounded_list(final_json_mapping_get(record, "baseline_lookup_order"), 12),
        "learning_baseline_key": final_json_mapping_get(record, "learning_baseline_key"),
        "blocked_baseline_keys": bounded_list(final_json_mapping_get(record, "blocked_baseline_keys"), 24),
        "learning_allowed": boolean_field_true(final_json_mapping_get(record, "learning_allowed", False)),
        "learning_reason": final_json_mapping_get(record, "learning_reason"),
        "fingerprint_evidence": canonical_text_list(final_json_mapping_get(record, "fingerprint_evidence"), 32, width=512),
    }


def compact_success_scheduler_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    duration = context["scan_duration_seconds"]
    timeout_evidence = final_json_mapping_get(record, "timeout_evidence")
    timing = final_json_mapping_get(record, "timing")
    worker_id = final_json_mapping_get(record, "worker_id")
    return {
        "scheduler_mode": final_json_mapping_get(record, "scheduler_mode"),
        "scan_session": bounded_dict(final_json_mapping_get(record, "scan_session"), 8),
        "cache_hit": boolean_field_true(final_json_mapping_get(record, "cache_hit", False)),
        "cache_source": final_json_mapping_get(record, "cache_source"),
        "worker_id": worker_id if worker_id is not None else context["serial_execution_marker"],
        "timeout_evidence": timeout_evidence_projection(timeout_evidence),
        "worker_state": final_json_mapping_get(
            timeout_evidence,
            "worker_state",
            final_json_mapping_get(record, "worker_state"),
        ),
        "timeout_budget": final_json_mapping_get(
            timeout_evidence,
            "timeout_budget",
            final_json_mapping_get(record, "timeout_budget"),
        ),
        "scan_duration_seconds": duration,
        "duration_seconds": duration,
        "duration": duration,
        "timing": bounded_dict(timing, 8)
        if timing is not None
        else {"scan_duration_seconds": duration},
        "yara_enabled": final_json_mapping_get(record, "yara_enabled"),
        "errors": record_errors(record),
        "warnings": functional_diagnostic_warnings(record, context["tags"]),
        "crash_traceback": crash_traceback(record),
    }


def compact_success_signal_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    findings = context["functional_findings"]
    yara_signals = context["yara_signals"]
    entropy_signals = context["entropy_signals"]
    archive_signals = context["archive_container_signals"]
    return {
        "tags": context["tags"][:96],
        "chains": canonical_chain_list(first_present_value(record, "chains", "attack_chains", "chain_hits"), 32),
        "temporal_signals": context["temporal_signals"],
        "markov_sequence_signals": context["markov_sequence_signals"],
        "clustering_signals": context["clustering_signals"],
        "graph_signals": context["graph_signals"],
        "yara_signals": canonical_text_list(yara_signals, 32, width=512),
        "entropy_signals": canonical_text_list(entropy_signals, 32, width=512),
        "archive_container_signals": canonical_text_list(archive_signals, 32, width=512),
        "yara": canonical_text_list(yara_signals, 32, width=512),
        "entropy": canonical_text_list(entropy_signals, 32, width=512),
        "temporal": context["temporal_signals"],
        "markov": context["markov_sequence_signals"],
        "clustering": context["clustering_signals"],
        "graph": context["graph_signals"],
        "decoded_evidence_snippets": context["decoded_evidence_snippets"],
        "evidence_snippets": context["audit_evidence_snippets"],
        "binary_failover_tags": findings["binary_failover_tags"],
        "stego_findings": findings["stego_findings"],
        "dotnet_findings": findings["dotnet_findings"],
        "ilspy_findings": findings["ilspy_findings"],
        "dncil_findings": findings["dncil_findings"],
        "contextual_signal_frame": contextual_signal_frame(
            record,
            temporal_signals=context["temporal_signals"],
            markov_sequence_signals=context["markov_sequence_signals"],
            clustering_signals=context["clustering_signals"],
            graph_signals=context["graph_signals"],
            yara_signals=yara_signals,
            entropy_signals=entropy_signals,
            archive_container_signals=archive_signals,
            decoded_evidence_snippets=context["decoded_evidence_snippets"],
        ),
    }


def compact_success_analysis_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    explanation = context["explanation"]
    reasons = context["reasons"]
    explanation_items = final_json_mapping_items(explanation)
    explanation_projection = {
        key: value
        for key, value in (() if explanation_items is None else explanation_items)
        if type(key) is str
    }
    canonical_chain_evidence = first_present_value(record, "canonical_chain_evidence")
    attack_explainability = first_present_value(record, "attack_explainability")
    fields = {
        "yara_evidence": yara_scan_result_record(final_json_mapping_get(record, "yara_evidence")),
        "yara_hits": canonical_text_list(final_json_mapping_get(record, "yara_hits"), 16, width=512),
        "canonical_chain_evidence": canonical_chain_evidence,
        "attack_explainability": attack_explainability,
        "attack_intelligence": bounded_dict(final_json_mapping_get(record, "attack_intelligence"), 32),
        "heuristics": bounded_dict(final_json_mapping_get(record, "heuristics"), 16),
        "profile_selection": bounded_dict(final_json_mapping_get(record, "profile_selection"), 12),
        "effective_stage": final_json_mapping_get(record, "effective_stage"),
        "fast_path": boolean_field_true(final_json_mapping_get(record, "fast_path", False)),
        "learn_eligible": boolean_field_true(final_json_mapping_get(record, "learn_eligible", False)),
        "active_layers": final_json_mapping_get(record, "active_layers"),
        "scan_integrity": bounded_dict(final_json_mapping_get(record, "scan_integrity"), 12),
        "evidence": [bounded_text_value(r, 512) for r in reasons],
        "explanation": {
            **explanation_projection,
            "reasons": [bounded_text_value(r, 512) for r in reasons],
            "score": final_json_mapping_get(explanation, "score"),
            "classification": final_json_mapping_get(explanation, "classification"),
        },
        "compact_output": True,
    }
    static_summary = static_analysis_summary_record(
        final_json_mapping_get(record, STATIC_ANALYSIS_SUMMARY_FIELD)
    )
    if static_summary is not None:
        fields[STATIC_ANALYSIS_SUMMARY_FIELD] = static_summary
    return fields




def build_compact_success_record(record: Mapping[str, object]) -> dict[str, object]:
    context = compact_success_context(record)
    compact: dict[str, object] = {}
    compact.update(compact_success_identity_fields(record, context))
    compact.update(compact_success_classification_fields(record, context))
    compact.update(compact_success_routing_fields(record, context))
    compact.update(compact_success_scheduler_fields(record, context))
    compact.update(compact_success_signal_fields(record, context))
    compact.update(compact_success_analysis_fields(record, context))
    if context["scheduler_fields"]:
        compact.update(context["scheduler_fields"])
    model_evidence_fields = safe_model_evidence_final_json_fields(record); compact.update(model_evidence_fields)
    append_compact_summaries(compact, record)
    return compact


__all__ = (
    'append_compact_summaries',
    'build_compact_success_record',
    'compact_success_analysis_fields',
    'compact_success_classification_fields',
    'compact_success_identity_fields',
    'compact_success_routing_fields',
    'compact_success_scheduler_fields',
    'compact_success_signal_fields',
)
