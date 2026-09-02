"""Error-path compact final JSON field groups."""
from __future__ import annotations

import os
from typing import Mapping

from Virus_Scan.contracts.yara_hits import yara_scan_result_record

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_list,
    canonical_chain_list,
    canonical_tag_list,
    canonical_text_list,
    record_sample_id,
    record_sha256,
    reporting_canonical_tags,
)
from Virus_Scan.publication.json_finalization.model_evidence_boundary import safe_model_evidence_final_json_fields
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_error_tag,
    final_json_mapping_get,
    final_json_type_name,
)
from Virus_Scan.publication.json_finalization.record_fields import (
    crash_traceback,
    extension_mismatch_evidence,
    record_declared_extension,
    record_duration_seconds,
    record_errors,
    record_extension,
    record_extension_mismatch,
    record_filename,
    routing_engine_context,
    present_text,
)
from Virus_Scan.publication.json_finalization.scheduler_projection import existing_scheduler_final_json_fields
from Virus_Scan.publication.json_finalization.signal_projection import (
    audit_evidence_snippets,
    functional_tag_findings,
)
from Virus_Scan.publication.json_finalization.success_context import compact_signal_context
from Virus_Scan.publication.json_finalization.success_fields import append_compact_summaries
from Virus_Scan.publication.json_finalization.truthiness import (
    boolean_field_true,
    first_present_value,
    signal_present,
)

def compact_error_context(record: Mapping[str, object], exc: BaseException) -> dict[str, object]:
    path = first_present_value(record, "input_file_path", "path", "file", "node")
    classification = first_present_value(record, "classification", "class")
    if classification is None:
        classification = "scan_error"
    scheduler_mode = final_json_mapping_get(record, "scheduler_mode")
    serial_scheduler = (
        type(scheduler_mode) is str
        and str.__str__(scheduler_mode) == "serial"
    )
    queue_claim_id = first_present_value(record, "queue_claim_id", "claim_id")
    tags = reporting_canonical_tags(final_json_mapping_get(record, "tags"), 64)
    errors = record_errors(record)
    errors.append(final_json_error_tag("compact_record_error", exc))
    signal_context = compact_signal_context(record, tags, errors)
    path_text = present_text(path)
    stable_path = os.path.normpath(path_text) if path_text != "" else ""
    return {
        **signal_context,
        "path": path,
        "stable_path": stable_path,
        "sha256": record_sha256({**record, "input_file_path": stable_path}),
        "classification": classification,
        "tags": tags,
        "errors": errors,
        "sample_id": record_sample_id({**record, "input_file_path": stable_path}),
        "scheduler_fields": existing_scheduler_final_json_fields(record),
        "extension_mismatch_evidence": extension_mismatch_evidence(
            record,
            canonical_tag_list(final_json_mapping_get(record, "tags"), 128),
        ),
        "serial_execution_marker": "serial_execution"
        if final_json_mapping_get(record, "worker_id") is None and serial_scheduler
        else None,
        "queue_claim_id": queue_claim_id
        if queue_claim_id is not None
        else ("serial-no-queue-claim" if serial_scheduler else None),
    }

def compact_error_identity_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": "scan_result_compact_v2",
        "json_schema_version": "scan_result_compact_v2",
        "sample_id": context["sample_id"],
        "sha256": context["sha256"],
        "final_sha256": context["sha256"],
        "original_path": context["stable_path"],
        "normalized_path": context["stable_path"],
        "final_classification": context["classification"],
        "media_type": first_present_value(record, "media_type", "sniffed_type", "sniffed_file_type"),
        "magic_type": first_present_value(record, "magic_type", "sniffed_type", "sniffed_file_type"),
        "extension_type": record_extension(record),
        "mismatch_flag": record_extension_mismatch(record, context["tags"]),
        "scanner_path": first_present_value(record, "scanner_path", "scheduler_mode") if first_present_value(record, "scanner_path", "scheduler_mode") is not None else "unknown",
        "serial_execution_marker": context["serial_execution_marker"],
        "queue_claim_id": context["queue_claim_id"],
        "errors_warnings": context["errors"],
        "final_status": "compact_record_error",
        "timestamp_or_deterministic_run_marker": first_present_value(record, "timestamp", "deterministic_run_marker")
        if first_present_value(record, "timestamp", "deterministic_run_marker") is not None
        else "deterministic-final-json-v1",
        "replay_checkpoint_reference": first_present_value(record, "replay_checkpoint_reference", "checkpoint_reference")
        if first_present_value(record, "replay_checkpoint_reference", "checkpoint_reference") is not None
        else "not-emitted-for-current-scan-mode",
        "node": context["stable_path"],
        "file": context["path"],
        "path": context["path"],
        "input_file_path": context["path"],
        "filename": record_filename(record),
    }

def compact_error_classification_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    classification = context["classification"]
    return {
        "score": final_json_mapping_get(record, "score", 0.0),
        "verdict": classification,
        "class": classification,
        "classification": classification,
        "exit_code": 4,
        "confidence": final_json_mapping_get(record, "confidence"),
        "extension": record_extension(record),
    }

def compact_error_routing_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
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
        "cross_engine_artifact": boolean_field_true(final_json_mapping_get(record, "cross_engine_artifact", default=False)),
        "engine_mismatch": boolean_field_true(final_json_mapping_get(record, "engine_mismatch", default=False)),
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
        "learning_allowed": False,
        "learning_reason": "compact_record_error",
        "fingerprint_evidence": canonical_text_list(final_json_mapping_get(record, "fingerprint_evidence"), 32, width=512),
    }

def compact_error_runtime_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    duration = record_duration_seconds(record)
    timing = final_json_mapping_get(record, "timing")
    return {
        "scheduler_mode": final_json_mapping_get(record, "scheduler_mode"),
        "scan_session": bounded_dict(final_json_mapping_get(record, "scan_session"), 8),
        "worker_id": final_json_mapping_get(record, "worker_id"),
        "scan_duration_seconds": duration,
        "duration_seconds": duration,
        "duration": duration,
        "timing": bounded_dict(timing, 8)
        if timing is not None
        else {"scan_duration_seconds": duration},
        "yara_enabled": final_json_mapping_get(record, "yara_enabled"),
        "errors": context["errors"],
        "warnings": bounded_list(final_json_mapping_get(record, "warnings"), 16),
        "crash_traceback": crash_traceback(record),
    }

def compact_error_signal_fields(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    tags = context["tags"]
    temporal_signals = context["temporal_signals"]
    markov_sequence_signals = context["markov_sequence_signals"]
    clustering_signals = context["clustering_signals"]
    graph_signals = context["graph_signals"]
    yara_signals = context["yara_signals"]
    entropy_signals = context["entropy_signals"]
    archive_signals = context["archive_container_signals"]
    decoded_evidence = context["decoded_evidence_snippets"]
    return {
        "tags": tags,
        "chains": canonical_chain_list(first_present_value(record, "chains", "attack_chains", "chain_hits"), 32),
        "temporal_signals": temporal_signals,
        "markov_sequence_signals": markov_sequence_signals,
        "clustering_signals": clustering_signals,
        "graph_signals": graph_signals,
        "yara_signals": yara_signals,
        "entropy_signals": entropy_signals,
        "archive_container_signals": archive_signals,
        "yara": yara_signals,
        "entropy": entropy_signals,
        "temporal": temporal_signals,
        "markov": markov_sequence_signals,
        "clustering": clustering_signals,
        "graph": graph_signals,
        "decoded_evidence_snippets": decoded_evidence,
        "evidence_snippets": audit_evidence_snippets(record, context["errors"], decoded_evidence, tags),
        "binary_failover_tags": functional_tag_findings(tags, ("binary_failover", "scan_failsafe", "extension_mismatch", "magic_type", "declared_")),
        "stego_findings": functional_tag_findings(tags, ("stego", "polyglot", "embedded_pe", "embedded_zip", "appended", "image_decode", "png_invalid", "entropy")),
        "dotnet_findings": functional_tag_findings(tags, ("dotnet", "assembly_load", "reflection", "dynamic_loader", "methodinfo", "process_exec", "powershell", "webclient", "download")),
        "ilspy_findings": bounded_list(final_json_mapping_get(record, "ilspy_findings"), 16),
        "dncil_findings": functional_tag_findings(tags, ("pseudo_dncil", "il_op_", "assembly_load", "reflection", "dynamic_loader", "methodinfo", "download_execute", "process_exec", "powershell")),
    }

def compact_error_contextual_frame(record: Mapping[str, object], context: Mapping[str, object]) -> dict[str, object]:
    return {
        "container_engine": final_json_mapping_get(record, "container_engine"),
        "artifact_engine": final_json_mapping_get(record, "artifact_engine"),
        "effective_analysis_engine": final_json_mapping_get(record, "effective_analysis_engine"),
        "declared_extension": final_json_mapping_get(record, "declared_extension"),
        "sniffed_type": final_json_mapping_get(record, "sniffed_type"),
        "baseline_key": final_json_mapping_get(record, "baseline_key"),
        "contextual_baseline": final_json_mapping_get(record, "contextual_baseline"),
        "learning_allowed": False,
        "signal_presence": {
            "temporal_signals": signal_present(context["temporal_signals"]),
            "markov_sequence_signals": signal_present(context["markov_sequence_signals"]),
            "clustering_signals": signal_present(context["clustering_signals"]),
            "graph_signals": signal_present(context["graph_signals"]),
            "yara_signals": signal_present(context["yara_signals"]),
            "entropy_signals": signal_present(context["entropy_signals"]),
            "archive_container_signals": signal_present(context["archive_container_signals"]),
            "decoded_evidence_snippets": signal_present(context["decoded_evidence_snippets"]),
        },
    }

def compact_error_analysis_fields(record: Mapping[str, object], context: Mapping[str, object], exc: BaseException) -> dict[str, object]:
    error_tag = final_json_error_tag("compact_record_error", exc)
    explanation = final_json_mapping_get(record, "explanation")
    canonical_chain_evidence = first_present_value(record, "canonical_chain_evidence")
    return {
        "contextual_signal_frame": compact_error_contextual_frame(record, context),
        "yara_evidence": yara_scan_result_record(final_json_mapping_get(record, "yara_evidence")),
        "yara_hits": canonical_text_list(final_json_mapping_get(record, "yara_hits"), 16, width=512),
        "canonical_chain_evidence": canonical_chain_evidence,
        "attack_intelligence": {},
        "heuristics": {},
        "profile_selection": bounded_dict(final_json_mapping_get(record, "profile_selection"), 12),
        "effective_stage": final_json_mapping_get(record, "effective_stage"),
        "fast_path": boolean_field_true(final_json_mapping_get(record, "fast_path", default=False)),
        "learn_eligible": False,
        "active_layers": final_json_mapping_get(record, "active_layers"),
        "scan_integrity": {"compact_record_error": final_json_type_name(exc)},
        "evidence": [error_tag],
        "explanation": {
            "reasons": [error_tag],
            "score": final_json_mapping_get(record, "score"),
            "classification": context["classification"],
        },
        "compact_output": True,
        "compact_error": True,
    }

def build_compact_error_record(record: Mapping[str, object], exc: BaseException) -> dict[str, object]:
    context = compact_error_context(record, exc)
    compact: dict[str, object] = {}
    compact.update(compact_error_identity_fields(record, context))
    compact.update(compact_error_classification_fields(record, context))
    compact.update(compact_error_routing_fields(record, context))
    compact.update(compact_error_runtime_fields(record, context))
    compact.update(compact_error_signal_fields(record, context))
    compact.update(compact_error_analysis_fields(record, context, exc))
    compact.update(context["scheduler_fields"])
    append_compact_summaries(compact, record)
    model_evidence_fields = safe_model_evidence_final_json_fields(record); compact.update(model_evidence_fields)
    return compact
__all__ = (
    'build_compact_error_record',
    'compact_error_analysis_fields',
    'compact_error_classification_fields',
    'compact_error_context',
    'compact_error_contextual_frame',
    'compact_error_identity_fields',
    'compact_error_routing_fields',
    'compact_error_runtime_fields',
    'compact_error_signal_fields',
)
