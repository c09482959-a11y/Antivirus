"""Identity, routing, duration, and error field projection for final JSON."""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Mapping

from Virus_Scan.publication.json_finalization.base_projection import bounded_list
from Virus_Scan.publication.json_finalization.extension_mismatch import (
    extension_mismatch_evidence,
    record_extension_mismatch,
    sniffed_tag_projection_token,
)
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_mapping_items,
    present_text,
    projection_failure,
)
from Virus_Scan.publication.json_finalization.record_numeric import exact_int_value, exact_nonnegative_float

from Virus_Scan.publication.json_finalization.truthiness import (
    boolean_field_true,
    first_present_value,
)

PLR2004N16 = 16

_MISSING = object()


def record_json_status(record: Mapping[str, object], *, exit_code: object) -> str:
    """Return explicit final persistence status without default-clean masking."""
    errors = record_errors(record)
    if errors:
        return "completed_with_errors"
    numeric_exit = exact_int_value(exit_code, present_text)
    if numeric_exit is None:
        return "completed_unknown_exit"
    if numeric_exit != 0:
        return "completed_nonzero_exit"
    return "completed"


def record_filename(record: Mapping[str, object]) -> str | None:
    """Return the stable basename used by JSON evidence validators.

    Engine-routing validation compares records across scheduler modes by
    canonical path, but human audit reports also require a filename field.
    Derive it once at the reporting boundary from the already-normalized
    identity fields instead of letting each scanner invent its own spelling.
    """
    value = first_present_value(record, "filename", "file_name")
    value_text = present_text(value)
    if value_text != "":
        return PurePosixPath(value_text.replace("\\", "/")).name
    path = first_present_value(record, "input_file_path", "path", "file", "node")
    path_text = present_text(path)
    if path_text == "":
        return None
    basename = PurePosixPath(path_text.replace("\\", "/")).name
    return basename if basename != "" else path_text[:512]


def record_extension(record: Mapping[str, object]) -> str:
    """Return the declared extension required by JSON evidence audits.

    Some internal result records arrive at the final reporting boundary with
    only a path/file/node identity.  The final JSON contract still requires an
    extension and declared_extension for every per-file record.  Derive that
    value once from canonical path identity rather than letting downstream
    validators infer it inconsistently.
    """
    for key in ("extension", "declared_extension"):
        value = final_json_mapping_get(record, key)
        text = present_text(value)
        if text:
            return text.removeprefix(".")
    path = first_present_value(record, "input_file_path", "path", "file", "node")
    path_text = present_text(path)
    if path_text == "":
        return ""
    suffix = PurePosixPath(path_text.replace("\\", "/")).suffix
    if suffix == "" and "final_json_text_unavailable" in path_text:
        return "final_json_extension_unavailable"
    return suffix[1:] if suffix.startswith(".") else (suffix or "")


def record_declared_extension(record: Mapping[str, object]) -> str:
    """Return declared extension in the scanner contract's declared format.

    ``extension`` is the compact extension bucket used by older JSON consumers,
    while ``declared_extension`` preserves the explicit declared spelling when
    scanners supplied it.  If scanners only supplied a path, derive the dotted
    filesystem suffix for mismatch/audit evidence.
    """
    value = final_json_mapping_get(record, "declared_extension")
    text = present_text(value)
    if text:
        return text
    value = final_json_mapping_get(record, "extension")
    text = present_text(value)
    if text:
        return text
    path = first_present_value(record, "input_file_path", "path", "file", "node")
    path_text = present_text(path)
    if path_text == "":
        return ""
    suffix = PurePosixPath(path_text.replace("\\", "/")).suffix
    if suffix == "" and "final_json_text_unavailable" in path_text:
        return "final_json_extension_unavailable"
    return suffix if suffix != "" else ""


def record_errors(record: Mapping[str, object]) -> list[object]:
    """Return explicit error evidence from all canonical scanner error fields.

    Some scanner boundaries report a single scalar ``error`` while scheduler
    and detector boundaries may report ``errors`` or ``detector_errors``.
    The compact JSON contract must not publish exit_code 4 with an empty
    error list, because that hides the failure behind an apparently clean
    record.  Merge those fields once at the reporting boundary without
    changing scanner control flow.
    """
    raw_errors = final_json_mapping_get(record, "_finalizer_raw_errors", _MISSING)
    if raw_errors is not _MISSING:
        return bounded_list(raw_errors, 16)
    merged: list[object] = []
    for key in ("errors", "error", "detector_errors"):
        value = final_json_mapping_get(record, key)
        if value is None:
            continue
        for item in bounded_list(value, 16):
            if item not in merged:
                merged.append(item)
        if len(merged) >= PLR2004N16:
            break
    return merged[:16]


def record_duration_seconds(record: Mapping[str, object]) -> float | dict[str, object]:
    """Return an explicit numeric scan duration for every compact record.

    Missing duration is a legitimate compact-record absence case: direct scan
    results and recovered error records may not own runtime timing.  Keep that
    contract as the initialized projection value while ensuring rejected or
    unsafe numeric values still become explicit failure evidence instead of
    falling through to the absence value.
    """
    projected_duration: float | dict[str, object] = 0.0
    invalid_value: object = None
    for key in ("scan_duration_seconds", "duration_seconds", "duration"):
        value = final_json_mapping_get(record, key)
        if value is None:
            continue
        numeric = exact_nonnegative_float(value, present_text)
        if numeric is not None:
            return numeric
        if invalid_value is None:
            invalid_value = value
    timing = final_json_mapping_get(record, "timing")
    timing_items = final_json_mapping_items(timing)
    if timing_items is not None:
        for key in ("scan_duration_seconds", "duration_seconds", "duration"):
            value = final_json_mapping_get(timing, key)
            if value is None:
                continue
            if (numeric := exact_nonnegative_float(value, present_text)) is not None:
                return numeric
            if invalid_value is None:
                invalid_value = value
    elif timing is not None and invalid_value is None:
        invalid_value = timing
    if invalid_value is not None:
        projected_duration = projection_failure("unsafe_numeric_value_rejected", invalid_value)
    return projected_duration


def routing_engine_context(record: Mapping[str, object], tags: list[object] | None = None) -> dict[str, object]:
    """Return deterministic engine-routing context for compact JSON.

    This is a projection of canonical routing fields, not a second routing path.
    Validators need one object that proves container identity, artifact identity,
    sniffed identity, baseline keys, mismatch state, and learning suppression
    survived finalization together.
    """
    return {
        "detected_engine": final_json_mapping_get(record, "detected_engine"),
        "container_engine": final_json_mapping_get(record, "container_engine"),
        "artifact_engine": final_json_mapping_get(record, "artifact_engine"),
        "effective_analysis_engine": final_json_mapping_get(record, "effective_analysis_engine"),
        "declared_extension": record_declared_extension(record),
        "sniffed_file_type": first_present_value(record, "sniffed_file_type", "sniffed_type"),
        "engine_baseline_key": first_present_value(record, "engine_baseline_key", "baseline_key"),
        "extension_baseline_key": first_present_value(record, "extension_baseline_key", "extension_baseline"),
        "extension_mismatch": record_extension_mismatch(record, tags),
        "cross_engine_artifact": boolean_field_true(final_json_mapping_get(record, "cross_engine_artifact", default=False)),
        "embedded_payloads": bounded_list(first_present_value(record, "embedded_payloads", "sniffed_embedded_types"), 24),
        "learning_allowed": boolean_field_true(final_json_mapping_get(record, "learning_allowed", default=False)),
        "learning_reason": final_json_mapping_get(record, "learning_reason"),
    }


def crash_traceback(record: Mapping[str, object]) -> str | None:
    value = first_present_value(record, "crash_traceback", "traceback")
    text = present_text(value)
    if text != "":
        return text[:4096]
    return None


__all__ = (
    'crash_traceback',
    'extension_mismatch_evidence',
    'record_declared_extension',
    'record_duration_seconds',
    'record_errors',
    'record_extension',
    'record_extension_mismatch',
    'record_filename',
    'record_json_status',
    'routing_engine_context',
    'sniffed_tag_projection_token',
)
