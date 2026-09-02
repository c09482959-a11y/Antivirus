"""Bounded deterministic value projection helpers for final JSON."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import PurePosixPath
from typing import Mapping

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.contracts.no_hook_materialization import exact_finite_float_or_none
from Virus_Scan.publication.json_finalization.truthiness import (
    first_present_value,
    iterable_values_without_truthiness,
)
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_mapping_items,
    projection_failure,
    safe_projection_sort_key,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    json_key_result,
    mapping_pair_sort_key,
    projection_text_or_failure,
    projection_text_or_marker,
    projection_text_result,
    projection_unavailable_text,
)
from Virus_Scan.publication.json_finalization.model_metric_projection import (
    bounded_probability_mapping,
    is_model_probability_mapping_key,
    is_model_probability_metric_key,
    model_metric_projection_failure,
)
from Virus_Scan.publication.json_finalization.sha_projection import record_sha256

def stable_record_path(record: Mapping[str, object]) -> str:
    """Return the canonical path used by final JSON identity fields."""
    path = first_present_value(record, "input_file_path", "path", "file", "node")
    if path is None:
        return ""
    text, reason = projection_text_result(path)
    if reason:
        return projection_unavailable_text(path, reason)
    if text == "":
        return ""
    return os.path.normpath(text).replace("\\", "/")

def record_sample_id(record: Mapping[str, object]) -> str:
    """Return an explicit stable sample id for persisted JSON records.

    Test corpora may assign ids in fixture filenames (``sample_0001__...``).
    Production scans still receive a deterministic identity derived from the
    normalized input path so replay/reload validation can refer to the record
    without relying on dictionary ordering.
    """
    existing = final_json_mapping_get(record, "sample_id")
    existing_text, existing_reason = projection_text_result(existing)
    if existing is not None and existing_reason == "" and existing_text != "":
        return existing_text
    filename_value = final_json_mapping_get(record, "filename")
    filename_source = filename_value if filename_value is not None else PurePosixPath(stable_record_path(record)).name
    filename, filename_reason = projection_text_result(filename_source)
    if filename_reason:
        filename = ""
    prefix = filename.split("__", 1)[0]
    for sample_prefix in ("sample_", "malicious_", "benign_", "synthetic_"):
        if prefix.startswith(sample_prefix) and len(prefix) > len(sample_prefix):
            return prefix
    stable_path = stable_record_path(record)
    digest = hashlib.sha256(stable_path.encode("utf-8", errors="replace")).hexdigest()[:16]
    return "path_" + digest


def bounded_list(value: object, limit: int = 64) -> list[object]:
    """Return a bounded JSON-list projection without splitting scalar text.

    Scanner subsystems are not perfectly uniform: some emit ``errors`` or
    ``warnings`` as a single string while others emit a list.  The final JSON
    contract requires explicit error records; splitting a scalar string into
    characters makes the failure ambiguous and breaks evidence validation.
    Normalize scalar text as one entry at the reporting boundary.
    """
    try:
        if value is None:
            projected_items: list[object] = []
        elif type(value) in (set, frozenset):
            projected_items = [
                bounded_signal_value(item)
                for item in sorted(value, key=safe_projection_sort_key)
            ]
        elif isinstance(value, str):
            projected_items = [str.__str__(value)]
        elif type(value) is bytes:
            projected_items = [value.decode("utf-8", errors="replace")]
        elif type(value) is bytearray:
            projected_items = [bytes(value).decode("utf-8", errors="replace")]
        elif final_json_mapping_items(value) is not None:
            projected_items = [bounded_dict(value, 16)]
        elif type(value) in (tuple, list):
            projected_items = [bounded_signal_value(item) for item in value]
        else:
            direct_values = iterable_values_without_truthiness(value)
            projected_items = (
                [bounded_signal_value(item) for item in direct_values]
                if direct_values
                else [projection_failure("final_json_list_value_unavailable", value)]
            )
    except TELEMETRY_FAILURE_ERRORS:
        projected_items = [projection_failure("final_json_list_projection_failure", value)]
    return projected_items[:limit]

def canonical_tag_list(value: object, limit: int = 128) -> list[str]:
    """Return deterministic forensic tag output without changing detection scoring.

    Scheduler modes can merge tag evidence from independently completed workers.
    The detection record may therefore arrive with equivalent tag sets in different
    insertion orders.  Final JSON is a persistence/reporting boundary, so tags are
    canonicalized here as unique strings sorted case-insensitively. Timeline and
    sequence semantics remain in temporal and Markov fields.
    """
    raw_items = iterable_values_without_truthiness(value)
    if raw_items == [] and value is not None and type(value) not in (list, tuple, set, frozenset):
        raw_items = [value]
    items = [projection_text_or_marker(item) for item in raw_items]
    return sorted(dict.fromkeys(items), key=lambda item: (item.lower(), item))[:limit]

def reporting_canonical_tags(value: object, limit: int = 128) -> list[str]:
    """Return canonical detector tags with reporting-only mismatch tokens removed.

    Declared/sniffed mismatch facts are persisted in extension_mismatch and
    extension_mismatch_evidence. Keeping scheduler-specific generated mismatch
    tokens in tags causes serial/process drift and changes canonical tag meaning.
    """
    raw = canonical_tag_list(value, limit)
    filtered: list[str] = []
    for tag in raw:
        text = tag
        low = text.lower()
        if low.startswith("declared_") and "_sniffs_as_" in low:
            continue
        filtered.append(text)
    return filtered[:limit]

def canonical_chain_list(value: object, limit: int = 32) -> list[str]:
    """Return deterministic chain identifiers at the reporting boundary.

    Chain construction keeps sequence semantics inside the detection/model record.
    Final JSON is consumed by replay validators and byte-for-byte comparisons, so
    equivalent merged worker outputs must not drift solely because process workers
    completed in a different order.
    """
    raw_items = iterable_values_without_truthiness(value)
    if raw_items == [] and value is not None and type(value) not in (list, tuple, set, frozenset):
        raw_items = [value]
    items = [projection_text_or_marker(item) for item in raw_items]
    return sorted(dict.fromkeys(items), key=lambda item: (item.lower(), item))[:limit]

def canonical_text_list(value: object, limit: int = 32, *, width: int = 512) -> list[object]:
    """Return a deterministic unique text list for order-insensitive audit fields.

    Evidence snippets, diagnostic warnings, and scanner hit names can be merged
    from process workers in completion order.  These compact-report fields are
    audit facts rather than sequence models, so canonicalizing them at the final
    JSON boundary prevents replay drift without changing detector scoring or
    temporal/Markov order.  Scalar text is one forensic fact; treating it as an
    iterable would split evidence such as a YARA rule name into characters and
    make medium/high/malicious JSON evidence unreadable.
    """
    try:
        if value is None:
            raw_items: list[object] = []
        elif isinstance(value, bytes):
            raw_items = [value.decode("utf-8", errors="replace")]
        elif isinstance(value, str):
            raw_items = [value]
        elif final_json_mapping_items(value) is not None:
            raw_items = [json.dumps(bounded_dict(value, 16), ensure_ascii=False, sort_keys=True)]
        else:
            raw_items = iterable_values_without_truthiness(value)
            if raw_items == [] and value is not None and type(value) not in (list, tuple, set, frozenset):
                return [projection_failure("final_json_text_unavailable", value)]
        items = []
        for item in raw_items:
            if item is None:
                continue
            text = projection_text_or_marker(item, width=width)
            if text != "":
                items.append(text)
    except TELEMETRY_FAILURE_ERRORS:
        return [projection_failure("final_json_text_projection_failure", value)]
    return sorted(dict.fromkeys(items), key=lambda item: (item.lower(), item))[:limit]

def bounded_dict(value: object, limit: int = 12) -> dict[str, object]:
    items = final_json_mapping_items(value)
    if items is None:
        if value is None:
            return {"_unavailable_mapping": projection_failure("final_json_mapping_unavailable", value)}
        return {"_unavailable_mapping": projection_failure("final_json_mapping_projection_failure", value)}
    out: dict[str, object] = {}
    ordered = sorted(items, key=mapping_pair_sort_key)
    for idx, (key, v) in enumerate(ordered):
        if idx >= limit:
            out["_truncated"] = True
            break
        out_key, key_reason = json_key_result(key, idx)
        if key_reason:
            out[out_key] = projection_failure(key_reason, key)
            continue
        if type(v) is float and not math.isfinite(v):
            out[out_key] = {
                "model_signal_projection_failed": True,
                "reason": "non_finite_model_signal_value",
            }
        elif is_model_probability_metric_key(key) and v is not None:
            probability = exact_finite_float_or_none(v)
            if probability is None:
                if type(v) is float and not math.isfinite(v):
                    out[out_key] = model_metric_projection_failure("non_finite_probability")
                else:
                    out[out_key] = model_metric_projection_failure("non_numeric_probability")
            elif probability < 0.0 or probability > 1.0:
                out[out_key] = model_metric_projection_failure("out_of_bounds_probability")
            else:
                out[out_key] = probability
        elif is_model_probability_mapping_key(key):
            if v is None:
                out[out_key] = None
            elif final_json_mapping_items(v) is not None:
                out[out_key] = bounded_probability_mapping(v, 12)
            else:
                out[out_key] = model_metric_projection_failure("non_mapping_probability_container")
        elif isinstance(v, str) or type(v) in (int, float, bool) or v is None:
            out[out_key] = str.__str__(v)[:512] if isinstance(v, str) else v
        elif type(v) is list:
            out[out_key] = [bounded_signal_value(x) for x in v[:16]]
        elif type(v) is tuple:
            out[out_key] = [bounded_signal_value(x) for x in v[:16]]
        elif final_json_mapping_items(v) is not None:
            out[out_key] = bounded_dict(v, 12)
        else:
            out[out_key] = projection_text_or_failure(v, 512)
    return out

def bounded_signal_value(value: object) -> object:
    """Return a bounded JSON-native subsystem signal value.

    Temporal, Markov, clustering, and graph analyzers often emit list-shaped
    evidence containing dictionaries.  Stringifying those dictionaries at the
    final reporting boundary destroys field names/types and makes JSON evidence
    audits unable to prove which model produced which fact.  Preserve dict/list
    structure in bounded form and only stringify scalar leaf values.
    """
    if final_json_mapping_items(value) is not None:
        return bounded_dict(value, 16)
    if type(value) is tuple:
        return [bounded_signal_value(item) for item in value[:32]]
    if type(value) is list:
        return [bounded_signal_value(item) for item in value[:32]]
    if type(value) in (set, frozenset):
        return [bounded_signal_value(item) for item in sorted(value, key=safe_projection_sort_key)[:32]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, float) and not math.isfinite(value):
            return {
                "model_signal_projection_failed": True,
                "reason": "non_finite_model_signal_value",
            }
        return str.__str__(value)[:512] if isinstance(value, str) else value
    return projection_text_or_failure(value, 512)

def contains_non_finite_float(value: object) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    items = final_json_mapping_items(value)
    if items is not None:
        return any(contains_non_finite_float(item) for _key, item in items)
    if type(value) in (list, tuple, set, frozenset):
        return any(contains_non_finite_float(item) for item in value)
    return False

__all__ = (
    'bounded_dict',
    'bounded_list',
    'bounded_probability_mapping',
    'bounded_signal_value',
    'canonical_chain_list',
    'canonical_tag_list',
    'canonical_text_list',
    'contains_non_finite_float',
    'is_model_probability_mapping_key',
    'is_model_probability_metric_key',
    'model_metric_projection_failure',
    'record_sample_id',
    'record_sha256',
    'reporting_canonical_tags',
    'stable_record_path',
)
