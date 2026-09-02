"""Recoverable partial scan-result JSON ownership."""
from __future__ import annotations

from pathlib import Path
from collections.abc import Mapping
import json

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_items,
)
from Virus_Scan.publication.json_finalization.checkpoint_journal import (
    is_checkpoint_journal,
    load_checkpoint_journal,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    duplicate_json_key_text,
    json_key_result,
    projection_path_result,
)

PARTIAL_RECOVERY_EVIDENCE_KEY = "_partial_result_recovery_evidence"
_PARTIAL_VALUE_MISSING = object()
PartialValue = object
PartialRecord = dict[str, PartialValue]
PartialEvidence = Mapping[str, PartialValue]


def _partial_recovery_evidence(
    reason: str,
    path: PartialValue,
    *,
    exception: BaseException | None = None,
    value: PartialValue = _PARTIAL_VALUE_MISSING,
) -> PartialRecord:
    evidence: PartialRecord = {
        "partial_result_recovery_failed": True,
        "error_category": "partial_result_recovery_failed",
        "error_source": "publication.json_finalization.partial_results",
        "reason": reason,
        "path_type": no_hook_type_name(path),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }
    if exception is not None:
        evidence["exception_type"] = no_hook_type_name(exception)
    if value is not _PARTIAL_VALUE_MISSING:
        evidence["value_type"] = no_hook_type_name(value)
    return evidence


def _partial_recovery_failure(
    reason: str,
    path: PartialValue,
    *,
    exception: BaseException | None = None,
    value: PartialValue = _PARTIAL_VALUE_MISSING,
) -> PartialRecord:
    return {
        PARTIAL_RECOVERY_EVIDENCE_KEY: _partial_recovery_evidence(
            reason,
            path,
            exception=exception,
            value=value,
        )
    }


def _partial_results_snapshot(value: PartialValue, path: PartialValue) -> PartialRecord:
    items = final_json_mapping_items(value)
    if items is None:
        if value is None:
            return {}
        return _partial_recovery_failure("partial_result_current_results_rejected", path, value=value)
    snapshot: PartialRecord = {}
    for index, (key, item) in enumerate(items):
        key_text, key_reason = json_key_result(key, index)
        if key_text in snapshot:
            key_text = duplicate_json_key_text(key_text, index)
        if key_reason:
            snapshot[key_text] = {
                PARTIAL_RECOVERY_EVIDENCE_KEY: _partial_recovery_evidence(
                    "partial_result_key_rejected",
                    path,
                    value=key,
                ),
                "value": item,
            }
        else:
            snapshot[key_text] = item
    return snapshot


def load_partial_results(path: str) -> PartialRecord:
    path_text, path_reason = projection_path_result(path)
    if path_reason:
        return _partial_recovery_failure("partial_result_path_rejected", path)
    try:
        partial = str(Path(path_text).resolve()) + ".partial"
        partial_path = Path(partial)
        if partial_path.exists() and partial_path.stat().st_size >= 2:
            if is_checkpoint_journal(partial_path):
                data = load_checkpoint_journal(partial_path)
            else:
                with partial_path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
        else:
            data = {}
    except TELEMETRY_FAILURE_ERRORS as exc:
        return _partial_recovery_failure("partial_result_read_failed", path, exception=exc)
    if type(data) is dict:
        return data
    return _partial_recovery_failure("partial_result_not_mapping", path, value=data)


def _partial_recovery_failure_record(partial: PartialEvidence) -> PartialEvidence | None:
    if type(partial) is dict:
        candidate = dict.get(partial, PARTIAL_RECOVERY_EVIDENCE_KEY)
        if type(candidate) is dict:
            return candidate
    return None


def recover_results_from_partial(path: str, results: PartialEvidence | None) -> PartialRecord:
    """Return the larger of in-memory results and valid partial output."""
    current = _partial_results_snapshot(results, path) if results is not None else {}
    partial = load_partial_results(path)
    failure = _partial_recovery_failure_record(partial)
    if failure is not None:
        if current:
            recovered = dict(current)
            recovered[PARTIAL_RECOVERY_EVIDENCE_KEY] = failure
            return recovered
        return dict(partial)
    if len(partial) > len(current):
        return partial
    return current


__all__ = (
    'PARTIAL_RECOVERY_EVIDENCE_KEY',
    'load_partial_results',
    'recover_results_from_partial',
)
