"""Canonical parent replay-learning persistence owner."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import logging

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.result_record import is_passive_fast_asset_result
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.contracts.retained_scan_result import (
    retained_parent_replay_payload,
    retained_result_marker_present,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.api.profile_learning_contracts import (
    commit_promoted_learning,
    learning_verdict_is_clean,
)
from Virus_Scan.models.api.replay_economics_contracts import (
    replay_compress_metadata,
    replay_should_retain,
)
from Virus_Scan.runtime.environment import runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.runtime.structured_failures import record_suppressed_failure

from Virus_Scan.models.replay.payload import result_learning_payload
from Virus_Scan.models.replay.transaction_projection import (
    project_runtime_transaction_stats,
)
from Virus_Scan.models.replay.learning_boundaries import (
    has_non_empty_text_field,
    replay_mapping_get,
    replay_mapping_items,
    replay_mapping_values,
    result_parent_replayed,
    safe_summary_count,
)
from Virus_Scan.models.replay.payload_boundaries import safe_truthy_replay_flag
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name

_REPLAY_TOTAL_KEYS = ("checked", "runtime", "clean_checked", "committed", "promoted", "errors")


def empty_replay_summary(**extra: object) -> dict[str, object]:
    summary = dict.fromkeys(_REPLAY_TOTAL_KEYS, 0)
    summary.update(extra)
    return summary


def parent_replay_result_learning(result: object) -> dict[str, object]:
    """Run parent-side model replay and clean profile learning for one result."""
    if type(result) is not dict:
        return empty_replay_summary()
    retained = retained_result_marker_present(result)
    if not retained and result_parent_replayed(result):
        return empty_replay_summary(skipped="already_replayed")
    payload = retained_parent_replay_payload(result) if retained else result_learning_payload(result)
    if payload is None:
        return empty_replay_summary(skipped="no_payload")
    if safe_truthy_replay_flag(replay_mapping_get(payload, "replay_payload_unavailable")):
        return empty_replay_summary(
            errors=1,
            degraded=True,
            skipped=replay_mapping_get(payload, "reason", "parent_replay_payload_unavailable"),
        )
    summary = empty_replay_summary(checked=1)
    learning_result: dict[str, object] | None = None
    try:
        file_path = replay_mapping_get(payload, "file_path", "")
        ext_l = get_scan_extension(file_path)
        if ext_l in {".tmp", ".cache", ".pyc", ".pyo", ".yarc"}:
            learning_result = {
                "learned": False,
                "reason": "extension_excluded_from_parent_learning",
                "promoted": False,
            }
        elif replay_mapping_get(replay_mapping_get(payload, "integrity", {}), "allow_learning") is False:
            learning_result = {
                "learned": False,
                "reason": "scan_integrity_blocks_learning",
                "promoted": False,
            }
        elif learning_verdict_is_clean(replay_mapping_get(payload, "verdict")) and not (
            replay_mapping_get(payload, "passive_fast_asset") is True
            if retained
            else is_passive_fast_asset_result(result)
        ):
            summary["clean_checked"] = 1
            replay_tag_evidence = TagEvidence.from_record(
                replay_mapping_get(payload, "tag_evidence")
            )
            learning_result = commit_promoted_learning(
                replay_mapping_get(payload, "engine"),
                file_path,
                replay_tag_evidence,
                yara_hits=replay_mapping_get(payload, "yara_hits", []) if type(replay_mapping_get(payload, "yara_hits", [])) is list else [],
                risk=replay_mapping_get(payload, "score") if type(replay_mapping_get(payload, "score")) in (int, float) else 0.0,
                strings_blob="",
                verdict=replay_mapping_get(payload, "verdict"),
                api_calls=replay_mapping_get(payload, "api_calls", []) if type(replay_mapping_get(payload, "api_calls", [])) is list else [],
                ordered_events=replay_mapping_get(payload, "ordered_events", []) if type(replay_mapping_get(payload, "ordered_events", [])) is list else [],
                behavior_flow=_learning_behavior_flow(payload),
                prev_stage=replay_mapping_get(payload, "prev_stage") if type(replay_mapping_get(payload, "prev_stage")) is str else "unknown",
                curr_stage=replay_mapping_get(payload, "curr_stage") if type(replay_mapping_get(payload, "curr_stage")) is str else "unknown",
                observation_id=replay_mapping_get(payload, "observation_id"),
                scan_integrity=replay_mapping_get(payload, "integrity", {}),
            )
            if replay_mapping_items(learning_result) is not None:
                if safe_truthy_replay_flag(replay_mapping_get(learning_result, "learned")) or has_non_empty_text_field(learning_result, "reason"):
                    summary["committed"] = 1
                if safe_truthy_replay_flag(replay_mapping_get(learning_result, "promoted")):
                    summary["promoted"] = 1
        else:
            learning_result = {
                "learned": False,
                "reason": "verdict_not_clean_for_profile_learning",
                "promoted": False,
            }
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        summary["errors"] += 1
        learning_result = {
            "learned": False,
            "reason": "parent_clean_learning_error",
            "error_type": no_hook_type_name(exc),
            "promoted": False,
        }
        log_error("parent clean learning replay failed")
    runtime_stats = project_runtime_transaction_stats(learning_result, summary)
    if not retained:
        _record_parent_replay_metadata(result, learning_result, runtime_stats)
        result["_umige_parent_model_replayed"] = True
    return summary


def _learning_behavior_flow(payload: Mapping[str, object]) -> list[object]:
    behavior_flow = replay_mapping_get(payload, "behavior_flow")
    if type(behavior_flow) is list:
        return behavior_flow
    flow = replay_mapping_get(payload, "flow")
    if type(flow) is list:
        return flow
    return []


def _record_parent_replay_metadata(
    result: dict[str, object],
    learning_result: Mapping[str, object] | None,
    runtime_stats: Mapping[str, object],
) -> None:
    try:
        exp = result.setdefault("explanation", {})
        if isinstance(exp, dict):
            retain_replay = replay_should_retain(result)
            learning_items = replay_mapping_items(learning_result) or ()
            replay_meta = {
                "runtime": runtime_stats,
                "learning": {k: v for k, v in learning_items if k != "baseline"},
                "retained": retain_replay is True,
            }
            if retain_replay is True:
                exp["parent_model_replay"] = replay_compress_metadata(replay_meta)
            else:
                exp["parent_model_replay"] = {"retained": False}
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure("suppressed_exception", suppressed_exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc


def persist_parent_learning_from_results(results: object) -> dict[str, object]:
    """Replay worker model observations in the parent after workers finish."""
    if runtime_worker_shared_persistence_writes_disabled():
        return empty_replay_summary()
    totals = empty_replay_summary()
    iterable, unavailable_reason = _parent_replay_iterable(results)
    if unavailable_reason is not None:
        totals["errors"] = 1
        totals["degraded"] = True
        totals["final_json_must_record"] = True
        totals["replay_record_required"] = True
        totals["unavailable_reason"] = unavailable_reason
    for result in iterable:
        summary = parent_replay_result_learning(result)
        for key in _REPLAY_TOTAL_KEYS:
            _add_summary_count(totals, summary, key)
    _log_replay_totals(totals)
    return totals


def _parent_replay_iterable(results: object) -> tuple[Iterable[object], str | None]:
    try:
        values = replay_mapping_values(results)
        if values is not None:
            return values, None
        if isinstance(results, Mapping):
            return (), "parent_replay_results_mapping_values_failed"
        if results is None:
            return (), None
        if isinstance(results, (str, bytes)) or not isinstance(results, Iterable):
            return (), "non_iterable_parent_replay_results"
        try:
            return tuple(results), None
        except RECOVERABLE_RUNTIME_ERRORS:
            return (), "parent_replay_results_iteration_failed"
    except RECOVERABLE_RUNTIME_ERRORS:
        return (), "parent_replay_results_iteration_failed"


def _add_summary_count(totals: dict[str, object], summary: Mapping[str, object], key: str) -> None:
    try:
        value = replay_mapping_get(summary, key, 0)
        count = safe_summary_count(value)
        totals[key] += count
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure("suppressed_exception", suppressed_exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc


def _log_replay_totals(totals: Mapping[str, object]) -> None:
    try:
        counts = tuple(safe_summary_count(replay_mapping_get(totals, key, 0)) for key in _REPLAY_TOTAL_KEYS)
        if any(count != 0 for count in counts):
            logging.info(
                "parent model replay: checked=%s runtime=%s clean_checked=%s committed=%s promoted=%s errors=%s",
                *counts,
            )
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure("suppressed_exception", suppressed_exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc



__all__ = ("parent_replay_result_learning", "persist_parent_learning_from_results")
