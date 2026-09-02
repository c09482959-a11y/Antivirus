"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .constants import (
    MODEL_CONTRACT_RECORD_FIELDS,
    MODEL_FAILURE_RECORD_KEYS,
    MODEL_SIGNAL_SOURCE_FIELDS,
)
from .contract_sanitization import sanitize_contract_record
from .model_failure_sanitization import sanitize_model_failure_records
from .record_validation import invalid_contract_record_failure, invalid_model_failure_record_failure
from .safe_mapping import (
    is_explicit_empty_text,
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_keys,
    safe_str,
    model_evidence_child_path,
    model_evidence_index_path,
    model_evidence_is_container,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def direct_model_contract_records(record: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    out: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in MODEL_CONTRACT_RECORD_FIELDS:
        if not safe_mapping_contains(record, field):
            continue
        value = safe_mapping_get(record, field)
        if value is None or is_explicit_empty_text(value):
            continue
        contract_value, contract_unavailable, contract_failures = sanitize_contract_record(field, value)
        if contract_value is not None:
            out[field] = contract_value
        unavailable.update(contract_unavailable)
        failures.extend(contract_failures)
    return out, unavailable, tuple(failures)

def existing_model_contract_records(evidence: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    out: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in MODEL_CONTRACT_RECORD_FIELDS:
        if not safe_mapping_contains(evidence, field):
            continue
        value = safe_mapping_get(evidence, field)
        if value is None or is_explicit_empty_text(value):
            continue
        contract_value, contract_unavailable, contract_failures = sanitize_contract_record(field, value)
        if contract_value is not None:
            out[field] = contract_value
        unavailable.update(contract_unavailable)
        failures.extend(contract_failures)
    return out, unavailable, tuple(failures)

def nested_model_signal_contract_records(
    record: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    """Project contract records nested inside model signal containers.

    Model-owned metadata such as ``adaptive_learning`` may carry a contract
    record below the top level.  Publication must treat malformed probability
    fields in those nested contracts as degraded model evidence instead of
    dropping them when compacting final JSON.
    """
    out: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    seen_paths: set[str] = set()

    def visit(source_path: str, value: object) -> None:
        if model_evidence_is_mapping(value):
            keys, read_reason = safe_mapping_keys(value)
            if read_reason:
                unavailable[source_path] = read_reason
                failures.append(invalid_contract_record_failure(source_path, value, read_reason))
                return
            for raw_key in keys:
                key = safe_str(raw_key)
                item = safe_mapping_get(value, raw_key)
                child_path = model_evidence_child_path(source_path, key)
                if key in MODEL_CONTRACT_RECORD_FIELDS:
                    if child_path in seen_paths:
                        continue
                    seen_paths.add(child_path)
                    if item is None or is_explicit_empty_text(item):
                        continue
                    contract_value, contract_unavailable, contract_failures = sanitize_contract_record(
                        child_path,
                        item,
                    )
                    if contract_value is not None:
                        out.setdefault(key, contract_value)
                    unavailable.update(contract_unavailable)
                    failures.extend(contract_failures)
                    continue
                if model_evidence_is_container(item):
                    visit(child_path, item)
            return
        if model_evidence_is_sequence(value):
            for index, item in enumerate(value):
                if model_evidence_is_container(item):
                    visit(model_evidence_index_path(source_path, index), item)

    for field in MODEL_SIGNAL_SOURCE_FIELDS:
        if not safe_mapping_contains(record, field):
            continue
        value = safe_mapping_get(record, field)
        if model_evidence_is_container(value):
            visit(field, value)
    return out, unavailable, tuple(failures)

def has_replay_model_mismatch_evidence(evidence: Mapping[str, object]) -> bool:
    """Return whether replay comparison contract evidence reports a mismatch.

    Replay mismatches are output-affecting model evidence even when they are not
    represented as model-failure records.  Publication must keep final JSON and
    replay records required for them instead of only activating those flags for
    unavailable/failure records.
    """

    def visit(value: object) -> bool:
        if model_evidence_is_mapping(value):
            keys, read_reason = safe_mapping_keys(value)
            if read_reason:
                return False
            matched = safe_mapping_get(value, "matched")
            if matched is False:
                return True
            for key in keys:
                item = safe_mapping_get(value, key)
                if model_evidence_is_container(item) and visit(item):
                    return True
            return False
        if model_evidence_is_sequence(value):
            return any(visit(item) for item in value)
        return False

    for field in ("replay_model_comparison", "replay_model_comparison_record"):
        value = safe_mapping_get(evidence, field)
        if model_evidence_is_container(value) and visit(value):
            return True
    return False

def existing_model_contract_failure_records(
    evidence: Mapping[str, object],
) -> tuple[tuple[object, ...], dict[str, object], tuple[dict[str, object], ...]]:
    """Project model-failure evidence nested in existing contract records.

    Existing upstream ``model_evidence`` may already carry contract-shaped
    records such as ``model_feature_bundle`` or ``temporal_overlay_record``.
    Publication keeps those records, but their nested model-failure evidence must
    also reach the canonical ``model_evidence.model_failures`` collection so the
    final JSON/replay flags are activated by output-affecting failures.
    """
    records: list[object] = []
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []

    def visit(source_path: str, value: object) -> None:
        if model_evidence_is_mapping(value):
            keys, read_reason = safe_mapping_keys(value)
            if read_reason:
                unavailable[source_path] = read_reason
                failures.append(invalid_model_failure_record_failure(source_path, value, read_reason))
                return
            for failure_key in MODEL_FAILURE_RECORD_KEYS:
                if not safe_mapping_contains(value, failure_key):
                    continue
                failure_path = model_evidence_child_path(source_path, failure_key)
                field_records, field_unavailable, field_failures = sanitize_model_failure_records(
                    failure_path,
                    safe_mapping_get(value, failure_key),
                )
                records.extend(field_records)
                unavailable.update(field_unavailable)
                failures.extend(field_failures)
            for raw_key in keys:
                key = safe_str(raw_key)
                if key in MODEL_FAILURE_RECORD_KEYS:
                    continue
                item = safe_mapping_get(value, raw_key)
                if model_evidence_is_container(item):
                    child_path = model_evidence_child_path(source_path, key)
                    visit(child_path, item)
            return
        if model_evidence_is_sequence(value):
            for index, item in enumerate(value):
                if model_evidence_is_container(item):
                    visit(model_evidence_index_path(source_path, index), item)

    for field in MODEL_CONTRACT_RECORD_FIELDS:
        value = safe_mapping_get(evidence, field)
        if model_evidence_is_container(value):
            visit(model_evidence_child_path("model_evidence", field), value)
    return tuple(records), unavailable, tuple(failures)

__all__ = ('direct_model_contract_records', 'existing_model_contract_failure_records', 'existing_model_contract_records', 'has_replay_model_mismatch_evidence', 'nested_model_signal_contract_records')
