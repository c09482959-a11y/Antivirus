"""Import-light result-record constructors.

Owned by contracts so routing/scheduler/reporting do not depend on each other for
basic worker error/timeout records.
"""
from __future__ import annotations
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from pathlib import Path
import math
from typing import Mapping
from .path_identity import get_scan_extension
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_json_key,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_text,
)




PLR2004N70_0 = 70.0


def _is_explicit_empty_text(value: object) -> bool:
    """Return True only for a literal empty string without probing caller truthiness."""
    return type(value) is str and value == ''


def _is_missing_or_empty_text(value: object) -> bool:
    return value is None or _is_explicit_empty_text(value)


def _safe_strip_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_result_record_text",
        unsupported_reason="unsafe_result_record_text_value_rejected",
    )
    if reason:
        return ''
    return str.strip(text)


def _safe_text_present(value: object) -> bool:
    return _safe_strip_text(value) != ''


def _owned_mapping_snapshot(value: object) -> dict[object, object] | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    out: dict[object, object] = {}
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix="result_record_key")
        if key_reason:
            out[key_text] = {"unavailable_reason": key_reason}
            continue
        if key_text in out:
            key_text = key_text + "#" + int.__str__(index)
        out[key_text] = item
    return out


def _safe_mapping_text_items(
    value: object,
    *,
    prefix: str = "result_record_key",
) -> tuple[tuple[str, str, object], ...] | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    keyed_items: list[tuple[str, str, object]] = []
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix=prefix)
        keyed_items.append((key_text, key_reason, item))
    return tuple(keyed_items)


def _safe_mapping_has_text_key(value: object, key: str) -> bool:
    if type(key) is not str:
        return False
    keyed_items = _safe_mapping_text_items(value, prefix="result_record_lookup_key")
    if keyed_items is None:
        return False
    for key_text, key_reason, _item in keyed_items:
        if key_reason:
            continue
        if key_text == key:
            return True
    return False


def _safe_mapping_get(value: object, key: object, default: object = None) -> object:
    if type(key) is not str:
        return default
    keyed_items = _safe_mapping_text_items(value, prefix="result_record_lookup_key")
    if keyed_items is None:
        return default
    for key_text, key_reason, item_value in keyed_items:
        if key_reason:
            continue
        if key_text == key:
            return item_value
    return default


def _first_present_mapping_value(value: object, *keys: object, default: object = None) -> object:
    for key in keys:
        item = _safe_mapping_get(value, key, None)
        if item is None or _is_explicit_empty_text(item):
            continue
        return item
    return default


def _safe_contract_field_name(value: object) -> str:
    return _safe_strip_text(value).lower()


def _safe_contract_terminal_name(value: object) -> str:
    text = _safe_strip_text(value)
    return text.rsplit('.', 1)[-1]


def _is_owned_mapping_value(value: object) -> bool:
    return no_hook_mapping_items(value) is not None


def _mapping_like_type_status(value: object) -> tuple[bool, str]:
    try:
        mro = type.__getattribute__(type(value), "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return False, "mapping_type_mro_unavailable"
    if type(mro) is not tuple:
        return False, "mapping_type_mro_not_tuple"
    return MappingABC in mro, ""


def _is_mapping_like_type(value: object) -> bool:
    accepted, _reason = _mapping_like_type_status(value)
    return accepted


def _safe_context_field(context: str, field: object, separator: str = ".") -> str:
    field_text = _safe_strip_text(field)
    if not field_text:
        field_text = "unknown"
    return context + separator + field_text


def _safe_count(value: object) -> int:
    if value is None or _is_explicit_empty_text(value):
        return 0
    if type(value) is str:
        return 1 if str.strip(value) else 0
    if type(value) in (tuple, list, set, frozenset):
        return len(value)
    items = no_hook_mapping_items(value)
    if items is not None:
        return int(len(items) > 0)
    if type(value) is bool:
        return 1 if value else 0
    if type(value) is int:
        return 1 if value != 0 else 0
    if type(value) is float:
        return int(math.isfinite(value))
    return 1

def _safe_nonnegative_int_count(value: object) -> int:
    if value is None or _is_explicit_empty_text(value):
        return 0
    if type(value) is bool:
        return int(value)
    count, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason="unsafe_result_record_count_rejected",
        non_finite_reason="non_finite_result_record_count",
        allow_exact_text=True,
    )
    if reason:
        return 0
    return count


def _safe_bool_presence(value: object) -> bool:
    if value is None or _is_explicit_empty_text(value):
        return False
    if type(value) is bool:
        return value
    if type(value) in (int, float):
        return value != 0
    return _safe_count(value) > 0

INCOMPLETE_SCAN_TAGS = ("scanner_failure", "scanner_degraded", "scan_incomplete")
SCANNER_DEGRADED_TAGS = INCOMPLETE_SCAN_TAGS
MODEL_RESULT_EVIDENCE_KEYS = (
    'model_evidence',
    'feature_probabilities',
    'temporal_signals',
    'temporal_features',
    'markov_sequence_signals',
    'markov_features',
    'clustering_signals',
    'cluster_features',
    'clustering_features',
    'graph_signals',
    'graph_features',
    'model_context',
    'contextual_expected_behavior',
    'context_confidence_amplifier',
    'context_confidence',
    'contextual_confidence',
    'analytical_calibration',
    'score_metadata',
    'score_meta',
    'adaptive_score_metadata',
    'adaptive_score_meta',
    'calibrated_score_metadata',
    'calibrated_log_odds',
    'layered_detection',
    'layer_weights',
    'engine_context',
    'engine_confidence',
    'baseline_maturity',
    'profile_selection',
    'detection_profile_context',
    'feature_vector',
    'adaptive_learning',
    'adaptive_weights',
    'pre_rolling_weights',
    'rolling_learned_static',
    'bucket_vector',
    'model_failures',
    'model_failure',
    'model_failure_record',
    'model_feature_bundle',
    'model_snapshot',
    'model_evidence_record',
    'probability_record',
    'markov_probability_record',
    'temporal_overlay_record',
    'profile_evidence',
    'profile_evidence_record',
    'cluster_evidence',
    'cluster_evidence_record',
    'graph_evidence',
    'graph_evidence_record',
    'cold_start_record',
    'replay_model_comparison',
    'replay_model_comparison_record',
)


_MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS = (
    'score_metadata',
    'score_meta',
    'adaptive_score_metadata',
    'adaptive_score_meta',
    'calibrated_score_metadata',
    'calibrated_log_odds',
    'analytical_calibration',
    'model_context',
    'contextual_expected_behavior',
    'context_confidence_amplifier',
    'context_confidence',
    'contextual_confidence',
    'layered_detection',
    'adaptive_learning',
    'profile_selection',
    'detection_profile_context',
)


_MODEL_CONTRACT_RECORD_KEYS = (
    'model_feature_bundle',
    'model_snapshot',
    'model_evidence_record',
    'probability_record',
    'markov_probability_record',
    'temporal_overlay_record',
    'profile_evidence',
    'profile_evidence_record',
    'cluster_evidence',
    'cluster_evidence_record',
    'graph_evidence',
    'graph_evidence_record',
    'cold_start_record',
    'replay_model_comparison',
    'replay_model_comparison_record',
)
_MODEL_CONTRACT_SCALAR_PROBABILITY_FIELDS = (
    'probability',
    'stage_probability',
    'sequence_probability',
    'confidence',
)
_MODEL_CONTRACT_PROBABILITY_MAPPING_FIELDS = (
    'pair_probabilities',
    'feature_probabilities',
    'probabilities',
)
_MODEL_CONTRACT_PROBABILITY_FIELD_EXCLUSIONS = (
    'probability_ready',
    'probability_support',
    'probability_count',
    'probability_unavailable_reason',
)
_MODEL_CONTRACT_NONNEGATIVE_INTEGER_FIELDS = (
    'support',
    'count',
    'vocab',
)
_MODEL_CONTRACT_BOOLEAN_FLAG_FIELDS = (
    'ready',
    'probability_ready',
    'stage_probability_ready',
)
_MODEL_PROBABILITY_RECORD_REQUIRED_FIELDS = (
    'ready',
    'probability',
    'support',
    'count',
    'vocab',
    'smoothing',
    'reason',
    'model_version',
)
_MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS = (
    'smoothing',
    'model_version',
)
_MODEL_PROBABILITY_RECORD_KEYS = (
    'probability_record',
    'markov_probability_record',
)


_MODEL_FAILURE_RECORD_REQUIRED_FIELDS = (
    'model_name',
    'failure_type',
    'reason',
)
_MODEL_FAILURE_RECORD_KEYS = (
    'model_failure',
    'model_failure_record',
    'model_failures',
)


def _is_contract_scalar_probability_field(field_name: object) -> bool:
    name = _safe_contract_field_name(field_name)
    if not name:
        return False
    if name in _MODEL_CONTRACT_SCALAR_PROBABILITY_FIELDS:
        return True
    if name.endswith('_confidence') and not name.endswith('_confidence_amplifier'):
        return True
    if not name.endswith('_probability'):
        return False
    return name not in _MODEL_CONTRACT_PROBABILITY_FIELD_EXCLUSIONS


def _is_contract_probability_mapping_field(field_name: object) -> bool:
    name = _safe_contract_field_name(field_name)
    return name in _MODEL_CONTRACT_PROBABILITY_MAPPING_FIELDS or name.endswith('_probabilities')


def _is_contract_nonnegative_integer_field(field_name: object) -> bool:
    name = _safe_contract_field_name(field_name)
    return (
        name in _MODEL_CONTRACT_NONNEGATIVE_INTEGER_FIELDS
        or name.endswith(('_support', '_count', '_vocab'))
    )


def _is_contract_boolean_flag_field(field_name: object) -> bool:
    name = _safe_contract_field_name(field_name)
    return name in _MODEL_CONTRACT_BOOLEAN_FLAG_FIELDS or name.endswith('_ready')


def _is_contract_unavailable_reason_field(field_name: object) -> bool:
    return _safe_contract_field_name(field_name).endswith('_unavailable_reason')


def _contract_record_terminal_name(field_name: object) -> str:
    return _safe_contract_terminal_name(field_name)


def _required_contract_record_fields(field_name: object) -> tuple[str, ...]:
    terminal = _contract_record_terminal_name(field_name)
    if terminal in _MODEL_PROBABILITY_RECORD_KEYS:
        return _MODEL_PROBABILITY_RECORD_REQUIRED_FIELDS
    return ()


def _validate_required_contract_record_fields(field_name: object, value: Mapping[str, object], *, context: str) -> None:
    for required in _required_contract_record_fields(field_name):
        if _safe_mapping_has_text_key(value, required) or _safe_mapping_has_text_key(
            value,
            required + '_unavailable_reason',
        ):
            continue
        raise ValueError(context + ': model contract record missing ' + required)


def _validate_probability_record_state(field_name: object, value: Mapping[str, object], *, context: str) -> None:
    if _contract_record_terminal_name(field_name) not in _MODEL_PROBABILITY_RECORD_KEYS:
        return
    for text_field in _MODEL_PROBABILITY_RECORD_REQUIRED_TEXT_FIELDS:
        if not _safe_mapping_has_text_key(value, text_field) or _safe_mapping_has_text_key(
            value,
            text_field + '_unavailable_reason',
        ):
            continue
        text_value = _safe_mapping_get(value, text_field)
        if not (type(text_value) is str and str.strip(text_value)):
            raise ValueError(context + ': probability record ' + text_field + ' must be non-empty text')
    if _safe_mapping_has_text_key(value, 'reason') and not _safe_mapping_has_text_key(
        value,
        'reason_unavailable_reason',
    ):
        reason_value = _safe_mapping_get(value, 'reason')
        if reason_value is not None and not (type(reason_value) is str and str.strip(reason_value)):
            raise ValueError(context + ': probability record reason must be non-empty text or null')
    for identity_field in ('source', 'target'):
        if not _safe_mapping_has_text_key(value, identity_field) or _safe_mapping_has_text_key(
            value,
            identity_field + '_unavailable_reason',
        ):
            continue
        identity_value = _safe_mapping_get(value, identity_field)
        if identity_value is not None and not (type(identity_value) is str and str.strip(identity_value)):
            raise ValueError(context + ': probability record ' + identity_field + ' must be non-empty text or null')
    if _safe_mapping_has_text_key(value, 'flow') and not _safe_mapping_has_text_key(value, 'flow_unavailable_reason'):
        flow_value = _safe_mapping_get(value, 'flow')
        if flow_value is None:
            pass
        elif type(flow_value) in (str, bytes) or _is_owned_mapping_value(flow_value):
            raise ValueError(context + ': probability record flow must be a sequence of non-empty text')
        elif type(flow_value) in (list, tuple):
            for index, item in enumerate(flow_value):
                if not (type(item) is str and str.strip(item)):
                    raise ValueError(
                        context + ': probability record flow[' + int.__str__(index) + '] must be non-empty text'
                    )
        else:
            raise ValueError(context + ': probability record flow must be a sequence of non-empty text')
    if not _safe_mapping_has_text_key(value, 'ready') or _safe_mapping_has_text_key(value, 'ready_unavailable_reason'):
        return
    ready = _safe_mapping_get(value, 'ready')
    if type(ready) is not bool:
        return
    probability_missing = not _safe_mapping_has_text_key(value, 'probability') or _safe_mapping_get(value, 'probability') is None
    if ready and probability_missing and not _safe_mapping_has_text_key(value, 'probability_unavailable_reason'):
        raise ValueError(context + ': ready probability record missing probability')
    if not ready and _safe_mapping_get(value, 'probability') is not None:
        raise ValueError(context + ': not-ready probability record cannot carry probability')
    reason_missing = not _safe_strip_text(_safe_mapping_get(value, 'reason'))
    if not ready and reason_missing and not _safe_mapping_has_text_key(value, 'reason_unavailable_reason'):
        raise ValueError(context + ': not-ready probability record missing reason')


def _assert_boolean_flag(value: object, *, context: str) -> None:
    if value is None:
        return
    if type(value) is not bool:
        raise ValueError(context + ': readiness flag must be boolean or null')


def _assert_unavailable_reason(value: object, *, context: str) -> None:
    if not (type(value) is str and str.strip(value)):
        raise ValueError(context + ': unavailable reason must be non-empty text')


def _assert_nonnegative_integer_metric(value: object, *, context: str) -> None:
    if value is None:
        return
    if type(value) not in (int, float) or type(value) is bool:
        raise ValueError(context + ': count/support metric must be numeric or null')
    metric = float(value)
    if not math.isfinite(metric):
        raise ValueError(context + ': count/support metric must be finite')
    if metric < 0.0:
        raise ValueError(context + ': count/support metric must be non-negative')
    if not metric.is_integer():
        raise ValueError(context + ': count/support metric must be an integer')


def _assert_probability_metric(value: object, *, context: str) -> None:
    if value is None:
        return
    if type(value) not in (int, float) or type(value) is bool:
        raise ValueError(context + ': probability must be numeric or null')
    probability = float(value)
    if not math.isfinite(probability):
        raise ValueError(context + ': probability must be finite')
    if probability < 0.0 or probability > 1.0:
        raise ValueError(context + ': probability out of bounds')


def _assert_probability_mapping(value: object, *, context: str) -> None:
    if value is None:
        return
    if not _is_owned_mapping_value(value):
        raise ValueError(context + ': probability mapping must be an object or null')


def _validate_model_contract_metric_bounds(value: object, *, context: str) -> None:
    keyed_items = _safe_mapping_text_items(value, prefix="model_contract_metric_key")
    if keyed_items is not None:
        for key, key_reason, item in keyed_items:
            metric_context = _safe_context_field(context, key)
            if key_reason:
                continue
            if _is_contract_unavailable_reason_field(key):
                _assert_unavailable_reason(item, context=metric_context)
                continue
            if _is_contract_scalar_probability_field(key):
                _assert_probability_metric(item, context=metric_context)
                continue
            if _is_contract_boolean_flag_field(key):
                _assert_boolean_flag(item, context=metric_context)
                continue
            if _is_contract_nonnegative_integer_field(key):
                _assert_nonnegative_integer_metric(item, context=metric_context)
                continue
            if _is_contract_probability_mapping_field(key):
                _assert_probability_mapping(item, context=metric_context)
                probability_items = _safe_mapping_text_items(item, prefix="model_contract_probability_key")
                if probability_items is not None:
                    for probability_key, probability_key_reason, probability_value in probability_items:
                        if probability_key_reason:
                            continue
                        _assert_probability_metric(
                            probability_value,
                            context=_safe_context_field(metric_context, probability_key),
                        )
                continue
            _validate_model_contract_metric_bounds(item, context=metric_context)
        return
    if type(value) in (list, tuple):
        for index, item in enumerate(value):
            _validate_model_contract_metric_bounds(item, context=context + '[' + int.__str__(index) + ']')


def _validate_probability_record_bounds(record: Mapping[str, object], *, context: str) -> None:
    for key in _MODEL_CONTRACT_RECORD_KEYS:
        if not _safe_mapping_has_text_key(record, key):
            continue
        value = _safe_mapping_get(record, key)
        if _is_missing_or_empty_text(value):
            continue
        if not _is_owned_mapping_value(value):
            raise ValueError(context + ':' + key + ': model contract record must be an object')
        contract_context = context + ':' + key
        _validate_required_contract_record_fields(key, value, context=contract_context)
        _validate_model_contract_metric_bounds(value, context=contract_context)
        _validate_probability_record_state(key, value, context=contract_context)



def _validate_single_model_failure_record(value: object, *, context: str) -> None:
    if not _is_owned_mapping_value(value):
        raise ValueError(context + ': model failure record must be an object')
    for required in _MODEL_FAILURE_RECORD_REQUIRED_FIELDS:
        if not _safe_strip_text(_safe_mapping_get(value, required)):
            raise ValueError(context + ': model failure record missing ' + required)


def _validate_model_failure_record_value(value: object, *, context: str) -> None:
    if _is_missing_or_empty_text(value):
        return
    if _is_owned_mapping_value(value):
        _validate_single_model_failure_record(value, context=context)
        return
    if type(value) in (list, tuple):
        for index, item in enumerate(value):
            _validate_single_model_failure_record(item, context=context + '[' + int.__str__(index) + ']')
        return
    raise ValueError(context + ': model failure record must be an object')


def _validate_nested_model_failure_records(value: object, *, context: str, seen: set[int] | None = None) -> None:
    """Validate model-failure aliases anywhere inside model-owned evidence.

    Final JSON publication can sanitize malformed nested failure records into
    degraded evidence, but source/result contract validation must not accept a
    malformed ``model_failure``/``model_failure_record``/``model_failures`` value
    as if it were valid model evidence.
    """
    if seen is None:
        seen = set()
    keyed_items = _safe_mapping_text_items(value, prefix="model_failure_key")
    if keyed_items is not None:
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for name, name_reason, item in keyed_items:
            if name_reason:
                continue
            child_context = _safe_context_field(context, name)
            if name in _MODEL_FAILURE_RECORD_KEYS:
                _validate_model_failure_record_value(item, context=child_context)
                continue
            if _is_owned_mapping_value(item) or type(item) in (list, tuple):
                _validate_nested_model_failure_records(item, context=child_context, seen=seen)
        return
    if type(value) in (list, tuple):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for index, item in enumerate(value):
            if _is_owned_mapping_value(item) or type(item) in (list, tuple):
                _validate_nested_model_failure_records(item, context=context + '[' + int.__str__(index) + ']', seen=seen)


def _validate_nested_model_contract_records(record: Mapping[str, object], *, context: str) -> None:
    for key in _MODEL_CONTRACT_RECORD_KEYS:
        if not _safe_mapping_has_text_key(record, key):
            continue
        value = _safe_mapping_get(record, key)
        if _is_missing_or_empty_text(value):
            continue
        if not _is_owned_mapping_value(value):
            raise ValueError(context + ':' + key + ': model contract record must be an object')
        contract_context = context + ':' + key
        _validate_required_contract_record_fields(key, value, context=contract_context)
        _validate_model_contract_metric_bounds(value, context=contract_context)
        _validate_probability_record_state(key, value, context=contract_context)
        _validate_nested_model_failure_records(value, context=contract_context)


def _validate_nested_model_signal_failure_records(record: Mapping[str, object], *, context: str) -> None:
    for key in MODEL_RESULT_EVIDENCE_KEYS:
        if (
            not _safe_mapping_has_text_key(record, key)
            or key in _MODEL_FAILURE_RECORD_KEYS
            or key == 'model_evidence'
        ):
            continue
        value = _safe_mapping_get(record, key)
        if _is_owned_mapping_value(value) or type(value) in (list, tuple):
            _validate_nested_model_failure_records(value, context=context + ':' + key)


def _validate_nested_model_signal_contract_records(
    value: object,
    *,
    context: str,
    seen: set[int] | None = None,
) -> None:
    """Validate contract-shaped records nested inside model signal containers.

    Phase-1 publication can project malformed direct/upstream contract records
    into explicit degraded model evidence, but the source/result boundary must
    not accept an out-of-range nested contract metric merely because it is
    wrapped inside adaptive/profile/layered model metadata.
    """
    if seen is None:
        seen = set()
    keyed_items = _safe_mapping_text_items(value, prefix="model_signal_contract_key")
    if keyed_items is not None:
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for key, key_reason, item in keyed_items:
            if key_reason:
                continue
            child_context = _safe_context_field(context, key)
            if key in _MODEL_CONTRACT_RECORD_KEYS:
                if item is None or item == '':
                    continue
                if not _is_owned_mapping_value(item):
                    raise ValueError(child_context + ': model contract record must be an object')
                _validate_required_contract_record_fields(key, item, context=child_context)
                _validate_model_contract_metric_bounds(item, context=child_context)
                _validate_probability_record_state(key, item, context=child_context)
                _validate_nested_model_failure_records(item, context=child_context, seen=seen)
                continue
            if _is_owned_mapping_value(item) or type(item) in (list, tuple):
                _validate_nested_model_signal_contract_records(item, context=child_context, seen=seen)
        return
    if type(value) in (list, tuple):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for index, item in enumerate(value):
            if _is_owned_mapping_value(item) or type(item) in (list, tuple):
                _validate_nested_model_signal_contract_records(
                    item,
                    context=context + '[' + int.__str__(index) + ']',
                    seen=seen,
                )


def _validate_model_signal_contract_records(record: Mapping[str, object], *, context: str) -> None:
    for key in MODEL_RESULT_EVIDENCE_KEYS:
        if not _safe_mapping_has_text_key(record, key) or key == 'model_evidence':
            continue
        value = _safe_mapping_get(record, key)
        if _is_owned_mapping_value(value) or type(value) in (list, tuple):
            _validate_nested_model_signal_contract_records(value, context=context + ':' + key)


def _validate_model_failure_records(record: Mapping[str, object], *, context: str) -> None:
    for key in _MODEL_FAILURE_RECORD_KEYS:
        if _safe_mapping_has_text_key(record, key):
            _validate_model_failure_record_value(_safe_mapping_get(record, key), context=context + ':' + key)
    _validate_nested_model_contract_records(record, context=context)
    _validate_nested_model_signal_failure_records(record, context=context)
    model_evidence = _safe_mapping_get(record, 'model_evidence')
    if _is_missing_or_empty_text(model_evidence):
        return
    if not _is_owned_mapping_value(model_evidence):
        raise ValueError(context + ':model_evidence: model evidence record must be an object')
    for key in _MODEL_FAILURE_RECORD_KEYS:
        if _safe_mapping_has_text_key(model_evidence, key):
            _validate_model_failure_record_value(
                _safe_mapping_get(model_evidence, key),
                context=context + ':model_evidence.' + key,
            )
    _validate_nested_model_contract_records(model_evidence, context=context + ':model_evidence')
    _validate_nested_model_signal_failure_records(model_evidence, context=context + ':model_evidence')
    _validate_model_signal_contract_records(model_evidence, context=context + ':model_evidence')


def _iter_feature_probability_container_values(record: Mapping[str, object]) -> tuple[tuple[str, object], ...]:
    containers: list[tuple[str, object]] = [('feature_probabilities', _safe_mapping_get(record, 'feature_probabilities'))]
    for metadata_key in _MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS:
        metadata = _safe_mapping_get(record, metadata_key)
        if _is_owned_mapping_value(metadata):
            containers.append((metadata_key + '.feature_probabilities', _safe_mapping_get(metadata, 'feature_probabilities')))
    model_evidence = _safe_mapping_get(record, 'model_evidence')
    if _is_owned_mapping_value(model_evidence):
        containers.append(('model_evidence.feature_probabilities', _safe_mapping_get(model_evidence, 'feature_probabilities')))
    explanation = _safe_mapping_get(record, 'explanation')
    if _is_owned_mapping_value(explanation):
        containers.append(('explanation.feature_probabilities', _safe_mapping_get(explanation, 'feature_probabilities')))
    return tuple(containers)


def _validate_feature_probability_record_shapes(record: Mapping[str, object], *, context: str) -> None:
    for source_field, feature_probabilities in _iter_feature_probability_container_values(record):
        if (feature_probabilities is not None and not _is_explicit_empty_text(feature_probabilities)
                and not _is_owned_mapping_value(feature_probabilities)):
            raise ValueError(context + ':' + source_field + ': feature probabilities record must be an object')


def _validate_feature_probability_unavailable_reason_values(value: object, *, context: str) -> None:
    if _is_missing_or_empty_text(value):
        return
    keyed_items = _safe_mapping_text_items(value, prefix="feature_unavailable_reason_key")
    if keyed_items is None:
        return
    for name, name_reason, item in keyed_items:
        if name_reason:
            continue
        if not name.endswith('_unavailable_reason'):
            continue
        reason_subject = name.removesuffix('_unavailable_reason').strip()
        if not reason_subject:
            raise ValueError(context + '.' + name + ': unavailable reason model key missing')
        if item is None:
            continue
        if not (type(item) is str and str.strip(item)):
            raise ValueError(context + '.' + name + ': unavailable reason must be non-empty text')


def _validate_feature_probability_unavailable_reason_shapes(record: Mapping[str, object], *, context: str) -> None:
    for source_field, feature_probabilities in _iter_feature_probability_container_values(record):
        _validate_feature_probability_unavailable_reason_values(
            feature_probabilities,
            context=context + ':' + source_field,
        )


def _validate_feature_probability_failure_record_shapes(record: Mapping[str, object], *, context: str) -> None:
    for source_field, feature_probabilities in _iter_feature_probability_container_values(record):
        if _is_missing_or_empty_text(feature_probabilities) or not _is_owned_mapping_value(feature_probabilities):
            continue
        for failure_key in _MODEL_FAILURE_RECORD_KEYS:
            if not _safe_mapping_has_text_key(feature_probabilities, failure_key):
                continue
            _validate_model_failure_record_value(
                _safe_mapping_get(feature_probabilities, failure_key),
                context=context + ':' + source_field + '.' + failure_key,
            )


def _validate_feature_probability_metric_bounds(record: Mapping[str, object], *, context: str) -> None:
    for source_field, feature_probabilities in _iter_feature_probability_container_values(record):
        if _is_missing_or_empty_text(feature_probabilities) or not _is_owned_mapping_value(feature_probabilities):
            continue
        probability_items = _safe_mapping_text_items(feature_probabilities, prefix='feature_probability_key')
        if probability_items is None:
            raise ValueError(context + ':' + source_field + ': feature probabilities record is unreadable')
        for key, key_reason, probability_value in probability_items:
            if key_reason == 'blank_json_mapping_key':
                raise ValueError(context + ':' + source_field + ': feature probability key missing')
            if key_reason:
                continue
            if key in _MODEL_FAILURE_RECORD_KEYS or key.endswith('_unavailable_reason'):
                continue
            _assert_probability_metric(
                probability_value,
                context=context + ':' + source_field + '.' + key,
            )


def _validate_model_evidence_unavailable_reason_shapes(record: Mapping[str, object], *, context: str) -> None:
    model_evidence = _safe_mapping_get(record, 'model_evidence')
    if not _is_owned_mapping_value(model_evidence):
        return
    unavailable_reasons = _safe_mapping_get(model_evidence, 'unavailable_reasons')
    if _is_missing_or_empty_text(unavailable_reasons):
        return
    if not _is_owned_mapping_value(unavailable_reasons):
        raise ValueError(
            context + ':model_evidence.unavailable_reasons: unavailable reasons record must be an object'
        )
    reason_items = _safe_mapping_text_items(unavailable_reasons, prefix='model_unavailable_reason_key')
    if reason_items is None:
        raise ValueError(context + ':model_evidence.unavailable_reasons: unavailable reasons record is unreadable')
    for reason_key, key_reason, value in reason_items:
        if key_reason == 'blank_json_mapping_key':
            raise ValueError(
                context + ':model_evidence.unavailable_reasons: unavailable reason key missing'
            )
        if not (type(value) is str and str.strip(value)):
            raise ValueError(
                context + ':model_evidence.unavailable_reasons.' + reason_key + ': unavailable reason must be non-empty text'
            )


@dataclass(frozen=True, slots=True)
class ResultIdentitySnapshot:
    """Immutable file identity view used at persistence boundaries."""

    file: str
    path: str
    input_file_path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _safe_strip_text(self.file))
        object.__setattr__(self, "path", _safe_strip_text(self.path))
        object.__setattr__(self, "input_file_path", _safe_strip_text(self.input_file_path))

    @classmethod
    def from_record(cls, record: Mapping[str, object]) -> "ResultIdentitySnapshot":
        return cls(
            file=_safe_strip_text(_safe_mapping_get(record, 'file')),
            path=_safe_strip_text(_safe_mapping_get(record, 'path')),
            input_file_path=_safe_strip_text(_safe_mapping_get(record, 'input_file_path')),
        )

    def present_values(self) -> tuple[str, ...]:
        return tuple(v for v in (self.file, self.path, self.input_file_path) if v)

    def normalized_values(self) -> tuple[str, ...]:
        return tuple(v.replace('\\', '/').rstrip('/') for v in self.present_values())

    def validate_consistent(self, *, context: str) -> bool:
        values = self.normalized_values()
        if not values:
            raise ValueError(context + ': result record missing file identity')
        if len(set(values)) > 1:
            raise ValueError(context + ': conflicting file identity fields')
        return True


@dataclass(frozen=True, slots=True)
class ResultEvidenceSnapshot:
    """Immutable forensic evidence summary for a result record.

    This is a validation structure, not a second result representation.  It is
    built at persistence/cache boundaries to ensure high-risk results are never
    written without explicit evidence and that invalid records fail loudly.
    """

    verdict: str
    score: float
    tags: tuple[str, ...]
    chains: tuple[str, ...]
    yara_count: int
    decoded_count: int
    model_evidence_count: int
    error_present: bool
    explanation_present: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", _safe_strip_text(self.verdict).lower())
        score, _score_reason = no_hook_finite_float(self.score, default=0.0, allow_exact_text=True)
        object.__setattr__(self, "score", score)
        object.__setattr__(self, "tags", tuple(_normalize_tag_list(self.tags or ())))
        object.__setattr__(self, "chains", tuple(_normalize_tag_list(self.chains or ())))
        object.__setattr__(self, "yara_count", _safe_nonnegative_int_count(self.yara_count))
        object.__setattr__(self, "decoded_count", _safe_nonnegative_int_count(self.decoded_count))
        object.__setattr__(self, "model_evidence_count", _safe_nonnegative_int_count(self.model_evidence_count))
        object.__setattr__(self, "error_present", _safe_bool_presence(self.error_present))
        object.__setattr__(self, "explanation_present", _safe_bool_presence(self.explanation_present))

    @classmethod
    def from_record(cls, record: Mapping[str, object]) -> "ResultEvidenceSnapshot":
        tags = tuple(_normalize_tag_list(_first_present_mapping_value(record, 'tags', 'suspicious_tags', default=())))
        chains_raw = _first_present_mapping_value(record, 'chains', 'attack_chains', 'chain_hits', default=())
        chains = tuple(_normalize_tag_list(chains_raw))
        score, _score_reason = no_hook_finite_float(_safe_mapping_get(record, 'score'), default=0.0, allow_exact_text=True)
        decoded = _first_present_mapping_value(record, 'decoded_evidence_snippets', 'decoded_payloads', 'decode_records', default=())
        yara = _first_present_mapping_value(record, 'yara_hits', 'yara_signals', default=())
        explanation = _safe_mapping_get(record, 'explanation')
        model_evidence_count = _evidence_item_count(record, (
            *MODEL_RESULT_EVIDENCE_KEYS,
            'entropy_signals',
            'archive_container_signals',
            'fingerprint_evidence',
            'engine_routing_evidence',
            'sniffed_embedded_types',
        ))
        return cls(
            verdict=(_safe_strip_text(_first_present_mapping_value(record, 'verdict', 'classification', 'class', default=''))).lower(),
            score=score,
            tags=tags,
            chains=chains,
            yara_count=_safe_count(yara),
            decoded_count=_safe_count(decoded),
            model_evidence_count=model_evidence_count,
            error_present=_safe_count(_safe_mapping_get(record, 'error')) > 0 or _safe_count(_safe_mapping_get(record, 'errors')) > 0 or _safe_count(_safe_mapping_get(record, 'crash_traceback')) > 0 or _safe_mapping_get(record, 'timed_out') is True,
            explanation_present=_safe_count(explanation) > 0,
        )

    @property
    def requires_evidence(self) -> bool:
        return self.verdict in {'malicious', 'high', 'high_confidence', 'suspicious_high'} or self.score >= PLR2004N70_0

    @property
    def has_evidence(self) -> bool:
        return (
            len(self.tags) > 0
            or len(self.chains) > 0
            or self.yara_count > 0
            or self.decoded_count > 0
            or self.model_evidence_count > 0
            or self.error_present is True
            or self.explanation_present is True
        )



@dataclass(frozen=True, slots=True)
class ResultRecordCollectionSnapshot:
    """Immutable durable-result collection view used at JSON boundaries.

    This is not a replacement result format. It is a validation snapshot that
    proves replay/result JSON does not contain duplicate durable file records
    before the payload is persisted or accepted on reload.
    """

    identities: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "identities", tuple(_safe_strip_text(identity) for identity in (self.identities or ())))

    @classmethod
    def from_payload(cls, payload: Mapping[str, object], *, context: str = 'result_collection') -> "ResultRecordCollectionSnapshot":
        records = _safe_mapping_get(payload, 'results') if _is_owned_mapping_value(payload) else None
        if records is None:
            return cls(())
        record_items = no_hook_mapping_items(records)
        if record_items is not None:
            iterable = tuple(item for _key, item in record_items)
        elif type(records) in (list, tuple):
            iterable = tuple(records)
        else:
            raise ValueError(context + ': results must be an object or array')
        identities: list[str] = []
        seen: set[str] = set()
        for index, record in enumerate(iterable):
            if not _is_owned_mapping_value(record):
                raise ValueError(context + ': result record at index ' + int.__str__(index) + ' must be an object')
            validate_result_record_invariants(record, context=context + ':results[' + int.__str__(index) + ']')
            identity_values = ResultIdentitySnapshot.from_record(record).normalized_values()
            identity = identity_values[0] if identity_values else ''
            if not identity:
                raise ValueError(context + ': result record at index ' + int.__str__(index) + ' missing file identity')
            key = identity.lower()
            if key in seen:
                raise ValueError(context + ': duplicate result record for ' + identity)
            seen.add(key)
            identities.append(identity)
        return cls(tuple(identities))


def validate_result_collection_invariants(payload: object, *, context: str = 'result_collection') -> bool:
    if _owned_mapping_snapshot(payload) is None:
        raise ValueError(context + ': result collection must be an owned object')
    ResultRecordCollectionSnapshot.from_payload(payload, context=context)
    return True

@dataclass(frozen=True, slots=True)
class EvidenceObjectSnapshot:
    """Immutable shape check for JSON-visible evidence objects.

    Evidence may be emitted by several scanners, but persistence accepts only
    explicit non-empty scalar/list/dict evidence. Empty containers, object()
    instances, and blank strings are malformed because they make high-risk
    records look evidenced while carrying no forensic content.
    """

    key: str
    count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _safe_strip_text(self.key))
        object.__setattr__(self, "count", _safe_nonnegative_int_count(self.count))

    @classmethod
    def from_value(cls, key: str, value: object, *, context: str = 'evidence') -> "EvidenceObjectSnapshot":
        name = _safe_strip_text(key)
        if not name:
            raise ValueError(context + ': evidence key missing')
        count = _validated_evidence_count(value, context=context + ':' + name)
        return cls(name, count)


def _validated_evidence_count(value: object, *, context: str) -> int:
    if _is_missing_or_empty_text(value):
        return 0
    if type(value) is str:
        return 1 if str.strip(value) else 0
    items = no_hook_mapping_items(value)
    if items is not None:
        if len(items) == 0:
            return 0
        total = 0
        for index, (inner_key, inner_value) in enumerate(items):
            key_text, key_reason = no_hook_json_key(inner_key, index, prefix='evidence_object_key')
            if key_reason == 'blank_json_mapping_key':
                raise ValueError(context + ': evidence object contains blank key')
            if key_reason:
                continue
            total += _validated_evidence_count(inner_value, context=context + '.' + key_text)
        return 1 if total > 0 else 0
    if type(value) in (list, tuple, set, frozenset):
        total = 0
        for index, item in enumerate(value):
            total += _validated_evidence_count(item, context=context + '[' + int.__str__(index) + ']')
        return total
    if type(value) is bool:
        return 1
    if type(value) is int:
        return 1
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(context + ': evidence object contains non-finite float')
        return 1
    if _is_mapping_like_type(value):
        raise ValueError(context + ': evidence object contains unsupported mapping')
    raise ValueError(context + ': evidence object contains non-json value')


def validate_evidence_object_invariants(record: Mapping[str, object], *, context: str = 'result_record') -> bool:
    evidence_keys = (
        'decoded_evidence_snippets', 'decoded_payloads', 'decode_records',
        'yara_hits', 'yara_signals', 'temporal_signals', 'markov_sequence_signals',
        'clustering_signals', 'graph_signals', 'entropy_signals',
        *MODEL_RESULT_EVIDENCE_KEYS,
        'archive_container_signals', 'fingerprint_evidence', 'engine_routing_evidence',
        'sniffed_embedded_types', 'evidence', 'evidence_details',
    )
    for key in evidence_keys:
        if _safe_mapping_has_text_key(record, key):
            EvidenceObjectSnapshot.from_value(key, _safe_mapping_get(record, key), context=context)
    _validate_probability_record_bounds(record, context=context)
    _validate_model_signal_contract_records(record, context=context)
    _validate_model_failure_records(record, context=context)
    _validate_feature_probability_record_shapes(record, context=context)
    _validate_feature_probability_unavailable_reason_shapes(record, context=context)
    _validate_feature_probability_failure_record_shapes(record, context=context)
    _validate_feature_probability_metric_bounds(record, context=context)
    _validate_model_evidence_unavailable_reason_shapes(record, context=context)
    return True


def _evidence_item_count(record: Mapping[str, object], keys: tuple[str, ...]) -> int:
    total = 0
    for key in keys:
        value = _safe_mapping_get(record, key)
        if _is_missing_or_empty_text(value):
            continue
        try:
            total += _validated_evidence_count(value, context='result_evidence:' + key)
        except ValueError:
            continue
    return total


def validate_result_record_invariants(record: object, *, context: str = 'result_record') -> bool:
    """Hard forensic invariant validation for durable result records.

    Normalization may mark incomplete results as degraded, but persistence and
    queue boundaries must not accept impossible high/malicious records without
    evidence, records without file identity, or records without a verdict.
    """
    owned_record = _owned_mapping_snapshot(record)
    if owned_record is None:
        raise ValueError(context + ': result record must be an owned object')
    record = owned_record
    ResultIdentitySnapshot.from_record(record).validate_consistent(context=context)
    validate_evidence_object_invariants(record, context=context)
    raw_tags = _first_present_mapping_value(record, 'tags', 'suspicious_tags', default=())
    if type(raw_tags) in (list, tuple):
        raw_keys = [_safe_strip_text(t).lower() for t in raw_tags if _safe_strip_text(t)]
        if len(raw_keys) != len(tuple(dict.fromkeys(raw_keys))):
            raise ValueError(context + ': duplicate tags violate deterministic ordering')
    raw_chains = _first_present_mapping_value(record, 'chains', 'attack_chains', 'chain_hits', default=())
    if type(raw_chains) in (list, tuple):
        raw_chain_keys = [_safe_strip_text(c).lower() for c in raw_chains if _safe_strip_text(c)]
        if len(raw_chain_keys) != len(tuple(dict.fromkeys(raw_chain_keys))):
            raise ValueError(context + ': duplicate chains violate deterministic ordering')
    snapshot = ResultEvidenceSnapshot.from_record(record)
    if not snapshot.verdict:
        raise ValueError(context + ': result record missing verdict/classification')
    if snapshot.requires_evidence and not snapshot.has_evidence:
        raise ValueError(context + ': high-risk result missing forensic evidence')
    if len(snapshot.tags) != len(tuple(dict.fromkeys(t.lower() for t in snapshot.tags))):
        raise ValueError(context + ': duplicate tags violate deterministic ordering')
    if len(snapshot.chains) != len(tuple(dict.fromkeys(c.lower() for c in snapshot.chains))):
        raise ValueError(context + ': duplicate chains violate deterministic ordering')
    return True


_VOLATILE_REPLAY_FIELDS = frozenset({
    'timestamp', 'created_at', 'updated_at', 'duration', 'duration_seconds',
    'elapsed', 'elapsed_seconds', 'pid', 'process_id', 'worker_pid', 'worker_id',
    'started_at', 'finished_at', 'scan_started_at', 'scan_finished_at',
})


@dataclass(frozen=True, slots=True)
class ReplayComparableResultSnapshot:
    """Immutable result view for deterministic replay comparison.

    Volatile runtime fields are excluded, but forensic routing, verdict, tags,
    chains, evidence counters, and JSON-visible identity are retained.
    """

    canonical: tuple[tuple[str, object], ...]

    def __post_init__(self) -> None:
        """Freeze direct-constructor replay comparison payloads."""
        canonical_items = []
        for index, pair in enumerate(self.canonical or ()):  # direct construction boundary
            if not (type(pair) is tuple and len(pair) == 2):
                canonical_items.append(("invalid_replay_canonical_pair_" + int.__str__(index), _freeze_json_value(pair)))
                continue
            key, value = pair
            key_text, key_reason = no_hook_json_key(key, index, prefix="replay_canonical_key")
            canonical_items.append((key_text, _freeze_json_value(value) if not key_reason else {"unavailable_reason": key_reason}))
        object.__setattr__(self, "canonical", tuple(canonical_items))

    @classmethod
    def from_record(cls, record: Mapping[str, object], *, context: str = 'replay_result') -> "ReplayComparableResultSnapshot":
        validate_result_record_invariants(record, context=context)
        canonical_items: list[tuple[str, object]] = []
        record_items = no_hook_mapping_items(record) or ()
        keyed_record_items = []
        for index, (key, value) in enumerate(record_items):
            key_text, key_reason = no_hook_json_key(key, index, prefix="replay_record_key")
            keyed_record_items.append((key_text, index, key_reason, value))
        for normalized_key, _index, key_reason, raw_value in sorted(keyed_record_items, key=lambda row: (row[0], row[1])):
            value = raw_value
            if key_reason:
                canonical_items.append((normalized_key, {"unavailable_reason": key_reason}))
                continue
            if normalized_key.lower() in _VOLATILE_REPLAY_FIELDS:
                continue
            if normalized_key in {'tags', 'suspicious_tags', 'chains', 'attack_chains', 'chain_hits'}:
                value = tuple(_normalize_tag_list(value))
            canonical_items.append((normalized_key, _freeze_json_value(value)))
        return cls(tuple(canonical_items))

    def digest_payload(self) -> dict[str, object]:
        return {key: _thaw_json_value(value) for key, value in self.canonical}


def _freeze_json_value(value: object) -> object:
    materialized = no_hook_materialize(value, reason_prefix="result_record_replay_json")
    if type(materialized) is dict:
        materialized_items = no_hook_mapping_items(materialized) or ()
        return tuple((key, _freeze_json_value(item)) for key, item in sorted(materialized_items, key=lambda row: row[0]))
    if type(materialized) is list:
        return tuple(_freeze_json_value(item) for item in materialized)
    return materialized


def _thaw_json_value(value: object) -> object:
    if type(value) is tuple:
        if all(type(item) is tuple and len(item) == 2 and type(item[0]) is str for item in value):
            return {key: _thaw_json_value(inner) for key, inner in value}
        return [_thaw_json_value(item) for item in value]
    return value


def validate_replay_equivalent(left: Mapping[str, object], right: Mapping[str, object], *, context: str = 'replay_result') -> bool:
    if ReplayComparableResultSnapshot.from_record(left, context=context + ':left') != ReplayComparableResultSnapshot.from_record(right, context=context + ':right'):
        raise ValueError(context + ': deterministic replay mismatch')
    return True

def scanner_degraded_tags(*values: object) -> list[str]:
    """Return existing tags plus the canonical degraded-scan markers.

    Scanner/helper collectors use this when an input cannot be read, a helper
    crashes, or raw chunks are missing.  It keeps fail-closed semantics available
    without constructing a full worker result record.
    """
    existing = values[0] if values else None
    tags = _normalize_tag_list(existing)
    for item in values[1:] + tuple(SCANNER_DEGRADED_TAGS):
        for tag in _normalize_tag_list((item,)):
            if tag.lower() not in {t.lower() for t in tags}:
                tags.append(tag)
    return tags

def degraded_scan_integrity(error: object = None, **extra: object) -> dict[str, object]:
    out: dict[str, object] = {'file_failed': True, 'had_degraded_stage': True, 'allow_learning': False}
    if error is not None:
        out['error'] = _safe_strip_text(error)[:500] or 'result_record_error_unavailable'
    out.update(extra)
    return out

def _normalize_tag_list(value: object) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if value is None:
        iterable: tuple[object, ...] = ()
    elif type(value) is str:
        iterable = (value,)
    elif type(value) in (bytes, bytearray):
        try:
            iterable = (bytes(value).decode('utf-8', errors='replace'),)
        except (ValueError, TypeError, UnicodeError):
            iterable = ('tag_decode_unavailable',)
    elif type(value) in (tuple, list, set, frozenset):
        iterable = tuple(value)
    else:
        mapping_items = no_hook_mapping_items(value)
        if mapping_items is not None:
            iterable = tuple(key for key, _item in mapping_items)
        else:
            iterable = (value,)
    for item in iterable:
        tag = _safe_strip_text(item)
        if not tag and item is not None:
            tag = 'tag_text_unavailable'
        if not tag:
            continue
        key = tag.lower()
        if key not in seen:
            seen.add(key)
            out.append(tag)
    return out


def result_has_scan_evidence(record: object) -> bool:
    """Return True when a result carries real evidence or an explicit safe fast-path.

    This is a persistence-boundary contract, not a scoring function. Empty or
    malformed worker results must not be indistinguishable from clean results.
    """
    owned_record = _owned_mapping_snapshot(record)
    if owned_record is None:
        return False
    record = owned_record
    tags = _normalize_tag_list(_first_present_mapping_value(record, 'tags', 'suspicious_tags', default=[]))
    if tags:
        return True
    if _safe_count(_safe_mapping_get(record, 'yara_hits')):
        return True
    if (
        _safe_count(_safe_mapping_get(record, 'error'))
        or _safe_mapping_get(record, 'timed_out') is True
        or _safe_count(_safe_mapping_get(record, 'queue_failure'))
    ):
        return True
    integrity = _owned_mapping_snapshot(_safe_mapping_get(record, 'scan_integrity')) or {}
    if integrity and any(
        _safe_mapping_get(integrity, k) is True or _safe_count(_safe_mapping_get(integrity, k))
        for k in ('file_failed','had_degraded_stage','partial_retry','missing_chunks','raw_failures')
    ):
        return True
    if _safe_mapping_get(record, 'fast_path') is True or _safe_mapping_get(record, 'passive_fast_asset') is True or _safe_mapping_get(record, 'fast_asset') is True:
        return True
    cls = (_safe_strip_text(_safe_mapping_get(record, 'class')) or _safe_strip_text(_safe_mapping_get(record, 'classification'))).lower()
    if cls in {'asset','media','image','passive_asset','benign_clean'} and _safe_count(_safe_mapping_get(record, 'explanation')):
        return True
    api = _owned_mapping_snapshot(_safe_mapping_get(record, 'api')) or {}
    if (
        _safe_count(_safe_mapping_get(api, 'api_calls'))
        or _safe_count(_safe_mapping_get(api, 'ordered_events'))
        or _safe_count(_safe_mapping_get(api, 'behavior_timeline'))
    ):
        return True
    if (
        _safe_count(_safe_mapping_get(record, 'ordered_events'))
        or _safe_count(_safe_mapping_get(record, 'behavior_timeline'))
        or _safe_count(_safe_mapping_get(record, 'behavior_flow'))
    ):
        return True
    return _evidence_item_count(record, MODEL_RESULT_EVIDENCE_KEYS) > 0

def normalize_result_record(record: object, *, file_path: object | None = None, source: str = 'result_boundary') -> dict[str, object]:
    """Return a persistence-safe result record.

    Guarantees: a persisted dict has file/path identity, normalized tag list, and
    either evidence or explicit incomplete-scan metadata. This closes router and
    result-writer fail-open gaps without altering detector scoring weights.
    """
    owned_record = _owned_mapping_snapshot(record)
    if owned_record is not None:
        out = dict(owned_record)
    else:
        out = {'file': _safe_strip_text(file_path), 'error': 'non-dict scan result', 'score': 0.0, 'class': 'error', 'classification': 'error'}
    resolved_file = (
        _safe_strip_text(file_path)
        or _safe_strip_text(_safe_mapping_get(out, 'file'))
        or _safe_strip_text(_safe_mapping_get(out, 'path'))
        or _safe_strip_text(_safe_mapping_get(out, 'node'))
    )
    if resolved_file:
        out.setdefault('file', resolved_file)
        out.setdefault('path', resolved_file)
        out.setdefault('node', resolved_file)
    tags = _normalize_tag_list(_first_present_mapping_value(out, 'tags', 'suspicious_tags', default=[]))
    integrity = _owned_mapping_snapshot(_safe_mapping_get(out, 'scan_integrity')) or {}
    cls = (
        _safe_strip_text(_safe_mapping_get(out, 'class'))
        or _safe_strip_text(_safe_mapping_get(out, 'classification'))
        or _safe_strip_text(_safe_mapping_get(out, 'verdict'))
    ).lower()
    if not cls:
        out['class'] = 'incomplete_scan'
        out['classification'] = 'incomplete_scan'
        out.setdefault('error', 'result record missing verdict/classification')
        cls = 'incomplete_scan'
    has_error = (
        _safe_count(_safe_mapping_get(out, 'error')) > 0
        or _safe_mapping_get(out, 'timed_out') is True
        or _safe_count(_safe_mapping_get(out, 'queue_failure')) > 0
        or cls in {'error','timeout','incomplete_scan'}
    )
    degraded = (
        has_error
        or any(
            _safe_mapping_get(integrity, k) is True or _safe_count(_safe_mapping_get(integrity, k)) > 0
            for k in ('file_failed','had_degraded_stage','partial_retry','missing_chunks','raw_failures')
        )
        or any(t.lower() in INCOMPLETE_SCAN_TAGS for t in tags)
    )
    if degraded:
        for tag in INCOMPLETE_SCAN_TAGS:
            if tag not in tags:
                tags.append(tag)
        integrity['had_degraded_stage'] = True
        integrity['allow_learning'] = False
        if has_error:
            existing_file_failed = _safe_mapping_get(integrity, 'file_failed', default=True)
            integrity['file_failed'] = existing_file_failed is not False
    out['tags'] = tags
    out['scan_integrity'] = integrity
    if not result_has_scan_evidence(out):
        tags = _normalize_tag_list([*tags, 'result_contract_violation', 'scanner_failure', 'scanner_degraded', 'scan_incomplete'])
        out['tags'] = tags
        integrity.update({'had_degraded_stage': True, 'allow_learning': False, 'file_failed': True, 'result_contract_violation': True, 'normalizer': source})
        out['scan_integrity'] = integrity
        out['learn_eligible'] = False
        cleanish = (
            _safe_strip_text(_safe_mapping_get(out, 'classification'))
            or _safe_strip_text(_safe_mapping_get(out, 'class'))
        ).lower() in {'', 'clean', 'benign', 'benign_clean'}
        if cleanish:
            out['class'] = 'incomplete_scan'
            out['classification'] = 'incomplete_scan'
            out.setdefault('confidence', 0.0)
        out.setdefault('error', 'result record lacked evidence and explicit incomplete-scan metadata')
    if _safe_mapping_get(_safe_mapping_get(out, 'scan_integrity'), 'allow_learning') is False:
        out['learn_eligible'] = False
    return out



def result_is_incomplete_scan(record: object) -> bool:
    """Return True when a result must not be replayed, learned, or cached.

    This is intentionally tag + integrity based so degraded records remain blocked
    after JSON round-trips, queue persistence, old-cache load, and replay.
    """
    owned_record = _owned_mapping_snapshot(record)
    if owned_record is None:
        return True
    record = owned_record
    tags = {_safe_strip_text(t).lower() for t in _normalize_tag_list(_first_present_mapping_value(record, 'tags', 'suspicious_tags', default=[]))}
    integrity = _owned_mapping_snapshot(_safe_mapping_get(record, 'scan_integrity')) or {}
    cls = (_safe_strip_text(_safe_mapping_get(record, 'classification')) or _safe_strip_text(_safe_mapping_get(record, 'class'))).lower()
    if any(t in tags for t in ('scanner_failure', 'scanner_degraded', 'scan_incomplete', 'result_contract_violation')):
        return True
    if cls in {'error', 'timeout', 'incomplete_scan'}:
        return True
    if _safe_count(_safe_mapping_get(record, 'error')) or _safe_mapping_get(record, 'timed_out') is True or _safe_count(_safe_mapping_get(record, 'queue_failure')):
        return True
    return (
        _safe_mapping_get(integrity, 'allow_learning') is False
        or _safe_mapping_get(integrity, 'file_failed') is True
        or _safe_mapping_get(integrity, 'had_degraded_stage') is True
    )


def result_is_cache_reusable(record: object) -> bool:
    """Return True only for completed results safe to serve from pre-scan cache."""
    if _owned_mapping_snapshot(record) is None:
        return False
    normalized = normalize_result_record(
        record,
        file_path=_first_present_mapping_value(record, 'file', 'path', 'node', default=''),
        source='cache_reuse_check',
    )
    return not result_is_incomplete_scan(normalized)

def normalize_stage_from_path(path: object) -> str:
    ext = get_scan_extension(path)
    if ext in {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico'}:
        return 'image'
    if ext in {'.ogg', '.mp3', '.wav', '.flac', '.m4a'}:
        return 'media'
    if ext in {'.zip', '.7z', '.rar', '.tar', '.gz'}:
        return 'archive'
    if ext in {'.dll', '.exe'}:
        return 'dotnet'
    if ext in {'.js', '.rpy', '.rpyc', '.json'}:
        return 'script'
    return ext.lstrip('.') or 'unknown'


def make_worker_error_result(path: object, exc: BaseException | str) -> dict[str, object]:
    err = _safe_strip_text(exc) or 'worker_error_unavailable'
    safe_path = _safe_strip_text(path)
    return {
        'file': safe_path,
        'error': err,
        'score': 0.0,
        'class': 'error',
        'classification': 'error',
        'tags': ['scanner_failure', 'scanner_degraded', 'scan_incomplete'],
        'yara_hits': [],
        'effective_stage': normalize_stage_from_path(safe_path),
        'learn_eligible': False,
        'scan_duration_seconds': 0.0,
        'scan_integrity': {'file_failed': True, 'had_degraded_stage': True, 'allow_learning': False, 'error': err},
    }


def terminal_asset_engine_context(path: object, tags: object) -> tuple[dict[str, float], str]:
    tagset = {_safe_strip_text(t).lower() for t in _normalize_tag_list(tags) if _safe_strip_text(t)}
    safe_path = _safe_strip_text(path)
    suffix = Path(safe_path).suffix.lower()
    if tagset & {'rpgm', 'rpgm_resource', 'rpgm_encrypted_asset', 'rpgm_encrypted_image', 'rpgm_encrypted_audio'} or suffix in {'.rpgmvp', '.rpgmvo', '.rpgmvm', '.rgssad', '.rgss2a', '.rgss3a'}:
        return {'rpgm': 1.0, 'unity': 0.0, 'renpy': 0.0, 'media': 0.0, 'unknown': 0.0}, 'rpgm'
    if tagset & {'unity_asset', 'unity_container_asset'} or suffix in {'.assets', '.bundle', '.unity3d', '.resource'}:
        return {'unity': 1.0, 'renpy': 0.0, 'rpgm': 0.0, 'media': 0.0, 'unknown': 0.0}, 'unity'
    if tagset & {'renpy_script', 'renpy_archive'} or suffix in {'.rpy', '.rpyc', '.rpa', '.rpyb'}:
        return {'renpy': 1.0, 'unity': 0.0, 'rpgm': 0.0, 'media': 0.0, 'unknown': 0.0}, 'renpy'
    if tagset & {'media_asset', 'image_asset', 'audio_asset', 'video_asset', 'image_file', 'audio_file', 'video_file', 'media_file'} or suffix in {'.png', '.jpg', '.jpeg', '.bmp', '.webp', '.gif', '.svg', '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.mp4', '.webm', '.mkv', '.avi', '.mov'}:
        return {'media': 1.0, 'unity': 0.0, 'renpy': 0.0, 'rpgm': 0.0, 'unknown': 0.0}, 'media'
    return {'other': 1.0}, 'other'

def make_terminal_asset_result(path: object, tags: object, prev_stage: str = 'unknown', curr_stage: str | None = None, cache_sha256: str = '') -> dict[str, object]:
    final_tags = _normalize_tag_list([*list(_normalize_tag_list(tags)), 'terminal_clean_asset_triage', 'fast_path_non_learning'])
    stage = _safe_strip_text(curr_stage) or normalize_stage_from_path(_safe_strip_text(path))
    engine_context, active_profile = terminal_asset_engine_context(path, final_tags)
    safe_path = _safe_strip_text(path)
    return {
        'node': safe_path, 'file': safe_path, 'path': safe_path,
        'score': 3.0, 'cluster': None,
        'class': 'benign_clean', 'classification': 'benign_clean',
        'confidence': 0.30, 'tags': final_tags, 'yara_hits': [],
        'api': {'api_calls': [], 'ngrams': [], 'call_graph': {}, 'graph_features': {}, 'behavior_timeline': [], 'ordered_events': []},
        'behavior_timeline': [], 'ordered_events': [],
        'attack_intelligence': {}, 'heuristics': {'score': 0.0, 'hits': []},
        'layered_detection': {}, 'active_layers': 0, 'layer_weights': {},
        'graph_features': {'risk': 0.0, 'base_risk': 0.0, 'anomaly': 0.0},
        'temporal_features': {'belief': 0.0},
        'markov_features': {'transition': 0.0, 'rarity': 0.0, 'pair_anomaly': 0.0},
        'engine_context': engine_context, 'profile_selection': {'active_profile': active_profile},
        'feature_vector': [], 'fast_path': True, 'learn_eligible': False,
        'effective_stage': stage, 'prev_stage': prev_stage, 'suspicious_type_router': False,
        'cache_sha256': _safe_strip_text(cache_sha256),
        'explanation': {'classification': 'benign_clean', 'exit_code': 0, 'reason': 'terminal clean passive asset fast path'},
        'scan_integrity': {'allow_learning': False, 'terminal_fast_path': True},
    }

def _safe_timeout_seconds(value: object) -> int:
    seconds, reason = no_hook_finite_float(value, default=0.0, minimum=0.0, allow_exact_text=True)
    if reason:
        return 0
    return int(seconds)


def make_timeout_result(path: object, timeout_seconds: float, prev_stage: str = 'unknown') -> dict[str, object]:
    safe_path = _safe_strip_text(path)
    safe_timeout = _safe_timeout_seconds(timeout_seconds)
    return {
        'file': safe_path,
        'error': 'per-file timeout exceeded: ' + int.__str__(safe_timeout) + 's',
        'score': 0.0,
        'class': 'timeout',
        'classification': 'timeout',
        'confidence': 0.0,
        'tags': ['scanner_failure', 'scanner_degraded', 'scan_incomplete'],
        'yara_hits': [],
        'effective_stage': normalize_stage_from_path(safe_path),
        'prev_stage': prev_stage,
        'timed_out': True,
        'learn_eligible': False,
        'scan_integrity': {'file_failed': True, 'had_degraded_stage': True, 'allow_learning': False, 'error': 'timeout', 'timeout_seconds': safe_timeout},
    }


def is_passive_fast_asset_result(res: object) -> bool:
    owned = _owned_mapping_snapshot(res)
    if owned is None:
        return False
    res = owned
    # Tags may arrive at the result boundary as a scalar string from older
    # scanner/helper paths. Iterating the scalar directly turns
    # "encoded_payload" into character tags and incorrectly permits passive
    # fast-asset classification.  Reuse the canonical tag normalizer so hostile
    # tags keep their identity before the deny-list check.
    tags = {_safe_strip_text(t).lower() for t in _normalize_tag_list(_first_present_mapping_value(res, 'tags', 'suspicious_tags', default=[]))}
    cls = (
        _safe_strip_text(_safe_mapping_get(res, 'class'))
        or _safe_strip_text(_safe_mapping_get(res, 'classification'))
    ).lower()
    if _safe_mapping_get(res, 'passive_fast_asset') is True or _safe_mapping_get(res, 'fast_asset') is True:
        return True
    return cls in {'asset', 'media', 'image', 'passive_asset'} and not tags.intersection(
        {'encoded_payload', 'powershell', 'pickle_dangerous_global', 'malware'}
    )


__all__ = ('INCOMPLETE_SCAN_TAGS', 'SCANNER_DEGRADED_TAGS', 'EvidenceObjectSnapshot', 'ReplayComparableResultSnapshot', 'ResultEvidenceSnapshot', 'ResultIdentitySnapshot', 'ResultRecordCollectionSnapshot', 'degraded_scan_integrity', 'is_passive_fast_asset_result', 'make_terminal_asset_result', 'make_timeout_result', 'make_worker_error_result', 'normalize_result_record', 'normalize_stage_from_path', 'result_has_scan_evidence', 'result_is_cache_reusable', 'result_is_incomplete_scan', 'scanner_degraded_tags', 'terminal_asset_engine_context', 'validate_evidence_object_invariants', 'validate_replay_equivalent', 'validate_result_collection_invariants', 'validate_result_record_invariants')
