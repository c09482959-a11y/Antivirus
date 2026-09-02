"""Canonical runtime model/baseline mutation API for Phase C.

This module owns mutations for process-wide model counters and baselines.  The
actual storage objects are registered once by runtime initialization; callers do
not bypass this owner to mutate them.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import math
from types import MappingProxyType
from threading import RLock
from typing import Iterable, Mapping, TYPE_CHECKING
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.contracts.runtime_model_state import (
    RUNTIME_MODEL_STATE_SCHEMA_VERSION,
    materialize_current_runtime_model_state,
)
from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
    MARKOV_DISPOSITION_TRUSTED_BENIGN,
    MARKOV_EVENT_KEY_TYPE,
    MARKOV_EVENT_VOCABULARY_KEY_TYPE,
    MARKOV_STAGE_KEY_TYPE,
    MARKOV_STAGE_VOCABULARY_KEY_TYPE,
    MARKOV_STATE_SCHEMA_VERSION,
    MarkovUpdateRequest,
    markov_context_support_key,
    markov_global_context_key,
)
from Virus_Scan.runtime.runtime_flags import runtime_flag_mark
from Virus_Scan.runtime.cluster_state import runtime_cluster_state_to_json
from Virus_Scan.runtime.temporal_state import (
    TemporalStateOwner,
    load_temporal_runtime_state,
    temporal_runtime_state_to_json,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.model_state_support import (
    _immutable_counter_snapshot,
    _is_runtime_mutable_mapping_storage,
    _runtime_model_count,
    _runtime_model_count_with_reason,
    _runtime_model_display_text,
    _runtime_model_dot_path,
    _runtime_model_failure,
    _runtime_model_identity_text as _runtime_model_identity_text_support,
    _runtime_model_items,
    _runtime_model_join_text,
    _runtime_model_keys,
    _runtime_model_mapping_nonempty,
    _runtime_model_nonempty_text,
    _runtime_model_owned_mapping_get,
    _runtime_model_owned_mapping_items,
    _runtime_model_sequence_values,
    _runtime_model_sort_key,
    _runtime_model_sorted_items,
    _runtime_transition_key_error,
    _runtime_transition_row_error,
    _sorted_counter_items,
)
from Virus_Scan.runtime.model_state_baseline_support import (
    _runtime_model_load_section,
    _runtime_model_parse_filetypes,
    _runtime_model_parse_pair_rows,
    _runtime_model_parse_tag_baseline,
    _runtime_model_parse_transition_rows,    runtime_transition_key_from_json,

)

if TYPE_CHECKING:
    from collections.abc import MutableMapping

def _runtime_model_identity_text(value: object) -> tuple[str, str]:
    return _runtime_model_identity_text_support(value)


class ModelStateNotConfigured(RuntimeError):
    """Raised when a model owner API is used before runtime storage is bound."""


class _RuntimeModelStateOwner:
    """Owns runtime model locks and storage bindings without global rebinding."""
    def __init__(self) -> None:
        self.model_lock = RLock()
        self.global_lock = RLock()
        self.learning_keys: dict[str, dict[str, int]] = {"markov": {}, "filetype": {}}
        self.maps: dict[str, MutableMapping[object, object]] = {
            'TRANSITION_COUNTS': defaultdict(Counter),
            'GLOBAL_TAG_BASELINE': defaultdict(int),
            'GLOBAL_TAG_PAIR_BASELINE': defaultdict(int),
            'FILETYPE_BASELINE': defaultdict(Counter),
        }

    def configure_locks(self, *, runtime_model_lock: object=None, global_state_lock: object=None) -> None:
        if runtime_model_lock is not None:
            self.model_lock = runtime_model_lock
        if global_state_lock is not None:
            self.global_lock = global_state_lock


_MODEL_OWNER = _RuntimeModelStateOwner()


def configure_runtime_model_state(*, runtime_model_lock: object=None, global_state_lock: object=None, transition_counts: object=None,
                                  global_tag_baseline: object=None, global_tag_pair_baseline: object=None,
                                  filetype_baseline: object=None) -> None:
    """Bind canonical model storage objects to the model owner.

    Storage remains the existing runtime dictionaries/counters for behavioral
    parity, but mutation authority is centralized here instead of scattered
    through shared mutable imports.
    """
    _MODEL_OWNER.configure_locks(runtime_model_lock=runtime_model_lock, global_state_lock=global_state_lock)
    pairs = {
        'TRANSITION_COUNTS': transition_counts,
        'GLOBAL_TAG_BASELINE': global_tag_baseline,
        'GLOBAL_TAG_PAIR_BASELINE': global_tag_pair_baseline,
        'FILETYPE_BASELINE': filetype_baseline,
    }
    with _MODEL_OWNER.model_lock, _MODEL_OWNER.global_lock:
        for name, mapping in dict.items(pairs):
            if mapping is None:
                continue
            if not _is_runtime_mutable_mapping_storage(mapping):
                raise TypeError(_runtime_model_join_text(
                    "runtime model storage must be an owned mutable mapping: ", name,
                ))
            _MODEL_OWNER.maps[name] = mapping
            if name == "TRANSITION_COUNTS":
                _MODEL_OWNER.learning_keys["markov"].clear()
            elif name == "FILETYPE_BASELINE":
                _MODEL_OWNER.learning_keys["filetype"].clear()


def _map(name: str) -> MutableMapping[object, object]:
    with _MODEL_OWNER.global_lock:
        mapping = _MODEL_OWNER.maps.get(name)
    if mapping is None:
        raise ModelStateNotConfigured(_runtime_model_join_text("runtime model state not configured: ", name))
    return mapping





































def runtime_model_mapping_snapshot(name: str) -> Mapping[object, object]:
    """Return an immutable detached snapshot of a runtime model mapping."""
    with _MODEL_OWNER.global_lock:
        mapping = _map(name)
        if name == 'TRANSITION_COUNTS':
            materialized_transitions = {}
            for k, v in _runtime_model_sorted_items(mapping):
                if _runtime_transition_key_error(k):
                    continue
                counter_snapshot = _immutable_counter_snapshot(v)
                if counter_snapshot:
                    materialized_transitions[k] = counter_snapshot
            return MappingProxyType(materialized_transitions)
        if name == 'FILETYPE_BASELINE':
            materialized_filetypes = {}
            for k, v in _runtime_model_sorted_items(mapping):
                ext_key = _runtime_model_nonempty_text(k)
                if not ext_key:
                    continue
                if _runtime_model_owned_mapping_items(v) is None:
                    continue
                materialized_counter = {}
                for counter_key, counter_value in _sorted_counter_items(v):
                    tag_key = _runtime_model_nonempty_text(counter_key)
                    count = _runtime_model_count(counter_value)
                    if tag_key and count > 0:
                        materialized_counter[tag_key] = count
                if materialized_counter:
                    materialized_filetypes[ext_key] = MappingProxyType(materialized_counter)
            return MappingProxyType(materialized_filetypes)
        if name == 'GLOBAL_TAG_PAIR_BASELINE':
            pair_snapshot = {}
            for k, v in _runtime_model_sorted_items(mapping):
                pair_a, pair_b, reason = _runtime_model_pair_key_parts(k)
                count = _runtime_model_count(v)
                if reason or count <= 0:
                    continue
                pair_snapshot[(pair_a, pair_b)] = count
            return MappingProxyType(pair_snapshot)
        if name == 'GLOBAL_TAG_BASELINE':
            tag_snapshot = {}
            for k, v in _runtime_model_sorted_items(mapping):
                key_text = _runtime_model_nonempty_text(k)
                count = _runtime_model_count(v)
                if key_text and count > 0:
                    tag_snapshot[key_text] = count
            return MappingProxyType(tag_snapshot)
        return MappingProxyType({
            k: _runtime_model_count(v)
            for k, v in _runtime_model_sorted_items(mapping)
        })


def runtime_transition_counter_snapshot(key: object) -> Mapping[object, int]:
    """Return an immutable detached transition counter for a valid Markov key."""
    if _runtime_transition_key_error(key):
        return MappingProxyType({})
    with _MODEL_OWNER.global_lock:
        counter = _runtime_model_owned_mapping_get(_map('TRANSITION_COUNTS'), key, Counter())
        return _immutable_counter_snapshot(counter)


def runtime_markov_observation_total() -> int:
    """Return the canonical global contextual Markov observation count."""
    key = markov_context_support_key(markov_global_context_key())
    counter = runtime_transition_counter_snapshot(key)
    return _runtime_model_count(counter.get("observations", 0))



def _increment_global_behavior_flow(flow: Iterable[object]) -> None:
    """Update global benign rarity baselines from one authorized flow."""
    with _MODEL_OWNER.model_lock:
        baseline = _map('GLOBAL_TAG_BASELINE')
        pair_baseline = _map('GLOBAL_TAG_PAIR_BASELINE')
        flow_list = [
            text for text in (
                _runtime_model_nonempty_text(item)
                for item in _runtime_model_sequence_values(flow)
            ) if text
        ]
        for key in flow_list:
            baseline[key] = (
                _runtime_model_count(_runtime_model_owned_mapping_get(baseline, key, 0)) + 1
            )
        for left, right in zip(flow_list, flow_list[1:], strict=False):
            pair = (left, right)
            pair_baseline[pair] = (
                _runtime_model_count(
                    _runtime_model_owned_mapping_get(pair_baseline, pair, 0)
                ) + 1
            )


def _increment_transition_counter(
    transitions: MutableMapping[object, object], key: object, target: object,
) -> None:
    """Increment one validated runtime-owned Markov counter."""
    if _runtime_transition_key_error(key):
        raise ValueError("invalid markov transition key")
    target_text = _runtime_model_nonempty_text(target)
    if target_text == "":
        raise ValueError("invalid markov transition target")
    counter = _runtime_model_owned_mapping_get(transitions, key)
    if _runtime_model_owned_mapping_items(counter) is None:
        counter = Counter()
        transitions[key] = counter
    counter[target_text] = (
        _runtime_model_count(_runtime_model_owned_mapping_get(counter, target_text, 0))
        + 1
    )


def _increment_contextual_markov_request(request: MarkovUpdateRequest) -> None:
    """Apply all canonical context-conditioned Markov counters atomically.

    The v2 rows are the sole transition owner.  The global lower-confidence
    context remains previous-stage conditioned under its canonical key.
    """
    if type(request) is not MarkovUpdateRequest:
        raise TypeError("markov update request required")
    request.validate()
    if request.learning_disposition != MARKOV_DISPOSITION_TRUSTED_BENIGN:
        raise ValueError("markov update disposition not trusted benign")
    flow_list = list(request.behavior_flow)
    with _MODEL_OWNER.model_lock:
        transitions = _map("TRANSITION_COUNTS")
        _increment_global_behavior_flow(flow_list)
        for _level, context_key in request.context_levels():
            _increment_transition_counter(
                transitions,
                request.context_support_key(context_key),
                "observations",
            )
            _increment_transition_counter(
                transitions,
                request.stage_vocabulary_key(context_key),
                request.current_stage,
            )
            for event in tuple(dict.fromkeys(flow_list)):
                _increment_transition_counter(
                    transitions,
                    request.event_vocabulary_key(context_key),
                    event,
                )
            _increment_transition_counter(
                transitions,
                request.stage_transition_key(context_key),
                request.current_stage,
            )
            for source, target in zip(flow_list, flow_list[1:], strict=False):
                _increment_transition_counter(
                    transitions,
                    request.event_transition_key(context_key, source),
                    target,
                )

def _runtime_model_commit_section(
    name: str, prepared: Mapping[object, object], *, should_commit: bool
) -> None:
    if not should_commit:
        return
    target = _map(name)
    target.clear()
    target.update(prepared)



def _runtime_model_prepare_learning_state(
    learning_section: object, learning_valid: bool,
    temporal_section: object, temporal_valid: bool,
    failures: list[dict[str, str]],
) -> tuple[dict[str, dict[str, int]], dict[str, object]]:
    prepared: dict[str, dict[str, int]] = {"markov": {}, "filetype": {}}
    if learning_valid:
        for target in ("markov", "filetype"):
            raw_keys = (
                learning_section.get(target, ())
                if isinstance(learning_section, Mapping) else ()
            )
            if type(raw_keys) not in (tuple, list):
                failures.append(_runtime_model_failure(
                    _runtime_model_dot_path("learning_applied_keys", target),
                    "invalid_runtime_learning_key_section", raw_keys,
                ))
                continue
            for index, raw_key in enumerate(raw_keys):
                try:
                    key = _valid_learning_replay_key(raw_key)
                except ValueError:
                    failures.append(_runtime_model_failure(
                        _runtime_model_join_text(
                            "learning_applied_keys.", target, ".", str(index),
                        ),
                        "invalid_runtime_learning_replay_key", raw_key,
                    ))
                    continue
                prepared[target][key] = index
    temporal_result = (
        TemporalStateOwner().load_record(temporal_section)
        if temporal_valid else {"loaded": False, "reason": "temporal_state_invalid"}
    )
    if temporal_valid and temporal_result.get("loaded") is not True:
        failures.append(_runtime_model_failure(
            "temporal_state",
            str(temporal_result.get("reason") or "temporal_state_invalid"),
            temporal_section,
        ))
    return prepared, temporal_result

def load_runtime_model_baselines(data: Mapping[str, object]) -> dict[str, object]:
    """Atomically hydrate one exact-current complete runtime-model snapshot.

    Any invalid envelope or nested section leaves all live model state intact.
    """
    try:
        current_record = materialize_current_runtime_model_state(data)
    except (TypeError, ValueError) as exc:
        reason = str(exc) or "runtime_model_snapshot_invalid"
        return {
            'loaded': False,
            'reason': reason,
            'records_loaded': 0,
            'records_skipped': 0,
            'model_state_unavailable_reasons': (
                _runtime_model_failure('runtime_model_snapshot', reason),
            ),
        }
    data = current_record
    failures: list[dict[str, str]] = []
    transition_rows, transitions_valid = _runtime_model_load_section(
        data, "transition_counts", (list, tuple), (), failures
    )
    tag_section, tags_valid = _runtime_model_load_section(
        data, "global_tag_baseline", Mapping, {}, failures
    )
    pair_rows, pairs_valid = _runtime_model_load_section(
        data, "global_tag_pair_baseline", (list, tuple), (), failures
    )
    filetype_section, filetypes_valid = _runtime_model_load_section(
        data, "filetype_baseline", Mapping, {}, failures
    )
    learning_section, learning_valid = _runtime_model_load_section(
        data, "learning_applied_keys", Mapping, {}, failures
    )
    temporal_section, temporal_valid = _runtime_model_load_section(
        data, "temporal_state", Mapping, {}, failures
    )

    transition_state, loaded_a, skipped_a, commit_a = (
        _runtime_model_parse_transition_rows(transition_rows, failures)
        if transitions_valid
        else ({}, 0, 0, False)
    )
    tag_state, loaded_b, skipped_b, commit_b = (
        _runtime_model_parse_tag_baseline(tag_section, failures)
        if tags_valid
        else ({}, 0, 0, False)
    )
    pair_state, loaded_c, skipped_c, commit_c = (
        _runtime_model_parse_pair_rows(pair_rows, failures)
        if pairs_valid
        else ({}, 0, 0, False)
    )
    filetype_state, loaded_d, skipped_d, commit_d = (
        _runtime_model_parse_filetypes(filetype_section, failures)
        if filetypes_valid
        else ({}, 0, 0, False)
    )

    prepared_learning, temporal_result = _runtime_model_prepare_learning_state(
        learning_section, learning_valid, temporal_section, temporal_valid, failures,
    )
    if failures:
        return {
            'loaded': False,
            'reason': failures[0]['reason'],
            'records_loaded': 0,
            'records_skipped': skipped_a + skipped_b + skipped_c + skipped_d,
            'model_state_unavailable_reasons': tuple(failures),
        }

    with _MODEL_OWNER.global_lock:
        if learning_valid:
            _MODEL_OWNER.learning_keys = prepared_learning
        _runtime_model_commit_section(
            "TRANSITION_COUNTS", transition_state, should_commit=commit_a
        )
        _runtime_model_commit_section(
            "GLOBAL_TAG_BASELINE", tag_state, should_commit=commit_b
        )
        _runtime_model_commit_section(
            "GLOBAL_TAG_PAIR_BASELINE", pair_state, should_commit=commit_c
        )
        _runtime_model_commit_section(
            "FILETYPE_BASELINE", filetype_state, should_commit=commit_d
        )
    live_temporal_result = load_temporal_runtime_state(temporal_section)
    if live_temporal_result.get("loaded") is not True:
        raise RuntimeError("validated_temporal_state_commit_failed")
    records_loaded = loaded_a + loaded_b + loaded_c + loaded_d
    records_loaded += int(live_temporal_result.get("nodes_loaded", 0))
    records_skipped = skipped_a + skipped_b + skipped_c + skipped_d
    return {
        'loaded': True,
        'reason': failures[0]['reason'] if failures else None,
        'records_loaded': records_loaded,
        'records_skipped': records_skipped,
        'model_state_unavailable_reasons': tuple(failures),
    }


def mark_runtime_models_dirty() -> None:
    """Record that runtime-owned model state changed.

    Runtime model-state owns the dirty flag because Markov, temporal, profile,
    and replay learning all mutate the same persisted learned-state snapshot.
    Keeping this marker here prevents each model from exposing a duplicate
    dirty-state authority.
    """
    runtime_flag_mark('runtime_model_state_dirty')


def update_filetype_baseline(ext: object, flow: Iterable[object], mark_dirty: object=None) -> None:
    """Update per-extension behavior baseline through the model owner.

    Blank extension/tag identities are malformed model evidence.  Do not add
    them to mutable runtime state and rely on later JSON filtering to hide them.
    """
    with _MODEL_OWNER.model_lock:
        filetype = _map('FILETYPE_BASELINE')
        key = _runtime_model_nonempty_text(ext)
        if key == "":
            key = '<no_ext>'
        key = key.lower()
        flow_list = [text for text in (_runtime_model_nonempty_text(x) for x in _runtime_model_sequence_values(flow)) if text]
        if not flow_list:
            return
        current = _runtime_model_owned_mapping_get(filetype, key)
        if current is None:
            current = Counter()
            filetype[key] = current
        current.update(flow_list)
        if mark_dirty is not None:
            mark_dirty()



def _valid_learning_replay_key(value: object) -> str:
    if type(value) is not str:
        raise ValueError("runtime learning replay key invalid")
    key = str.__str__(value)
    if len(key) != 64 or any(char not in "0123456789abcdef" for char in key):
        raise ValueError("runtime learning replay key invalid")
    return key


def _record_runtime_learning_key(target: str, replay_key: str, ordinal: object) -> None:
    ledger = _MODEL_OWNER.learning_keys[target]
    ledger[replay_key] = max(0, _runtime_model_count(ordinal))
    if len(ledger) > 4096:
        keep = {key for _value, key in sorted((value, key) for key, value in ledger.items())[-4096:]}
        for key in tuple(ledger):
            if key not in keep:
                ledger.pop(key, None)


def commit_markov_update_request(request: MarkovUpdateRequest) -> bool:
    """Atomically apply one immutable decision-bound Markov request once."""
    if type(request) is not MarkovUpdateRequest:
        raise TypeError("markov update request required")
    request.validate()
    key = _valid_learning_replay_key(request.replay_key)
    with _MODEL_OWNER.model_lock:
        if key in _MODEL_OWNER.learning_keys["markov"]:
            return False
        _increment_contextual_markov_request(request)
        _record_runtime_learning_key("markov", key, request.decision_ordinal)
        return True


def apply_filetype_baseline_once(
    replay_key: object, decision_ordinal: object, ext: object,
    flow: Iterable[object], mark_dirty: object = None,
) -> bool:
    """Atomically apply one decision-bound filetype mutation at most once."""
    key = _valid_learning_replay_key(replay_key)
    with _MODEL_OWNER.model_lock:
        if key in _MODEL_OWNER.learning_keys["filetype"]:
            return False
        update_filetype_baseline(ext, flow, mark_dirty=mark_dirty)
        _record_runtime_learning_key("filetype", key, decision_ordinal)
        return True

def set_global_tag_count(key: object, value: object) -> None:
    key_text = _runtime_model_nonempty_text(key)
    if not key_text:
        return
    with _MODEL_OWNER.global_lock:
        _map('GLOBAL_TAG_BASELINE')[key_text] = _runtime_model_count(value)


def runtime_transition_key_to_json(key: object) -> dict[str, object]:
    """Serialize one canonical v2 Markov transition key."""
    if type(key) is not tuple or len(key) != 2:
        return {"type": "invalid"}
    left, right = key
    left_s = _runtime_model_nonempty_text(left)
    if left_s == MARKOV_EVENT_KEY_TYPE and type(right) is tuple and len(right) == 3:
        context, previous_stage, source_event = (
            _runtime_model_nonempty_text(item) for item in right
        )
        return {
            "type": MARKOV_EVENT_KEY_TYPE,
            "context": context,
            "previous_stage": previous_stage,
            "source_event": source_event,
        }
    if left_s == MARKOV_STAGE_KEY_TYPE and type(right) is tuple and len(right) == 3:
        context, previous_stage, flow_class = (
            _runtime_model_nonempty_text(item) for item in right
        )
        return {
            "type": MARKOV_STAGE_KEY_TYPE,
            "context": context,
            "previous_stage": previous_stage,
            "flow_class": flow_class,
        }
    if left_s in {
        MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
        MARKOV_EVENT_VOCABULARY_KEY_TYPE,
        MARKOV_STAGE_VOCABULARY_KEY_TYPE,
    }:
        return {
            "type": left_s,
            "context": _runtime_model_nonempty_text(right),
        }
    return {"type": "invalid"}



def _runtime_model_pair_key_parts(key: object) -> tuple[str, str, str]:
    """Return deterministic pair-key parts and malformed-key evidence reason."""
    if isinstance(key, (str, bytes)) or not isinstance(key, (tuple, list)) or len(key) != 2:
        return "", "", "invalid_runtime_pair_key"
    left = _runtime_model_nonempty_text(key[0])
    right = _runtime_model_nonempty_text(key[1])
    if not left or not right:
        return "", "", "invalid_runtime_pair_key"
    return left, right, ""


def _runtime_transition_key_json_error(key_json: Mapping[str, object]) -> str:
    """Return why a runtime transition snapshot key cannot be replay evidence."""
    if _runtime_model_owned_mapping_items(key_json) is None:
        return "invalid_runtime_transition_key"
    
    try:
        row = {str.__str__(k): v for k, v in _runtime_model_items(key_json) if type(k) is str}
    except (TypeError, ValueError, RuntimeError):
        return "unreadable_runtime_transition_key"
    row["target"] = "__runtime_snapshot_validation__"
    return _runtime_transition_row_error(row)

def _runtime_model_snapshot_revision(value: object) -> int:
    """Return a deterministic logical revision for runtime model snapshots.

    The runtime model snapshot is replay-affecting persisted model state.  It
    must not stamp JSON with wall-clock time because identical learned state
    would otherwise produce different final JSON/replay evidence.  This helper
    derives a stable integer marker from the already-materialized model state.
    It is intentionally structural rather than cryptographic: callers should
    treat ``updated`` as a deterministic model-state revision, not a timestamp.
    """
    if _runtime_model_owned_mapping_items(value) is not None:
        total = len(value)
        for _key, item in _runtime_model_sorted_items(value):
            total += 1 + _runtime_model_snapshot_revision(item)
        return int(total)
    if type(value) in (list, tuple):
        return int(len(value) + sum(_runtime_model_snapshot_revision(item) for item in value))
    if type(value) in (set, frozenset):
        return int(len(value) + sum(_runtime_model_snapshot_revision(item) for item in sorted(value, key=_runtime_model_sort_key)))
    if type(value) is bool or value is None:
        return int(bool(value))
    if type(value) in (int, float):
        try:
            numeric = float(value)
        except RECOVERABLE_RUNTIME_ERRORS:
            return len(no_hook_type_name(value)) + 1
        if not math.isfinite(numeric):
            return len("non_finite_runtime_model_revision")
        return int(abs(numeric))
    text = _runtime_model_display_text(value)
    return 1 if text else 0



def _runtime_transition_rows_snapshot(
    transition_counts: object, markov_key_to_json: object,
    failures: list[dict[str, str]],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key, value in _runtime_model_sorted_items(transition_counts):
        key_json = markov_key_to_json(key)
        key_reason = _runtime_transition_key_json_error(key_json)
        if key_reason:
            failures.append(_runtime_model_failure(
                _runtime_model_dot_path("transition_counts", _runtime_model_sort_key(key)),
                key_reason, key,
            ))
            continue
        if _runtime_model_owned_mapping_items(value) is None:
            failures.append(_runtime_model_failure(
                _runtime_model_dot_path("transition_counts", _runtime_model_sort_key(key)),
                "non_mapping_runtime_transition_counter", value,
            ))
            continue
        for target, raw_count in _sorted_counter_items(value):
            target_text = _runtime_model_nonempty_text(target)
            if not target_text:
                failures.append(_runtime_model_failure(
                    _runtime_model_join_text(
                        "transition_counts.", _runtime_model_sort_key(key), ".<empty>",
                    ),
                    "invalid_runtime_transition_target", target,
                ))
                continue
            count, reason = _runtime_model_count_with_reason(raw_count)
            if reason:
                failures.append(_runtime_model_failure(
                    _runtime_model_join_text(
                        "transition_counts.", _runtime_model_sort_key(key), ".", target_text,
                    ),
                    reason, raw_count,
                ))
            if count > 0:
                rows.append({**key_json, "target": target_text, "count": count})
    rows.sort(
        key=lambda row: (
            row.get("type", ""),
            repr(row.get("flow", row.get("event", ""))),
            row.get("target", ""),
            row.get("context", ""),
            row.get("previous_stage", ""),
            row.get("source_event", ""),
            row.get("flow_class", ""),
        )
    )
    return rows


def _runtime_tag_baseline_snapshot(
    baseline: object, failures: list[dict[str, str]],
) -> dict[str, int]:
    out: dict[str, int] = {}
    for key, raw_count in _runtime_model_sorted_items(baseline):
        key_text = _runtime_model_nonempty_text(key)
        if not key_text:
            failures.append(_runtime_model_failure(
                "global_tag_baseline.<empty>", "invalid_runtime_tag_key", key,
            ))
            continue
        count, reason = _runtime_model_count_with_reason(raw_count)
        if reason:
            failures.append(_runtime_model_failure(
                _runtime_model_dot_path("global_tag_baseline", key_text),
                reason, raw_count,
            ))
        if count > 0:
            out[key_text] = count
    return out


def _runtime_pair_baseline_snapshot(
    baseline: object, failures: list[dict[str, str]],
) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for key, raw_count in _runtime_model_sorted_items(baseline):
        count, reason = _runtime_model_count_with_reason(raw_count)
        pair_a, pair_b, key_reason = _runtime_model_pair_key_parts(key)
        if key_reason:
            failures.append(_runtime_model_failure(
                _runtime_model_dot_path("global_tag_pair_baseline", _runtime_model_sort_key(key)),
                key_reason, key,
            ))
            continue
        if reason:
            failures.append(_runtime_model_failure(
                _runtime_model_dot_path("global_tag_pair_baseline", _runtime_model_sort_key(key)),
                reason, raw_count,
            ))
        if count > 0:
            out.append({"a": pair_a, "b": pair_b, "count": count})
    return out


def _runtime_filetype_baseline_snapshot(
    baseline: object, failures: list[dict[str, str]],
) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for extension, counter in _runtime_model_sorted_items(baseline):
        extension_key = _runtime_model_nonempty_text(extension)
        if not extension_key:
            failures.append(_runtime_model_failure(
                "filetype_baseline.<empty>", "invalid_runtime_filetype_key", extension,
            ))
            continue
        if _runtime_model_owned_mapping_items(counter) is None:
            failures.append(_runtime_model_failure(
                _runtime_model_dot_path("filetype_baseline", extension_key),
                "non_mapping_runtime_filetype_counter", counter,
            ))
            continue
        values: dict[str, int] = {}
        for tag, raw_count in _sorted_counter_items(counter):
            tag_key = _runtime_model_nonempty_text(tag)
            if not tag_key:
                failures.append(_runtime_model_failure(
                    _runtime_model_join_text(
                        "filetype_baseline.", extension_key, ".<empty>",
                    ),
                    "invalid_runtime_filetype_tag_key", tag,
                ))
                continue
            count, reason = _runtime_model_count_with_reason(raw_count)
            if reason:
                failures.append(_runtime_model_failure(
                    _runtime_model_join_text(
                        "filetype_baseline.", extension_key, ".", tag_key,
                    ),
                    reason, raw_count,
                ))
            if count > 0:
                values[tag_key] = count
        if values:
            out[extension_key] = values
    return out

def runtime_model_snapshot(*, markov_key_to_json: object, cluster_state_to_json: object, prune_runtime_model_state: object=None) -> dict[str, object]:
    """Serialize runtime model state through the model owner boundary."""
    if prune_runtime_model_state is not None:
        prune_runtime_model_state()
    with _MODEL_OWNER.global_lock:
        failures: list[dict[str, str]] = []
        payload: dict[str, object] = {
            "markov_state_schema_version": MARKOV_STATE_SCHEMA_VERSION,
            "markov_state_migration_evidence": "canonical_initial_contextual_state",
            "transition_counts": _runtime_transition_rows_snapshot(
                _map("TRANSITION_COUNTS"), markov_key_to_json, failures,
            ),
            "global_tag_baseline": _runtime_tag_baseline_snapshot(
                _map("GLOBAL_TAG_BASELINE"), failures,
            ),
            "global_tag_pair_baseline": _runtime_pair_baseline_snapshot(
                _map("GLOBAL_TAG_PAIR_BASELINE"), failures,
            ),
            "filetype_baseline": _runtime_filetype_baseline_snapshot(
                _map("FILETYPE_BASELINE"), failures,
            ),
            "cluster_state": cluster_state_to_json(),
            "temporal_state": temporal_runtime_state_to_json(),
            "learning_applied_keys": {
                target: tuple(key for _ordinal, key in sorted(
                    (ordinal, key) for key, ordinal in ledger.items()
                ))
                for target, ledger in sorted(_MODEL_OWNER.learning_keys.items())
            },
        }
        if failures:
            payload["model_state_unavailable_reasons"] = tuple(failures)
        return {
            "schema_version": RUNTIME_MODEL_STATE_SCHEMA_VERSION,
            "updated": _runtime_model_snapshot_revision(payload),
            **payload,
        }


def runtime_model_state_to_json() -> dict[str, object]:
    """Return the canonical current runtime-model snapshot."""
    return runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=runtime_cluster_state_to_json,
    )


def prune_runtime_model_mappings_for_retention(*,
                                             max_transition_keys: int,
                                             max_transition_next_keys: int,
                                             max_tag_counter_keys: int,
                                             max_pair_counter_keys: int,
                                             max_filetype_baselines: int) -> None:
    """Bound runtime Markov/filetype mappings through the model-state owner."""
    def _numeric_total(value: object) -> float:
        items = _runtime_model_owned_mapping_items(value)
        if items is not None:
            return float(sum(_runtime_model_count(v) for _k, v in items))
        return float(_runtime_model_count(value))

    def _retention_rank(item: object) -> tuple[float, str]:
        key, value = item
        return (-_numeric_total(value), _runtime_model_sort_key(key))

    def _prune_counter(counter: object, limit: int) -> None:
        if _runtime_model_owned_mapping_items(counter) is None:
            return
        for key in _runtime_model_keys(counter):
            if not _runtime_model_nonempty_text(key) or _runtime_model_count(_runtime_model_owned_mapping_get(counter, key, 0)) <= 0:
                del counter[key]
        safe_limit = _runtime_model_count(limit)
        if safe_limit <= 0 or len(counter) <= safe_limit:
            return
        ranked = sorted(_runtime_model_items(counter), key=_retention_rank)[:safe_limit]
        counter.clear()
        counter.update(dict(ranked))

    with _MODEL_OWNER.global_lock:
        transitions = _map('TRANSITION_COUNTS')
        for key in _runtime_model_keys(transitions):
            value = _runtime_model_owned_mapping_get(transitions, key)
            if _runtime_transition_key_error(key) or _runtime_model_owned_mapping_items(value) is None:
                del transitions[key]
                continue
            _prune_counter(value, _runtime_model_count(max_transition_next_keys))
            if not _runtime_model_mapping_nonempty(value):
                del transitions[key]
        max_transition_key_count = _runtime_model_count(max_transition_keys)
        if len(transitions) > max_transition_key_count > 0:
            ranked = sorted(_runtime_model_items(transitions), key=_retention_rank)[:max_transition_key_count]
            transitions.clear()
            for key, value in ranked:
                transitions[key] = Counter(dict(_runtime_model_items(value))) if _runtime_model_owned_mapping_items(value) is not None else Counter()

        tag_baseline = _map('GLOBAL_TAG_BASELINE')
        for key in _runtime_model_keys(tag_baseline):
            if not _runtime_model_nonempty_text(key):
                del tag_baseline[key]
        _prune_counter(tag_baseline, _runtime_model_count(max_tag_counter_keys))

        pair_baseline = _map('GLOBAL_TAG_PAIR_BASELINE')
        for key in _runtime_model_keys(pair_baseline):
            _left, _right, reason = _runtime_model_pair_key_parts(key)
            if reason or _runtime_model_count(_runtime_model_owned_mapping_get(pair_baseline, key, 0)) <= 0:
                del pair_baseline[key]
        max_pair_counter_key_count = _runtime_model_count(max_pair_counter_keys)
        if max_pair_counter_key_count > 0 and len(pair_baseline) > max_pair_counter_key_count:
            ranked = sorted(_runtime_model_items(pair_baseline), key=_retention_rank)[:max_pair_counter_key_count]
            pair_baseline.clear()
            pair_baseline.update(dict(ranked))

        filetype = _map('FILETYPE_BASELINE')
        for key in _runtime_model_keys(filetype):
            value = _runtime_model_owned_mapping_get(filetype, key)
            if not _runtime_model_nonempty_text(key) or _runtime_model_owned_mapping_items(value) is None:
                del filetype[key]
        for key, counter in list(_runtime_model_items(filetype)):
            _prune_counter(counter, _runtime_model_count(max_tag_counter_keys))
            if _runtime_model_owned_mapping_items(counter) is None or not _runtime_model_mapping_nonempty(counter):
                del filetype[key]
        max_filetype_baseline_count = _runtime_model_count(max_filetype_baselines)
        if len(filetype) > max_filetype_baseline_count > 0:
            ranked = sorted(_runtime_model_items(filetype), key=_retention_rank)[:max_filetype_baseline_count]
            filetype.clear()
            for key, value in ranked:
                filetype[key] = Counter(dict(_runtime_model_items(value))) if _runtime_model_owned_mapping_items(value) is not None else Counter()


__all__ = (
    'ModelStateNotConfigured',
    'apply_filetype_baseline_once',
    'commit_markov_update_request',
    'configure_runtime_model_state',
    'load_runtime_model_baselines',
    'mark_runtime_models_dirty',
    'prune_runtime_model_mappings_for_retention',
    'runtime_model_mapping_snapshot',
    'runtime_markov_observation_total',
    'runtime_model_snapshot',
    'runtime_model_state_to_json',
    'runtime_transition_counter_snapshot',
    'runtime_transition_key_from_json',
    'runtime_transition_key_to_json',
    'set_global_tag_count',
    'update_filetype_baseline',
)
