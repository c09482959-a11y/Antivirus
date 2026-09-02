from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
import math
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name

PLR2004N32 = 32

RETENTION_TEXT_ERRORS = (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError)
_DICT_ITEMS = dict.items


def _retention_type_label(value: object) -> object:
    return no_hook_type_name(value) or 'object'


def _retention_mapping_items(value: object) -> object:
    if type(value) is dict:
        return tuple(_DICT_ITEMS(value))
    if isinstance(value, dict):
        value_type = type(value)
        try:
            if (
                type.__getattribute__(value_type, "__iter__") is dict.__iter__
                and type.__getattribute__(value_type, "keys") is dict.keys
            ):
                return tuple(_DICT_ITEMS(value))
        except RETENTION_TEXT_ERRORS:
            return no_hook_mapping_items(value)
    return no_hook_mapping_items(value)


def _is_retention_mapping(value: object) -> object:
    return _retention_mapping_items(value) is not None


def _is_mutable_retention_dict(value: object) -> object:
    if type(value) is dict:
        return True
    if not isinstance(value, dict):
        return False
    return _retention_mapping_items(value) is not None


def _positive_int_from_text(text: object) -> object:
    text = str.strip(text)
    if text == "" or len(text) > PLR2004N32 or not text.isdecimal():
        return None
    parsed = int(text, 10)
    return parsed if parsed > 0 else None


def _primitive_positive_int(value: object, default: object) -> object:
    if type(default) is not int or default <= 0:
        default = 1
    if value is None or type(value) is bool:
        return default
    if type(value) is int:
        return value if value > 0 else default
    if type(value) is float:
        return int(value) if math.isfinite(value) and value > 0 else default
    if type(value) is str:
        parsed = _positive_int_from_text(str.__str__(value))
        return parsed if parsed is not None else default
    if type(value) is bytes:
        parsed = _positive_int_from_text(bytes.decode(value, 'utf-8', 'replace'))
        return parsed if parsed is not None else default
    return default


def _retention_limit_value(value: object) -> object:
    if type(value) is bool or value is None:
        return None
    if type(value) is int:
        return value if value > 0 else None
    if type(value) is float:
        return int(value) if math.isfinite(value) and value > 0 else None
    if type(value) is str:
        return _positive_int_from_text(str.__str__(value))
    if type(value) is bytes:
        return _positive_int_from_text(bytes.decode(value, 'utf-8', 'replace'))
    return None


def _retention_prefer_high(value: object) -> object:
    if type(value) is bool:
        return value
    if type(value) is int:
        return value != 0
    return True


MAX_STAGED_BENIGN_CANDIDATES = _primitive_positive_int(get_init_value('MAX_STAGED_BENIGN_CANDIDATES'), 5000)
MAX_PROFILE_TAGS_PER_EXTENSION = _primitive_positive_int(get_init_value('MAX_PROFILE_TAGS_PER_EXTENSION'), 2500)
MAX_PROFILE_CHAINS = _primitive_positive_int(get_init_value('MAX_PROFILE_CHAINS'), 2500)
MAX_PROFILE_BUCKET_TAGS = _primitive_positive_int(get_init_value('MAX_PROFILE_BUCKET_TAGS'), 1200)
MAX_PROFILE_TIMELINE_EVENTS = _primitive_positive_int(get_init_value('MAX_PROFILE_TIMELINE_EVENTS'), 2500)
MAX_PROFILE_TIMELINE_TRANSITIONS = _primitive_positive_int(get_init_value('MAX_PROFILE_TIMELINE_TRANSITIONS'), 5000)
MAX_EXTENSION_BASELINES_PER_ENGINE = _primitive_positive_int(get_init_value('MAX_EXTENSION_BASELINES_PER_ENGINE'), 512)
MAX_COUNTER_KEYS = _primitive_positive_int(get_init_value('MAX_COUNTER_KEYS'), 10000)


def _dict_get(value: object, key: object, default: object=None) -> object:
    items = _retention_mapping_items(value)
    if items is not None:
        for item_key, item_value in items:
            if type(item_key) is str and str.__eq__(item_key, key) is True:
                return item_value
    return default


def _dict_set(value: object, key: object, item: object) -> object:
    if _is_mutable_retention_dict(value):
        dict.__setitem__(value, key, item)
    return True


def _dict_setdefault(value: object, key: object, default: object) -> object:
    if not _is_mutable_retention_dict(value):
        return default
    sentinel = object()
    existing = _dict_get(value, key, sentinel)
    if existing is sentinel:
        dict.__setitem__(value, key, default)
        return default
    return existing


def _dict_values(value: object) -> object:
    items = _retention_mapping_items(value)
    if items is not None:
        return tuple(item_value for _item_key, item_value in items)
    return ()


def _dict_items(value: object) -> object:
    items = _retention_mapping_items(value)
    if items is not None:
        return items
    return ()



def _dict_clear(value: object) -> None:
    if _is_mutable_retention_dict(value):
        dict.clear(value)


def _dict_update(value: object, items: object) -> None:
    if _is_mutable_retention_dict(value):
        dict.update(value, items)


def _dict_pop(value: object, key: object, default: object=None) -> object:
    if _is_mutable_retention_dict(value):
        return dict.pop(value, key, default)
    return default

def _dict_len(value: object) -> object:
    items = _retention_mapping_items(value)
    if items is not None:
        return len(items)
    return 0


def _finite_numeric_value(value: object) -> object:
    if type(value) is int:
        return float(value)
    if type(value) is float:
        return value if math.isfinite(value) else None
    return None


def _max_finite_numeric(*values: object) -> object:
    best = 0.0
    for value in values:
        numeric = _finite_numeric_value(value)
        if numeric is not None and numeric > best:
            best = numeric
    return best


def _retention_candidate_reference_time(candidates: object) -> object:
    best = 0.0
    if _is_retention_mapping(candidates):
        for candidate in _dict_values(candidates):
            if _is_retention_mapping(candidate):
                best = _max_finite_numeric(
                    best,
                    _dict_get(candidate, 'last_seen'),
                    _dict_get(candidate, 'first_seen'),
                    _dict_get(candidate, 'promoted_at'),
                )
    return best


def _retention_baseline_reference_time(baseline: object) -> object:
    if not _is_retention_mapping(baseline):
        return 0.0
    timeline = _dict_get(baseline, 'timeline_baseline', {})
    retention = _dict_get(baseline, 'retention', {})
    candidates = [
        _dict_get(baseline, 'updated'),
        _dict_get(baseline, 'last_updated'),
        _dict_get(retention, 'last_pruned') if _is_retention_mapping(retention) else None,
        _dict_get(baseline, 'files'),
    ]
    if _is_retention_mapping(timeline):
        candidates.extend((_dict_get(timeline, 'last_updated'), _dict_get(timeline, 'sample_count')))
    vector = _dict_get(baseline, 'vector_baseline', {})
    if _is_retention_mapping(vector):
        candidates.append(_dict_get(vector, 'count'))
    learning_gate = _dict_get(baseline, 'learning_gate', {})
    if _is_retention_mapping(learning_gate):
        candidates.extend((_dict_get(learning_gate, 'accepted'), _dict_get(learning_gate, 'rejected')))
    return _max_finite_numeric(*candidates)


def _retention_profile_reference_time(profile: object) -> object:
    if not _is_retention_mapping(profile):
        return 0.0
    candidates = [_dict_get(profile, 'updated'), _dict_get(profile, 'created')]
    retention = _dict_get(profile, 'retention', {})
    if _is_retention_mapping(retention):
        candidates.append(_dict_get(retention, 'last_pruned'))
    exts = _dict_get(profile, 'extension_baselines', {})
    if _is_retention_mapping(exts):
        candidates.extend(_retention_baseline_reference_time(baseline) for baseline in _dict_values(exts))
    return _max_finite_numeric(*candidates)


def _counter_value(value: object) -> object:
    numeric = _finite_numeric_value(value)
    if numeric is not None:
        return numeric
    if _is_retention_mapping(value):
        total = 0.0
        for item in _dict_values(value):
            nested_numeric = _finite_numeric_value(item)
            if nested_numeric is not None:
                total += nested_numeric
        return total
    return 0.0


def _safe_bytes_text(value: object) -> object:
    if type(value) is bytes:
        return bytes.decode(value, 'latin1', errors='ignore')
    if type(value) is bytearray:
        return bytes(value).decode('latin1', errors='ignore')
    if type(value) is memoryview:
        return bytes(value).decode('latin1', errors='ignore')
    return None


def _retention_exact_text(value: object) -> object:
    if value is None:
        return ''
    if type(value) is str:
        return ''.join((str.__str__(value),))
    bytes_text = _safe_bytes_text(value)
    if bytes_text is not None:
        return bytes_text
    if type(value) is bool:
        return 'True' if value else 'False'
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value) if math.isfinite(value) else 'retention_non_finite_float'
    text, reason = no_hook_text(value, missing_reason='', unsupported_reason='retention_text_unavailable')
    if reason == '':
        return text
    return 'retention_text_unavailable:' + _retention_type_label(value)


def _retention_sequence_items(value: object) -> object:
    try:
        if isinstance(value, tuple):
            return tuple(tuple.__iter__(value))
        if isinstance(value, list):
            return tuple(list.__iter__(value))
        if isinstance(value, set):
            return tuple(set.__iter__(value))
        if isinstance(value, frozenset):
            return tuple(frozenset.__iter__(value))
    except RETENTION_TEXT_ERRORS:
        return ()
    return None


def _retention_key_text(value: object) -> object:
    try:
        items = _retention_sequence_items(value)
        if items is not None:
            return '(' + ','.join(sorted(_retention_key_text(item) for item in items)) + ')'
        return _retention_exact_text(value)
    except RETENTION_TEXT_ERRORS:
        return 'retention_text_unavailable:' + _retention_type_label(value)


def prune_counter_map(counter: object, limit: object, *, prefer_high: object=True) -> object:
    """Keep a mapping bounded by count/weight, preserving highest-value entries."""
    try:
        numeric_limit = _retention_limit_value(limit)
        if not _is_mutable_retention_dict(counter) or numeric_limit is None or _dict_len(counter) <= numeric_limit:
            return counter
        items = _dict_items(counter)
        if _retention_prefer_high(prefer_high):
            keep = sorted(items, key=lambda kv: (-_counter_value(kv[1]), _retention_key_text(kv[0])))[:numeric_limit]
        else:
            keep = sorted(items, key=lambda kv: (_counter_value(kv[1]), _retention_key_text(kv[0])))[:numeric_limit]
        dict.clear(counter)
        dict.update(counter, dict(keep))
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('counter prune failed: retention_prune_failure')
    return counter


def prune_staged_benign_store(store: object) -> object:
    """Bound staged clean candidates by keeping promoted/recent/high-observation entries."""
    try:
        cands = _dict_get(store, 'candidates', {}) if _is_retention_mapping(store) else {}
        if not _is_mutable_retention_dict(cands) or _dict_len(cands) <= MAX_STAGED_BENIGN_CANDIDATES:
            return store

        def cand_rank(item: object) -> object:
            key, c = item
            return (
                -(1 if _dict_get(c, 'promoted') is True else 0),
                -(_finite_numeric_value(_dict_get(c, 'clean_observations', 0)) or 0),
                -(_finite_numeric_value(_dict_get(c, 'last_seen', 0.0)) or 0.0),
                _retention_key_text(key),
            )
        ledger = _dict_get(store, 'observation_ledger', {})
        entries = _dict_get(ledger, 'entries', {}) if _is_retention_mapping(ledger) else {}
        referenced = {
            _retention_key_text(_dict_get(entry, 'candidate_key', ''))
            for entry in _dict_values(entries)
            if _is_retention_mapping(entry)
            and _retention_key_text(_dict_get(entry, 'candidate_key', ''))
        }
        ranked = sorted(_dict_items(cands), key=cand_rank)
        retained = [item for item in ranked if _retention_key_text(item[0]) in referenced]
        retained.extend(
            item for item in ranked
            if _retention_key_text(item[0]) not in referenced
        )
        _dict_set(store, 'candidates', dict(retained[:MAX_STAGED_BENIGN_CANDIDATES]))
        retention = _dict_setdefault(store, 'retention', {})
        if _is_mutable_retention_dict(retention):
            _dict_set(retention, 'staged_candidates_pruned_at', _retention_candidate_reference_time(_dict_get(store, 'candidates', {})))
            _dict_set(retention, 'max_staged_benign_candidates', MAX_STAGED_BENIGN_CANDIDATES)
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('staged benign prune failed: retention_prune_failure')
    return store


def prune_extension_baseline_for_retention(baseline: object) -> object:
    """Bound one extension profile without changing model semantics."""
    try:
        _dict_pop(baseline, 'tags', None)
        chains = _dict_get(baseline, 'chains', {})
        if _is_mutable_retention_dict(chains):
            audit = _dict_get(chains, 'suspicious_audit', {})
            if _is_mutable_retention_dict(audit):
                prune_counter_map(audit, MAX_PROFILE_CHAINS)
        tag_evidence = _dict_get(baseline, 'tag_evidence', {})
        tag_evidence_records = (
            _dict_get(tag_evidence, 'records', {})
            if _is_mutable_retention_dict(tag_evidence) else {}
        )
        if (
            _is_mutable_retention_dict(tag_evidence_records)
            and _dict_len(tag_evidence_records) > MAX_PROFILE_TAGS_PER_EXTENSION
        ):
            def tag_evidence_rank(item: object) -> object:
                key, value = item
                score = _counter_value(_dict_get(value, 'observation_count', 0))
                return (-score, _retention_key_text(key))
            ranked = sorted(
                _dict_items(tag_evidence_records), key=tag_evidence_rank,
            )[:MAX_PROFILE_TAGS_PER_EXTENSION]
            _dict_clear(tag_evidence_records)
            _dict_update(tag_evidence_records, dict(ranked))
        if _is_mutable_retention_dict(tag_evidence):
            allowed_tag_evidence_keys = {
                'schema_version', 'records', 'summary',
            }
            for key, _value in tuple(_dict_items(tag_evidence)):
                if key not in allowed_tag_evidence_keys:
                    _dict_pop(tag_evidence, key, None)
            retained_values = tuple(
                value for value in _dict_values(tag_evidence_records)
                if _is_retention_mapping(value)
            )
            summary = _dict_setdefault(tag_evidence, 'summary', {})
            if _is_mutable_retention_dict(summary):
                roots = {
                    _retention_key_text(_dict_get(value, 'root_observation_id', ''))
                    for value in retained_values
                    if _retention_key_text(_dict_get(value, 'root_observation_id', ''))
                }
                tags = {
                    _retention_key_text(_dict_get(value, 'publication_name', ''))
                    for value in retained_values
                    if _retention_key_text(_dict_get(value, 'publication_name', ''))
                }
                groups = {
                    _retention_key_text(_dict_get(value, 'correlation_group', ''))
                    for value in retained_values
                    if _retention_key_text(_dict_get(value, 'correlation_group', ''))
                }
                _dict_set(summary, 'raw_observation_count', len(roots))
                _dict_set(summary, 'canonical_tag_count', len(tags))
                _dict_set(summary, 'distinct_correlation_group_count', len(groups))
                _dict_set(summary, 'derived_composite_count', sum(
                    _dict_get(value, 'evidence_kind', '') in {'derived', 'composite'}
                    for value in retained_values
                ))
                _dict_set(summary, 'scoreable_family_count', len({
                    _retention_key_text(_dict_get(value, 'correlation_group', ''))
                    for value in retained_values
                    if _dict_get(value, 'scoreability_class', '') in {'scoreable', 'composite'}
                    and _dict_get(value, 'polarity', '') == 'positive'
                    and _retention_key_text(_dict_get(value, 'correlation_group', ''))
                }))
                _dict_set(summary, 'suppressed_negative_count', sum(
                    _dict_get(value, 'evidence_kind', '') == 'suppression'
                    or _dict_get(value, 'polarity', '') == 'negative'
                    for value in retained_values
                ))
                _dict_set(summary, 'failure_count', sum(
                    _dict_get(value, 'evidence_kind', '') == 'failure'
                    for value in retained_values
                ))
        for bucket in list(_dict_values(_dict_setdefault(baseline, 'behavior_buckets', {}))):
            if _is_mutable_retention_dict(bucket):
                _dict_pop(bucket, 'tags', None)
                ev = _dict_setdefault(bucket, 'evidence', {})
                if _is_mutable_retention_dict(ev):
                    prune_counter_map(ev, MAX_PROFILE_BUCKET_TAGS)
        tb = _dict_setdefault(baseline, 'timeline_baseline', {})
        prune_counter_map(_dict_setdefault(tb, 'event_counts', {}), MAX_PROFILE_TIMELINE_EVENTS)
        prune_counter_map(_dict_setdefault(tb, 'transition_counts', {}), MAX_PROFILE_TIMELINE_TRANSITIONS)
        prune_counter_map(_dict_setdefault(tb, 'behavior_counts', {}), MAX_PROFILE_TIMELINE_EVENTS)
        prune_counter_map(_dict_setdefault(tb, 'behavior_transition_counts', {}), MAX_PROFILE_TIMELINE_TRANSITIONS)
        vb = _dict_setdefault(baseline, 'vector_baseline', {})
        if _is_mutable_retention_dict(vb):
            for raw_key in ('vectors', 'samples', 'raw_vectors'):
                try:
                    _dict_pop(vb, raw_key, None)
                except RETENTION_TEXT_ERRORS:
                    continue
        retention = _dict_setdefault(baseline, 'retention', {})
        if _is_mutable_retention_dict(retention):
            _dict_set(retention, 'last_pruned', _retention_baseline_reference_time(baseline))
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('extension baseline prune failed: retention_prune_failure')
    return baseline


def prune_engine_profile_for_retention(profile: object) -> object:
    """Bound one engine profile snapshot before authoritative persistence."""
    try:
        exts = _dict_setdefault(profile, 'extension_baselines', {})
        if _is_mutable_retention_dict(exts) and _dict_len(exts) > MAX_EXTENSION_BASELINES_PER_ENGINE:
            def ext_rank(item: object) -> object:
                key, b = item
                return (
                    -(_finite_numeric_value(_dict_get(b, 'files', 0)) or 0),
                    -(_finite_numeric_value(_dict_get(b, 'updated', _dict_get(b, 'last_updated', 0.0))) or 0.0),
                    _retention_key_text(key),
                )
            kept = dict(sorted(_dict_items(exts), key=ext_rank)[:MAX_EXTENSION_BASELINES_PER_ENGINE])
            _dict_clear(exts)
            _dict_update(exts, kept)
        for baseline in list(_dict_values(exts)):
            if _is_mutable_retention_dict(baseline):
                prune_extension_baseline_for_retention(baseline)
        ms = _dict_setdefault(profile, 'model_state', {})
        for name in ('vector_baselines', 'temporal_baselines', 'markov_baselines', 'cluster_baselines', 'learning_rejections', 'learning_transactions'):
            obj = _dict_setdefault(ms, name, {})
            if _is_mutable_retention_dict(obj):
                prune_counter_map(obj, MAX_COUNTER_KEYS)
        retention = _dict_setdefault(profile, 'retention', {})
        if _is_mutable_retention_dict(retention):
            _dict_set(retention, 'last_pruned', _retention_profile_reference_time(profile))
            _dict_update(retention, {'max_extension_baselines_per_engine': MAX_EXTENSION_BASELINES_PER_ENGINE, 'max_profile_tags_per_extension': MAX_PROFILE_TAGS_PER_EXTENSION, 'max_profile_timeline_transitions': MAX_PROFILE_TIMELINE_TRANSITIONS})
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('engine profile prune failed: retention_prune_failure')
    return profile


__all__ = ('prune_counter_map', 'prune_engine_profile_for_retention', 'prune_extension_baseline_for_retention', 'prune_staged_benign_store')
