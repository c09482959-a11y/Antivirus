from types import MappingProxyType
import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.models.clustering.feature_registry import VECTOR_FEATURE_NAMES

CLUSTER_HALF_LIFE_SEC = float(runtime_value('CLUSTER_HALF_LIFE_SEC', 604800.0))
MIN_CLUSTER_MEMBERS_FOR_CONTEXT = int(runtime_value('MIN_CLUSTER_MEMBERS_FOR_CONTEXT', 3))
MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT = float(runtime_value('MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT', 0.35))
_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))

def finite_cluster_metric(value: object, default: object=0.0) -> object:
    candidate = default if value is None else value
    if type(candidate) is bool:
        return float(default)
    if type(candidate) is int:
        metric = float(candidate)
    elif type(candidate) is float:
        metric = candidate
    elif isinstance(candidate, str):
        try:
            metric = float(str.__str__(candidate).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return float(default)
    elif type(candidate) is bytes:
        try:
            metric = float(bytes.decode(candidate, 'utf-8', 'replace').strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return float(default)
    elif type(candidate) is bytearray:
        try:
            metric = float(bytes(candidate).decode('utf-8', 'replace').strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return float(default)
    else:
        return float(default)
    if not math.isfinite(metric):
        return float(default)
    return metric

def _cluster_exact_text(value: object) -> object:
    """Detach text into an exact built-in str before strip/truth checks."""
    text, reason = no_hook_text(
        value,
        missing_reason='unsupported_cluster_text_type',
        unsupported_reason='unsupported_cluster_text_type',
    )
    if reason == '':
        return text
    raise TypeError(reason)

def safe_cluster_text(value: object, *, default_text: object='') -> object:
    """Return exact detached text without probing caller-owned truthiness."""
    try:
        replacement_text = _cluster_exact_text(default_text) if default_text is not None else ''
    except RECOVERABLE_RUNTIME_ERRORS:
        replacement_text = ''
    if value is None:
        return replacement_text
    try:
        text = _cluster_exact_text(value).strip()
    except RECOVERABLE_RUNTIME_ERRORS:
        return replacement_text
    if text == '':
        return replacement_text
    return text

def cluster_input_sequence(value: object, *, reason: object) -> object:
    """Return owned primitive containers without invoking caller ``__iter__``."""
    if value is None:
        return (), None
    if isinstance(value, (str, bytes)) or type(value) is bytearray:
        return (value,), None
    if isinstance(value, tuple):
        return tuple(tuple.__iter__(value)), None
    if isinstance(value, list):
        return tuple(list.__iter__(value)), None
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(set.__iter__(value) if isinstance(value, set) else frozenset.__iter__(value), key=lambda item: safe_cluster_text(item, default_text=''))), None
    return (), reason

def cluster_text_sequence(value: object, *, reason: object) -> object:
    items, seq_reason = cluster_input_sequence(value, reason=reason)
    if seq_reason is not None:
        return (), seq_reason
    out = []
    for item in items:
        text = safe_cluster_text(item)
        if text == '':
            return (), reason
        out.append(text)
    return tuple(out), None

def cluster_mapping(value: object, *, reason: object=None) -> object:
    """Return owned mappings without invoking caller mapping hooks.

    """
    if value is None:
        return {}, None
    items = no_hook_mapping_items(value)
    if items is None:
        return {}, reason
    return {key: item for key, item in items}, None

def cluster_int_limit(value: object, default: object) -> object:
    """Materialize retention/vector limits without ``value or default`` truthiness."""
    candidate = default if value is None else value
    if type(candidate) is bool:
        return int(default)
    if type(candidate) is int:
        return candidate
    if type(candidate) is float and math.isfinite(candidate):
        return int(candidate)
    if isinstance(candidate, str):
        try:
            return int(str.__str__(candidate).strip())
        except RECOVERABLE_RUNTIME_ERRORS:
            return int(default)
    return int(default)

def cluster_finite_vector(value: object, *, max_dims: object = None) -> tuple[float, ...]:
    """Detach arbitrary vector-like input into finite floats deterministically."""
    items, reason = cluster_input_sequence(value, reason='cluster_vector_input_unavailable')
    if reason:
        return ()
    limit = cluster_int_limit(max_dims, len(items)) if max_dims is not None else len(items)
    if limit < 0:
        return ()
    return tuple(finite_cluster_metric(item, 0.0) for item in items[:limit])

def cluster_text_set(value: object, *, reason: object='cluster_text_set_unavailable') -> object:
    values, seq_reason = cluster_text_sequence(value, reason=reason)
    if seq_reason is not None:
        return set()
    return {
        text.lower()
        for item in values
        if (text := safe_cluster_text(item, default_text='')) != ''
    }

def dominant_engine_context(engine_context: object, default: object='unknown', *, allow_other: object=False) -> object:
    """Return the dominant engine using finite context weights only."""
    allowed = {'unity', 'renpy', 'rpgm', 'media', 'unknown'}
    if allow_other:
        allowed = allowed | {'other'}
    best_engine = safe_cluster_text(default, default_text='unknown').lower()
    if best_engine == '':
        best_engine = 'unknown'
    best_value = -1.0
    context, context_reason = cluster_mapping(engine_context, reason='cluster_engine_context_unavailable')
    items = () if context_reason is not None else dict.items(context)
    for key, raw_value in items:
        engine = safe_cluster_text(key, default_text='').lower()
        if engine == 'other' and not allow_other:
            engine = 'unknown'
        if engine not in allowed:
            continue
        value = finite_cluster_metric(raw_value, 0.0)
        if value > best_value:
            best_engine = engine
            best_value = value
    if best_engine == 'other' and not allow_other:
        return 'unknown'
    if best_engine not in allowed:
        replacement_engine = safe_cluster_text(default, default_text='unknown').lower()
        if replacement_engine == '':
            return 'unknown'
        return replacement_engine
    return best_engine

def cluster_flag_enabled(value: object) -> object:
    """Return True only for explicit True without probing hostile truthiness."""
    return value is True

def cluster_first_reason(*values: object, default_text: object='cluster_unavailable') -> object:
    """Return first non-empty reason text without caller-owned truthiness."""
    for value in values:
        if value is None:
            continue
        text = safe_cluster_text(value, default_text='')
        if text != '':
            return text
    return safe_cluster_text(default_text, default_text='cluster_unavailable')

def cluster_context_float(value: object, default: object=0.0) -> object:
    return finite_cluster_metric(value, default)

__all__ = (
    'CLUSTER_HALF_LIFE_SEC',
    'MIN_CLUSTER_MEMBERS_FOR_CONTEXT',
    'MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT',
    'VECTOR_FEATURE_NAMES',
    'cluster_context_float',
    'cluster_finite_vector',
    'cluster_first_reason',
    'cluster_flag_enabled',
    'cluster_input_sequence',
    'cluster_int_limit',
    'cluster_mapping',
    'cluster_text_sequence',
    'cluster_text_set',
    'dominant_engine_context',
    'finite_cluster_metric',
    'safe_cluster_text',
)
