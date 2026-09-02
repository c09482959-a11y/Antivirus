"""Shared profile public-input freezing helpers.

This neutral module owns the defensive coercion used by profile API, learning,
and evidence surfaces. It has no dependency on profile persistence or learning
state, preventing caller-owned mutable/hostile objects from crossing profile
model boundaries.
"""

import math
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath

from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_plain_instance_dict

PROFILE_PUBLIC_INPUT_ERRORS = (
    ArithmeticError,
    AttributeError,
    KeyError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    UnicodeError,
    ValueError,
)

_PROFILE_TEXT_FIELDS = ('text', '_text', 'value', '_value')
_PROFILE_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)
PROFILE_TEXT_UNAVAILABLE = 'profile_text_unavailable'


def _profile_stdlib_path_text(value: object) -> object:
    if type(value) in _PROFILE_STDLIB_PATH_TYPES:
        return PurePath.as_posix(value)
    return None


def _profile_plain_instance_text(value: object) -> object:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    for field_name in _PROFILE_TEXT_FIELDS:
        field_value = dict.get(data, field_name)
        if isinstance(field_value, str):
            return ''.join((str.__str__(field_value),))
        if type(field_value) is bytes:
            return bytes(field_value).decode('utf-8', 'replace')
        if type(field_value) is bytearray:
            return bytes(field_value).decode('utf-8', 'replace')
    return None


def _profile_exact_text(value: object) -> object:
    if isinstance(value, str):
        return ''.join((str.__str__(value),))
    if type(value) is bytes:
        return bytes(value).decode('utf-8', 'replace')
    if type(value) is bytearray:
        return bytes(value).decode('utf-8', 'replace')
    if type(value) is bool:
        return 'true' if value else 'false'
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float and math.isfinite(value):
        return float.__str__(value)
    path_text = _profile_stdlib_path_text(value)
    if path_text is not None:
        return path_text
    text_field = _profile_plain_instance_text(value)
    if text_field is not None:
        return text_field
    raise TypeError('unsupported_profile_text_type')


def profile_safe_text(value: object, *, replacement: object='') -> object:
    """Return bounded text for public profile model evidence."""
    try:
        replacement_text = _profile_exact_text(replacement).strip()
    except PROFILE_PUBLIC_INPUT_ERRORS:
        replacement_text = PROFILE_TEXT_UNAVAILABLE
    if value is None:
        return replacement_text
    try:
        text = _profile_exact_text(value).strip()
    except PROFILE_PUBLIC_INPUT_ERRORS:
        return replacement_text if replacement_text != '' else PROFILE_TEXT_UNAVAILABLE
    return text or replacement_text


def _profile_public_sequence(value: object, reason: object) -> object:
    """Freeze public profile sequence input without caller-owned iteration."""
    if value is None:
        return (), None
    if type(value) in (str, bytes, bytearray, bool, int, float):
        return (value,), None
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value), None
    return (), reason


def profile_owned_key_matches(key: object, name: object) -> object:
    """Compare profile-owned mapping keys without caller-owned equality hooks."""
    if key is name:
        return True
    key_type = type(key)
    if key_type is not type(name):
        return False
    if key_type is str:
        return str.__eq__(key, name) is True
    if key_type is bytes:
        return bytes.__eq__(key, name) is True
    if key_type is bool:
        return bool.__eq__(key, name) is True
    if key_type is int:
        return int.__eq__(key, name) is True
    if key_type is float:
        return math.isfinite(key) and math.isfinite(name) and float.__eq__(key, name) is True
    return False


def profile_mapping_items(value: object) -> object:
    """Return owned profile mapping items without invoking mapping methods."""
    return no_hook_mapping_items(value, allow_dict_subclass=True)


def profile_mapping_get(value: object, key: object, default: object=None) -> object:
    """Read a profile mapping field without caller-owned key equality or get hooks."""
    items = profile_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if profile_owned_key_matches(item_key, key):
            return item_value
    return default


def profile_mapping_copy(value: object) -> object:
    """Copy exact-string-key profile records without invoking mapping protocols."""
    items = profile_mapping_items(value)
    if items is None:
        return None
    copied = {}
    for key, item in items:
        if type(key) is str:
            copied[str.__str__(key)] = item
    return copied


def profile_has_mapping(value: object) -> object:
    return profile_mapping_items(value) is not None


def profile_ratio(numerator: object, denominator: object) -> object:
    denominator_value = profile_finite_float(denominator, 0.0)
    if denominator_value <= 0.0:
        return 0.0
    metric = profile_finite_float(numerator, 0.0) / denominator_value
    if metric < 0.0:
        return 0.0
    if metric > 1.0:
        return 1.0
    return metric


def profile_nested_metric(mapping: object, outer_key: object, inner_key: object, default: object=0.0) -> object:
    nested = profile_mapping_get(mapping, outer_key, {})
    return profile_ratio(profile_mapping_get(nested, inner_key, default), 1.0)


def profile_model_failure_records(value: object) -> object:
    failures, failures_unavailable = profile_iterable_items(
        value,
        'malformed_profile_model_failures',
    )
    if failures_unavailable is not None:
        return ()
    records = []
    for failure in failures:
        copied = profile_mapping_copy(failure)
        if copied is not None:
            records.append(copied)
    return tuple(records)


def _profile_owned_mapping(value: object) -> object:
    if profile_mapping_items(value) is not None:
        return value
    return None


def profile_public_tags(value: object, reason: object='malformed_profile_tags') -> object:
    if type(value) is TagEvidence:
        return tuple(value.tags), None
    mapping = _profile_owned_mapping(value)
    if mapping is not None:
        items = mapping
    else:
        items, unavailable = _profile_public_sequence(value, reason)
        if unavailable:
            return (), unavailable
    try:
        return tuple(ordered_unique_tags(items)), None
    except PROFILE_PUBLIC_INPUT_ERRORS:
        return (), reason


def profile_public_yara_hits(value: object, reason: object='malformed_profile_yara_hits') -> object:
    items, unavailable = _profile_public_sequence(value, reason)
    if unavailable:
        return (), unavailable
    normalized = []
    for index, item in enumerate(items):
        text = profile_safe_text(item, replacement='<unreadable_yara_hit_' + int.__str__(index) + '>')
        normalized.append(text)
    return tuple(normalized), None


def profile_public_ordered_events(value: object, reason: object='malformed_ordered_profile_events') -> object:
    mapping = _profile_owned_mapping(value)
    if mapping is not None:
        return (mapping,), None
    items, unavailable = _profile_public_sequence(value, reason)
    if unavailable:
        return (), unavailable
    return items, None



def profile_public_path_text(value: object, reason: object='profile_public_path_invalid', *, replacement: object='') -> object:
    """Return profile path text plus an explicit rejection reason for unsafe inputs.

    This is the profile-model path boundary: exact primitives, stdlib paths, and
    owned plain-instance text fields are accepted by ``profile_safe_text``.
    Unknown public objects that cannot be read without caller-owned hooks are
    rejected instead of being collapsed to an empty extension bucket.
    """
    try:
        replacement_text = _profile_exact_text(replacement).strip()
    except PROFILE_PUBLIC_INPUT_ERRORS:
        replacement_text = ''
    if value is None:
        return replacement_text, None
    try:
        text = _profile_exact_text(value).strip()
    except PROFILE_PUBLIC_INPUT_ERRORS:
        return replacement_text, profile_safe_text(reason, replacement='profile_public_path_invalid')
    if text != '':
        return text, None
    if type(value) in (str, bytes, bytearray):
        return replacement_text, None
    return replacement_text, profile_safe_text(reason, replacement='profile_public_path_invalid')

def profile_flag_enabled(value: object) -> object:
    """Return True only for explicit True without probing hostile truthiness."""
    return value is True


def profile_first_reason(*values: object, replacement: object='profile_unavailable') -> object:
    """Return the first non-empty reason text without boolean-probing inputs."""
    for value in values:
        if value is None:
            continue
        text = profile_safe_text(value, replacement='')
        if text != '':
            return text
    if replacement == '':
        return ''
    return profile_safe_text(replacement, replacement='profile_unavailable')


def profile_iterable_items(value: object, reason: object='malformed_profile_iterable') -> object:
    """Freeze an optional iterable without caller-owned truthiness."""
    items, unavailable = _profile_public_sequence(value, reason)
    return items, unavailable


def profile_finite_float(value: object, default: object = 0.0) -> object:
    if type(value) is bool:
        return default
    if type(value) is int:
        numeric = float(value)
    elif type(value) is float:
        numeric = value
    elif isinstance(value, str):
        try:
            numeric = float(str.__str__(value).strip())
        except PROFILE_PUBLIC_INPUT_ERRORS:
            return default
    elif type(value) is bytes:
        try:
            numeric = float(bytes.decode(value, 'utf-8', 'replace').strip())
        except PROFILE_PUBLIC_INPUT_ERRORS:
            return default
    elif type(value) is bytearray:
        try:
            numeric = float(bytes(value).decode('utf-8', 'replace').strip())
        except PROFILE_PUBLIC_INPUT_ERRORS:
            return default
    else:
        return default
    return numeric if math.isfinite(numeric) else default


def profile_int(value: object, default: object = 0) -> object:
    if type(value) is bool:
        return default
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return int(value) if value.is_integer() else default
    if isinstance(value, str):
        try:
            return int(str.__str__(value).strip())
        except PROFILE_PUBLIC_INPUT_ERRORS:
            return default
    if type(value) is bytes:
        try:
            return int(bytes.decode(value, 'utf-8', 'replace').strip())
        except PROFILE_PUBLIC_INPUT_ERRORS:
            return default
    if type(value) is bytearray:
        try:
            return int(bytes(value).decode('utf-8', 'replace').strip())
        except PROFILE_PUBLIC_INPUT_ERRORS:
            return default
    return default


__all__ = (
    'PROFILE_PUBLIC_INPUT_ERRORS',
    'PROFILE_TEXT_UNAVAILABLE',
    'profile_finite_float',
    'profile_first_reason',
    'profile_flag_enabled',
    'profile_has_mapping',
    'profile_int',
    'profile_iterable_items',
    'profile_mapping_copy',
    'profile_mapping_get',
    'profile_mapping_items',
    'profile_model_failure_records',
    'profile_nested_metric',
    'profile_owned_key_matches',
    'profile_public_ordered_events',
    'profile_public_path_text',
    'profile_public_tags',
    'profile_public_yara_hits',
    'profile_ratio',
    'profile_safe_text',
)
