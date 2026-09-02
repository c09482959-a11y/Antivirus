from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_type_name,
)
from Virus_Scan.runtime.config_state import (
    configure_profile_corruption_policy,
    get_profile_corruption_policy,
)
from Virus_Scan.models.profiles.schema import PROFILE_SCHEMA_VERSION

_PROFILE_TEXT_UNAVAILABLE = 'profile_corruption_text_unavailable'
_PROFILE_TEXT_EMPTY = 'profile_corruption_text_empty'
_PROFILE_VALUE_UNAVAILABLE = 'profile_value_unavailable'
_PROFILE_SCALAR_TYPES = (int, float, bool)
_TEXT_FIELDS = ('text', '_text', 'value', '_value')
_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


def _profile_unavailable_record(reason: str, value: object) -> dict[str, object]:
    return {
        _PROFILE_VALUE_UNAVAILABLE: True,
        'reason': reason,
        'value_type': no_hook_type_name(value),
    }


def _profile_detached_text(value: object) -> str | None:
    if isinstance(value, str):
        return str.__str__(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode('utf-8', errors='replace')
        except RECOVERABLE_RUNTIME_ERRORS:
            return _PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(value)
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return int.__str__(value)
    if isinstance(value, float):
        if math.isfinite(value):
            return float.__str__(value)
        return None
    if type(value) in _STDLIB_PATH_TYPES:
        return PurePath.as_posix(value)
    return None


def _profile_text_from_attrs(value: object) -> str | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    for field_name in _TEXT_FIELDS:
        detached = _profile_detached_text(dict.get(data, field_name))
        if detached is not None:
            return detached
    return None


def _profile_exception_text(value: object) -> str | None:
    if not isinstance(value, BaseException):
        return None
    try:
        args = tuple(value.args)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(value)
    parts: list[str] = []
    for arg in args:
        detached = _profile_detached_text(arg)
        if detached is None:
            detached = _profile_text_from_attrs(arg)
        if detached is not None:
            detached = str.strip(detached)
            if detached != '':
                parts.append(detached)
        else:
            parts.append(_PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(arg))
    if parts:
        return ': '.join(parts)
    return no_hook_type_name(value)


def _profile_boundary_text(
    value: object,
    *,
    default_text: str = '',
    strip: bool = True,
    allow_path: bool = True,
) -> str:
    del allow_path  # Explicitly unused contract parameters.
    default_value_text = str.__str__(default_text) if isinstance(default_text, str) else ''
    try:
        if value is None:
            text = default_value_text
        else:
            detached = _profile_detached_text(value)
            if detached is not None:
                text = detached
            else:
                exception_text = _profile_exception_text(value)
                if exception_text is not None:
                    text = exception_text
                else:
                    attr_text = _profile_text_from_attrs(value)
                    if attr_text is not None:
                        text = attr_text
                    else:
                        text = _PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(value)
        if strip:
            text = str.strip(text)
        if text == '':
            return default_value_text if default_value_text != '' else _PROFILE_TEXT_EMPTY
    except RECOVERABLE_RUNTIME_ERRORS:
        return default_value_text if default_value_text != '' else _PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(value)
    else:
        return text


def _profile_json_key_text(key: object, index: int) -> str:
    text = _profile_boundary_text(
        key,
        default_text=_PROFILE_TEXT_UNAVAILABLE + ':' + no_hook_type_name(key),
        allow_path=True,
    )
    if text == _PROFILE_TEXT_EMPTY:
        text = _PROFILE_TEXT_EMPTY + ':' + int.__str__(index)
    return text


def _profile_json_sort_key(value: object) -> tuple[str, str, str]:
    safe = profile_corruption_json_safe(value)
    try:
        payload = json.dumps(
            safe,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
            allow_nan=False,
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        payload = json.dumps(
            _profile_unavailable_record('unserializable_profile_corruption_value', value),
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
            allow_nan=False,
        )
    return (payload, no_hook_type_name(value), '')


@dataclass(frozen=True, slots=True)
class ProfileCorruptionEvidence:
    engine: str
    profile_path: str
    corruption_type: str
    reason: str
    expected_schema_version: int
    actual_schema_version: object
    policy: str
    quarantined: bool = False
    scan_continued: bool = False

    def to_json(self) -> object:
        event_key = profile_corruption_event_key(
            self.engine,
            self.profile_path,
            self.corruption_type,
            self.reason,
            self.actual_schema_version,
            self.policy,
        )
        content_key = profile_corruption_event_key(
            self.engine,
            self.corruption_type,
            self.reason,
            self.actual_schema_version,
            self.policy,
        )
        return {
            'profile_schema_error': True,
            'engine': self.engine,
            'profile_path': self.profile_path,
            'profile_corruption_type': self.corruption_type,
            'profile_corruption_reason': self.reason,
            'profile_corruption_policy': self.policy,
            'profile_quarantined': bool(self.quarantined),
            'expected_schema_version': self.expected_schema_version,
            'actual_schema_version': profile_corruption_json_safe(self.actual_schema_version),
            'scan_continued': bool(self.scan_continued),
            'profile_corruption_event_key': event_key,
            'profile_corruption_content_key': content_key,
            'timestamp': 0.0,
            'timestamp_source': 'deterministic_profile_corruption_event',
        }


def configure_engine_profile_corruption_policy(policy: object) -> object:
    return configure_profile_corruption_policy(policy)


def profile_corruption_type(reason: object) -> object:
    text = _profile_boundary_text(reason, default_text='', allow_path=False).lower()
    if 'schema_version' in text:
        return 'schema_version'
    if 'extension_baselines' in text:
        return 'extension_baselines'
    if 'model_state' in text:
        return 'model_state'
    if 'engine mismatch' in text:
        return 'engine_mismatch'
    if 'json' in text or 'decode' in text:
        return 'malformed_json'
    return 'schema_contract'


def profile_actual_schema_value(profile: object) -> object:
    if isinstance(profile, Mapping):
        items = no_hook_mapping_items(profile)
        if items is None:
            return _profile_unavailable_record('unreadable_profile_schema_version', profile)
        for key, value in items:
            if type(key) is str and str.__str__(key) == 'schema_version':
                return value
    return None


def _profile_corruption_mapping_json_safe(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return _profile_unavailable_record('unreadable_profile_corruption_mapping_keys', value)
    out: dict[str, object] = {}
    seen_names: dict[str, int] = {}
    for index, item_pair in enumerate(sorted(items, key=lambda pair: _profile_json_sort_key(pair[0]))):
        key, child = item_pair
        base_name = _profile_json_key_text(key, index)
        duplicate_index = seen_names.get(base_name, 0)
        seen_names[base_name] = duplicate_index + 1
        name = base_name if duplicate_index == 0 else base_name + '#' + int.__str__(duplicate_index)
        out[name] = profile_corruption_json_safe(child)
    return out


def _profile_corruption_set_json_safe(value: object) -> object:
    safe_items = [profile_corruption_json_safe(item) for item in value]
    return sorted(
        safe_items,
        key=lambda item: json.dumps(
            item,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
            allow_nan=False,
        ),
    )


def _profile_corruption_float_json_safe(value: float) -> object:
    try:
        if math.isfinite(value):
            return float(value)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _profile_unavailable_record('non_finite_profile_corruption_value', value)
    return {
        _PROFILE_VALUE_UNAVAILABLE: True,
        'reason': 'non_finite_profile_corruption_value',
        'value': float.__str__(value),
    }


def _profile_corruption_scalar_json_safe(value: object) -> object:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        text = _profile_detached_text(value)
        return text if text is not None else _profile_unavailable_record('unreadable_profile_corruption_bytes', value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return _profile_corruption_float_json_safe(value)
    attr_text = _profile_text_from_attrs(value)
    return attr_text if attr_text is not None else _profile_unavailable_record('unsupported_profile_corruption_value', value)


def profile_corruption_json_safe(value: object) -> object:
    """Return deterministic JSON-safe profile-corruption evidence values."""
    if isinstance(value, Mapping):
        return _profile_corruption_mapping_json_safe(value)
    if isinstance(value, (list, tuple)):
        return [profile_corruption_json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return _profile_corruption_set_json_safe(value)
    return _profile_corruption_scalar_json_safe(value)


def profile_corruption_event_key(*parts: object) -> object:
    """Deterministic identity for corrupt-profile evidence."""
    payload = json.dumps(
        [profile_corruption_json_safe(part) for part in parts],
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]


def profile_corruption_path_text(path: object) -> object:
    path_text = _profile_boundary_text(
        path,
        default_text=_PROFILE_TEXT_UNAVAILABLE + ':path',
        allow_path=True,
    )
    return os.path.abspath(path_text).replace("\\", "/")


def profile_corruption_evidence(
    path: object,
    engine: object,
    reason: object,
    *,
    profile: object=None,
    policy: object=None,
    quarantined: object=False,
    scan_continued: object=False,
) -> object:
    return ProfileCorruptionEvidence(
        engine=_profile_boundary_text(engine, default_text='other', allow_path=False),
        profile_path=profile_corruption_path_text(path),
        corruption_type=profile_corruption_type(reason),
        reason=_profile_boundary_text(reason, default_text='profile_corruption_reason_unavailable', allow_path=False),
        expected_schema_version=PROFILE_SCHEMA_VERSION,
        actual_schema_version=profile_actual_schema_value(profile),
        policy=_profile_boundary_text(policy if policy is not None else get_profile_corruption_policy('hard-fail'), default_text='hard-fail', allow_path=False),
        quarantined=quarantined is True,
        scan_continued=scan_continued is True,
    )


__all__ = (
    'ProfileCorruptionEvidence',
    'configure_engine_profile_corruption_policy',
    'profile_actual_schema_value',
    'profile_corruption_event_key',
    'profile_corruption_evidence',
    'profile_corruption_json_safe',
    'profile_corruption_path_text',
    'profile_corruption_type',
)
