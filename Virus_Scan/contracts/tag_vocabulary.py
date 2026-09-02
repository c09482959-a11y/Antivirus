"""Neutral immutable tag-vocabulary contract shared across domains."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

TAG_VOCABULARY_VERSION = "tag_vocabulary_v1"

_DEFAULT_CANONICAL_TAG_ALIAS_ITEMS: tuple[tuple[str, str], ...] = (
    ('activator_createinstance', 'reflection'),
    ('assembly_load_bytes', 'assembly_load'),
    ('assembly_loadfile', 'assembly_load'),
    ('assembly_loadfrom', 'assembly_load'),
    ('base64_decode', 'payload_decode_candidate'),
    ('browser_credential_theft', 'browser_credential_access'),
    ('browser_password_store_access', 'browser_credential_access'),
    ('c2_connection', 'network_c2'),
    ('c2_or_remote_command', 'remote_command_channel'),
    ('chrome_login_data_access', 'browser_credential_access'),
    ('create_remote_thread', 'thread_execution'),
    ('decoded_payload_observed', 'payload_decode_candidate'),
    ('download_file', 'network_download'),
    ('dpapi_credential_access', 'dpapi_access'),
    ('firefox_login_data_access', 'browser_credential_access'),
    ('http_download', 'network_download'),
    ('jscript_execution', 'javascript_execution'),
    ('load_from_bytes', 'assembly_load'),
    ('methodinfo_invoke', 'reflection'),
    ('network_url', 'url_present'),
    ('payload_decode', 'payload_decode_candidate'),
    ('powershell_encoded', 'encoded_powershell'),
    ('reflection_invoke', 'reflection'),
    ('registry_run_key', 'run_key_mod'),
    ('remote_thread_create', 'thread_execution'),
    ('scheduled_task', 'schtasks_create'),
    ('scheduled_task_create', 'schtasks_create'),
    ('schtasks', 'schtasks_create'),
    ('url_download', 'network_download'),
    ('write_process_memory', 'memory_write'),
)
_DEFAULT_TAG_ALIAS_REPORTING_ITEMS: tuple[tuple[str, str], ...] = ()


def _validate_synonym_items(values: object) -> Mapping[str, str]:
    if type(values) is not tuple:
        raise TypeError("tag vocabulary synonyms must be an exact tuple")
    normalized: dict[str, str] = {}
    for item in values:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError("tag vocabulary synonym entries must be exact pairs")
        source, target = item
        if type(source) is not str or type(target) is not str or not source or not target:
            raise ValueError("tag vocabulary synonyms require non-empty exact strings")
        if source in normalized and normalized[source] != target:
            raise ValueError("conflicting tag vocabulary synonym")
        normalized[source] = target
    for source in normalized:
        seen: set[str] = set()
        current = source
        while current in normalized:
            if current in seen:
                raise ValueError("cyclic tag vocabulary synonym graph")
            seen.add(current)
            current = normalized[current]
    return MappingProxyType(dict(sorted(normalized.items())))


DEFAULT_CANONICAL_TAG_ALIASES: Mapping[str, str] = _validate_synonym_items(
    _DEFAULT_CANONICAL_TAG_ALIAS_ITEMS
)
DEFAULT_TAG_ALIAS_REPORTING_MAP: Mapping[str, str] = _validate_synonym_items(
    _DEFAULT_TAG_ALIAS_REPORTING_ITEMS
)


def canonical_synonym_target(value: str) -> str:
    """Resolve one exact canonical spelling through the validated synonym graph."""
    if type(value) is not str or not value:
        return ""
    current = value
    seen: set[str] = set()
    while current in DEFAULT_CANONICAL_TAG_ALIASES:
        if current in seen:
            raise RuntimeError("validated tag vocabulary became cyclic")
        seen.add(current)
        current = DEFAULT_CANONICAL_TAG_ALIASES[current]
    return current


def tag_vocabulary_manifest() -> dict[str, object]:
    return {
        "version": TAG_VOCABULARY_VERSION,
        "synonym_count": len(DEFAULT_CANONICAL_TAG_ALIASES),
        "reporting_alias_count": len(DEFAULT_TAG_ALIAS_REPORTING_MAP),
        "synonyms": tuple(DEFAULT_CANONICAL_TAG_ALIASES.items()),
        "reporting_aliases": tuple(DEFAULT_TAG_ALIAS_REPORTING_MAP.items()),
    }


__all__ = (
    "DEFAULT_CANONICAL_TAG_ALIASES",
    "DEFAULT_TAG_ALIAS_REPORTING_MAP",
    "TAG_VOCABULARY_VERSION",
    "canonical_synonym_target",
    "tag_vocabulary_manifest",
)
