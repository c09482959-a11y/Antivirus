"""Exact identity contract for one model-context projection generation."""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot


MODEL_PROJECTION_IDENTITY_SCHEMA_VERSION: Final[str] = (
    "stage2636_11020_model_projection_identity_v1"
)
_PROJECTION_IDENTITY_KEYS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "scan_session_generation_id",
    "configuration_digest",
    "model_state",
    "model_state_digest",
    "model_database_generation",
    "model_database_schema_digest",
    "feature_registry_state",
    "feature_registry_digest",
    "detection_registry_digest",
    "tag_taxonomy_version",
    "tag_taxonomy_digest",
    "chain_registry_version",
    "chain_registry_digest",
})
_HEX: Final[frozenset[str]] = frozenset("0123456789abcdef")
_STATES: Final[frozenset[str]] = frozenset({"available", "partial", "disabled", "unavailable"})


def _text(value: object, field_name: str, *, allow_blank: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(field_name + "_invalid")
    text = str.__str__(value)
    if not allow_blank and text == "":
        raise ValueError(field_name + "_invalid")
    return text


def _digest(value: object, field_name: str, *, allow_blank: bool = False) -> str:
    text = _text(value, field_name, allow_blank=allow_blank)
    if text == "" and allow_blank:
        return text
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(field_name + "_invalid")
    return text


def model_projection_identity(
    scan_session_snapshot: ScanSessionSnapshot,
) -> Mapping[str, str]:
    """Project exact model/registry/configuration dependencies from one session."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("model_projection_scan_session_snapshot_required")
    return require_model_projection_identity({
        "schema_version": MODEL_PROJECTION_IDENTITY_SCHEMA_VERSION,
        "scan_session_generation_id": scan_session_snapshot.generation_id,
        "configuration_digest": scan_session_snapshot.configuration_digest,
        "model_state": scan_session_snapshot.model_state,
        "model_state_digest": scan_session_snapshot.model_state_digest,
        "model_database_generation": scan_session_snapshot.model_database_generation,
        "model_database_schema_digest": scan_session_snapshot.model_database_schema_digest,
        "feature_registry_state": scan_session_snapshot.feature_registry_state,
        "feature_registry_digest": scan_session_snapshot.feature_registry_digest,
        "detection_registry_digest": scan_session_snapshot.detection_registry_digest,
        "tag_taxonomy_version": scan_session_snapshot.tag_taxonomy_version,
        "tag_taxonomy_digest": scan_session_snapshot.tag_taxonomy_digest,
        "chain_registry_version": scan_session_snapshot.chain_registry_version,
        "chain_registry_digest": scan_session_snapshot.chain_registry_digest,
    })


def require_model_projection_identity(value: object) -> Mapping[str, str]:
    """Validate and freeze an exact current-schema projection dependency identity."""
    if type(value) is dict:
        data = dict(value)
    elif type(value) is MappingProxyType:
        data = dict(value)
    elif isinstance(value, Mapping):
        raise TypeError("model_projection_identity_owner_invalid")
    else:
        raise TypeError("model_projection_identity_required")
    if frozenset(data) != _PROJECTION_IDENTITY_KEYS:
        raise ValueError("model_projection_identity_keys_invalid")
    schema_version = _text(data["schema_version"], "model_projection_projection_schema_version")
    if schema_version != MODEL_PROJECTION_IDENTITY_SCHEMA_VERSION:
        raise ValueError("model_projection_identity_schema_invalid")
    model_state = _text(data["model_state"], "model_projection_model_state")
    feature_state = _text(data["feature_registry_state"], "model_projection_feature_registry_state")
    if model_state not in _STATES or feature_state not in _STATES:
        raise ValueError("model_projection_projection_state_invalid")
    model_identity_required = model_state in {"available", "partial"}
    feature_identity_required = feature_state in {"available", "partial"}
    validated = {
        "schema_version": schema_version,
        "scan_session_generation_id": _digest(
            data["scan_session_generation_id"], "model_projection_scan_session_generation_id",
        ),
        "configuration_digest": _digest(
            data["configuration_digest"], "model_projection_configuration_digest",
        ),
        "model_state": model_state,
        "model_state_digest": _digest(
            data["model_state_digest"], "model_projection_model_state_digest",
            allow_blank=not model_identity_required,
        ),
        "model_database_generation": _digest(
            data["model_database_generation"], "model_projection_model_database_generation",
            allow_blank=not model_identity_required,
        ),
        "model_database_schema_digest": _digest(
            data["model_database_schema_digest"], "model_projection_model_database_schema_digest",
            allow_blank=not model_identity_required,
        ),
        "feature_registry_state": feature_state,
        "feature_registry_digest": _digest(
            data["feature_registry_digest"], "model_projection_feature_registry_digest",
            allow_blank=not feature_identity_required,
        ),
        "detection_registry_digest": _digest(
            data["detection_registry_digest"], "model_projection_detection_registry_digest",
        ),
        "tag_taxonomy_version": _text(
            data["tag_taxonomy_version"], "model_projection_tag_taxonomy_version",
        ),
        "tag_taxonomy_digest": _digest(
            data["tag_taxonomy_digest"], "model_projection_tag_taxonomy_digest",
        ),
        "chain_registry_version": _text(
            data["chain_registry_version"], "model_projection_chain_registry_version",
        ),
        "chain_registry_digest": _digest(
            data["chain_registry_digest"], "model_projection_chain_registry_digest",
        ),
    }
    return MappingProxyType(validated)


__all__ = (
    "MODEL_PROJECTION_IDENTITY_SCHEMA_VERSION",
    "require_model_projection_identity",
    "model_projection_identity",
)
