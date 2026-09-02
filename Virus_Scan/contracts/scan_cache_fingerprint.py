"""Exact execution identity for durable scan-result cache reuse."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.contracts.yara_hits import (
    YARA_HIT_SCHEMA_VERSION,
    YARA_SCAN_RESULT_SCHEMA_VERSION,
)

SCAN_CACHE_SCHEMA_VERSION = 3
PROFILE_SCHEMA_VERSION = 2
SCAN_CACHE_EXECUTION_IDENTITY_VERSION = "scan_cache_execution_identity_v2"
SCAN_CACHE_RESULT_SCHEMA_VERSION = "scan_cache_result_record_v2"


def _hex_or_blank(value: object, reason: str, *, length: int) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).lower()
    if text == "":
        return ""
    if len(text) != length or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(reason)
    return text


@dataclass(frozen=True, slots=True)
class ScanCacheExecutionIdentity:
    """All dynamic identities that can change a published scan result."""

    session_generation_id: str
    session_state: str
    yara_state: str
    yara_package_kind: str
    yara_source_digest: str
    yara_compiled_cache_digest: str
    yara_rule_catalog_digest: str
    attack_state: str
    attack_alignment_digest: str
    attack_implementation_manifest_digest: str
    attack_policy_digest: str
    attack_policy_version: str
    attack_repository_digest: str
    attack_dataset_version: str
    schema_version: str = SCAN_CACHE_EXECUTION_IDENTITY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ScanCacheExecutionIdentity:
            raise TypeError("scan_cache_execution_identity_owner_invalid")
        session_generation = _hex_or_blank(
            self.session_generation_id,
            "scan_cache_session_generation_invalid",
            length=64,
        )
        if session_generation == "":
            raise ValueError("scan_cache_session_generation_invalid")
        session_state = exact_bounded_text(
            self.session_state,
            "scan_cache_session_state_invalid",
            maximum=32,
        )
        if session_state not in {"available", "unavailable"}:
            raise ValueError("scan_cache_session_state_invalid")
        yara_state = exact_bounded_text(
            self.yara_state,
            "scan_cache_yara_state_invalid",
            maximum=32,
        )
        if yara_state not in {"disabled", "verified", "unavailable"}:
            raise ValueError("scan_cache_yara_state_invalid")
        package = exact_bounded_text(
            self.yara_package_kind,
            "scan_cache_yara_package_invalid",
            maximum=32,
        )
        if package not in {"disabled", "core", "extended", "full", "custom", "unavailable"}:
            raise ValueError("scan_cache_yara_package_invalid")
        source = _hex_or_blank(self.yara_source_digest, "scan_cache_yara_source_digest_invalid", length=64)
        compiled = _hex_or_blank(
            self.yara_compiled_cache_digest,
            "scan_cache_yara_compiled_digest_invalid",
            length=64,
        )
        catalog = _hex_or_blank(
            self.yara_rule_catalog_digest,
            "scan_cache_yara_catalog_digest_invalid",
            length=64,
        )
        if yara_state == "verified":
            if package in {"disabled", "unavailable"} or not (source and compiled and catalog):
                raise ValueError("scan_cache_yara_identity_incomplete")
        elif yara_state == "disabled":
            if package != "disabled" or any((source, compiled, catalog)):
                raise ValueError("scan_cache_yara_disabled_identity_invalid")
        elif package != "unavailable" or any((source, compiled, catalog)):
            raise ValueError("scan_cache_yara_unavailable_identity_invalid")

        attack_state = exact_bounded_text(
            self.attack_state,
            "scan_cache_attack_state_invalid",
            maximum=32,
        )
        if attack_state not in {"disabled", "available", "unavailable"}:
            raise ValueError("scan_cache_attack_state_invalid")
        alignment = _hex_or_blank(
            self.attack_alignment_digest,
            "scan_cache_attack_alignment_digest_invalid",
            length=64,
        )
        implementation = _hex_or_blank(
            self.attack_implementation_manifest_digest,
            "scan_cache_attack_implementation_digest_invalid",
            length=64,
        )
        policy = _hex_or_blank(
            self.attack_policy_digest,
            "scan_cache_attack_policy_digest_invalid",
            length=64,
        )
        if not (alignment and implementation and policy):
            raise ValueError("scan_cache_attack_semantic_identity_incomplete")
        policy_version = exact_bounded_text(
            self.attack_policy_version,
            "scan_cache_attack_policy_version_invalid",
            maximum=128,
        )
        repository = _hex_or_blank(
            self.attack_repository_digest,
            "scan_cache_attack_repository_digest_invalid",
            length=64,
        )
        dataset = _hex_or_blank(
            self.attack_dataset_version,
            "scan_cache_attack_dataset_version_invalid",
            length=40,
        )
        if attack_state == "available":
            if not (repository and dataset):
                raise ValueError("scan_cache_attack_repository_identity_incomplete")
        elif repository or dataset:
            raise ValueError("scan_cache_attack_unavailable_identity_present")
        schema = exact_bounded_text(
            self.schema_version,
            "scan_cache_execution_identity_schema_invalid",
            maximum=128,
        )
        if schema != SCAN_CACHE_EXECUTION_IDENTITY_VERSION:
            raise ValueError("scan_cache_execution_identity_schema_invalid")
        object.__setattr__(self, "session_generation_id", session_generation)
        object.__setattr__(self, "session_state", session_state)
        object.__setattr__(self, "yara_state", yara_state)
        object.__setattr__(self, "yara_package_kind", package)
        object.__setattr__(self, "yara_source_digest", source)
        object.__setattr__(self, "yara_compiled_cache_digest", compiled)
        object.__setattr__(self, "yara_rule_catalog_digest", catalog)
        object.__setattr__(self, "attack_state", attack_state)
        object.__setattr__(self, "attack_alignment_digest", alignment)
        object.__setattr__(self, "attack_implementation_manifest_digest", implementation)
        object.__setattr__(self, "attack_policy_digest", policy)
        object.__setattr__(self, "attack_policy_version", policy_version)
        object.__setattr__(self, "attack_repository_digest", repository)
        object.__setattr__(self, "attack_dataset_version", dataset)
        object.__setattr__(self, "schema_version", schema)

    @property
    def cache_eligible(self) -> bool:
        """Unavailable semantic dependencies must never reuse or publish cache."""
        return (
            self.session_state == "available"
            and self.yara_state != "unavailable"
            and self.attack_state != "unavailable"
        )

    def to_record(self) -> dict[str, object]:
        return {
            "session_generation_id": self.session_generation_id,
            "session_state": self.session_state,
            "attack_alignment_digest": self.attack_alignment_digest,
            "attack_dataset_version": self.attack_dataset_version,
            "attack_implementation_manifest_digest": self.attack_implementation_manifest_digest,
            "attack_policy_digest": self.attack_policy_digest,
            "attack_policy_version": self.attack_policy_version,
            "attack_repository_digest": self.attack_repository_digest,
            "attack_state": self.attack_state,
            "schema_version": self.schema_version,
            "yara_compiled_cache_digest": self.yara_compiled_cache_digest,
            "yara_hit_schema_version": YARA_HIT_SCHEMA_VERSION,
            "yara_package_kind": self.yara_package_kind,
            "yara_rule_catalog_digest": self.yara_rule_catalog_digest,
            "yara_scan_result_schema_version": YARA_SCAN_RESULT_SCHEMA_VERSION,
            "yara_source_digest": self.yara_source_digest,
            "yara_state": self.yara_state,
        }

    def without_session_record(self) -> dict[str, object]:
        """Return semantic YARA/ATT&CK identity without circular session ID."""
        record = self.to_record()
        record.pop("session_generation_id", None)
        return record

    @property
    def digest(self) -> str:
        raw = json.dumps(
            self.to_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()



def scan_cache_execution_identity_from_record(record: object) -> ScanCacheExecutionIdentity:
    """Reconstruct one exact cache identity from an immutable manifest record."""
    if type(record) is not dict:
        raise TypeError("scan_cache_execution_identity_record_invalid")
    expected = {
        "session_generation_id", "session_state",
        "attack_alignment_digest", "attack_dataset_version",
        "attack_implementation_manifest_digest", "attack_policy_digest",
        "attack_policy_version", "attack_repository_digest", "attack_state",
        "schema_version", "yara_compiled_cache_digest", "yara_hit_schema_version",
        "yara_package_kind", "yara_rule_catalog_digest",
        "yara_scan_result_schema_version", "yara_source_digest", "yara_state",
    }
    if set(record) != expected:
        raise ValueError("scan_cache_execution_identity_record_keys_invalid")
    if record["yara_hit_schema_version"] != YARA_HIT_SCHEMA_VERSION:
        raise ValueError("scan_cache_yara_hit_schema_mismatch")
    if record["yara_scan_result_schema_version"] != YARA_SCAN_RESULT_SCHEMA_VERSION:
        raise ValueError("scan_cache_yara_result_schema_mismatch")
    return ScanCacheExecutionIdentity(
        session_generation_id=record["session_generation_id"],
        session_state=record["session_state"],
        yara_state=record["yara_state"],
        yara_package_kind=record["yara_package_kind"],
        yara_source_digest=record["yara_source_digest"],
        yara_compiled_cache_digest=record["yara_compiled_cache_digest"],
        yara_rule_catalog_digest=record["yara_rule_catalog_digest"],
        attack_state=record["attack_state"],
        attack_alignment_digest=record["attack_alignment_digest"],
        attack_implementation_manifest_digest=record["attack_implementation_manifest_digest"],
        attack_policy_digest=record["attack_policy_digest"],
        attack_policy_version=record["attack_policy_version"],
        attack_repository_digest=record["attack_repository_digest"],
        attack_dataset_version=record["attack_dataset_version"],
        schema_version=record["schema_version"],
    )

def scan_cache_options_payload(execution_identity: object) -> dict[str, object]:
    """Return the exact deterministic cache-affecting payload."""
    if type(execution_identity) is not ScanCacheExecutionIdentity:
        raise TypeError("scan_cache_execution_identity_required")
    return {
        "schema": SCAN_CACHE_SCHEMA_VERSION,
        "profile_schema": PROFILE_SCHEMA_VERSION,
        "result_schema": SCAN_CACHE_RESULT_SCHEMA_VERSION,
        "engine_hint": "auto",
        "use_ilspy": False,
        "ilspy_path": "",
        "ilspy_timeout": 0,
        "execution_identity": execution_identity.to_record(),
    }


def scan_cache_options_fingerprint(execution_identity: object) -> str:
    """Return the one canonical exact scan-cache fingerprint."""
    payload = scan_cache_options_payload(execution_identity)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = (
    "SCAN_CACHE_EXECUTION_IDENTITY_VERSION",
    "SCAN_CACHE_RESULT_SCHEMA_VERSION",
    "SCAN_CACHE_SCHEMA_VERSION",
    "scan_cache_execution_identity_from_record",
    "ScanCacheExecutionIdentity",
    "scan_cache_options_fingerprint",
    "scan_cache_options_payload",
)
