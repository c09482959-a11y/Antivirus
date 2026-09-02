"""Canonical runtime and publication status contracts for ATT&CK."""
from __future__ import annotations

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from math import isfinite
from urllib.parse import parse_qs

from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.attack.validation import exact_bool, exact_git_ref, exact_hex, exact_https_endpoint
from Virus_Scan.detection.attack.versioning import ATTACK_DOMAIN_SCHEMA_VERSION

_STATUS_FIELDS = frozenset({
    "unavailable_reason", "lock_state", "config_state", "refresh_state",
    "active_cache_source", "api_identity_checked", "sha1_verification_state",
    "expected_git_blob_sha1", "computed_git_blob_sha1", "local_sha256",
    "integrity_state", "refresh_failure", "locked_resource_count",
    "object_counts", "dataset_version", "repository_digest", "enabled",
    "available", "schema_version", "api_identity_url", "source_ref",
    "active_requirement_counts", "activation_state", "activation_digest",
    "activation_counts",
})
_READY_REQUIRED = frozenset({
    "unavailable_reason", "lock_state", "config_state", "refresh_state",
    "active_cache_source", "api_identity_checked", "sha1_verification_state",
    "expected_git_blob_sha1", "computed_git_blob_sha1", "local_sha256",
    "integrity_state", "locked_resource_count", "object_counts",
    "dataset_version", "repository_digest", "enabled", "available",
    "schema_version", "source_ref", "active_requirement_counts",
    "activation_state", "activation_digest", "activation_counts",
})
_TEXT_FIELDS = frozenset({
    "unavailable_reason", "lock_state", "config_state", "refresh_state",
    "active_cache_source", "sha1_verification_state", "integrity_state",
    "refresh_failure", "source_ref", "activation_state",
})
_BOOL_FIELDS = frozenset({"api_identity_checked", "enabled", "available"})
_IDENTITY_FIELDS = frozenset({
    "expected_git_blob_sha1", "computed_git_blob_sha1", "local_sha256",
    "object_counts", "dataset_version", "repository_digest", "schema_version",
    "source_ref", "active_requirement_counts", "activation_digest",
    "activation_counts",
})
_READY_LOCK_STATES = frozenset({"active_files_locked"})
_READY_CONFIG_STATES = frozenset({"typed_defaults", "explicit_validated_toml", "parent_validated_readonly"})
_READY_REFRESH_STATES = frozenset({
    "refreshed", "not_requested", "failed_lkg_retained", "worker_readonly",
    "seed_activated",
})
_READY_CACHE_SOURCES = frozenset({
    "github_contents_api", "offline_active_cache", "offline_last_known_good_cache",
    "validated_offline_seed",
})
_READY_SHA_STATES = frozenset({
    "verified", "local_git_blob_recomputed",
    "packaged_seed_identity_verified",
})
_READY_INTEGRITY_STATES = frozenset({
    "verified_and_semantically_valid", "semantic_and_local_integrity_valid",
})
_READY_ACTIVATION_STATES = frozenset({
    "candidate_validated", "revalidated_from_local_cache", "seed_validated",
})


def _object_counts(value: object) -> dict[str, int]:
    if type(value) is not dict or not value or len(value) > 64:
        raise TypeError("official_attack_object_counts_invalid")
    counts: dict[str, int] = {}
    for name, count in dict.items(value):
        key = exact_bounded_text(name, "official_attack_object_count_key_invalid", maximum=64)
        maximum = 65536 if key == "relationship" else 16384
        counts[key] = exact_bounded_nonnegative_int(count, "official_attack_object_count_invalid", maximum=maximum)
    return dict(sorted(counts.items()))


_REQUIREMENT_COUNT_KEYS = frozenset({
    "data_components", "analytics", "detection_strategies",
    "analytic_requirement_digests",
})


def _requirement_counts(value: object) -> dict[str, int]:
    if type(value) is not dict or frozenset(value) != _REQUIREMENT_COUNT_KEYS:
        raise TypeError("official_attack_requirement_counts_invalid")
    return {
        key: exact_bounded_nonnegative_int(
            dict.get(value, key),
            "official_attack_requirement_count_invalid",
            maximum=16384,
        )
        for key in sorted(_REQUIREMENT_COUNT_KEYS)
    }



_ACTIVATION_COUNT_KEYS = frozenset({
    "active_alignments", "quarantined_alignments",
    "active_implementations", "quarantined_implementations",
    "active_policies", "quarantined_policies", "retired_policies",
    "active_calibrations", "quarantined_calibrations",
})


def _activation_counts(value: object) -> dict[str, int]:
    if type(value) is not dict or frozenset(value) != _ACTIVATION_COUNT_KEYS:
        raise TypeError("official_attack_activation_counts_invalid")
    return {
        key: exact_bounded_nonnegative_int(
            dict.get(value, key),
            "official_attack_activation_count_invalid", maximum=4096,
        )
        for key in sorted(_ACTIVATION_COUNT_KEYS)
    }

def _api_identity(value: object) -> tuple[str, str]:
    text, parsed = exact_https_endpoint(
        value, "official_attack_api_identity_invalid",
        hostname="api.github.com",
        path="/repos/mitre-attack/attack-stix-data/contents/enterprise-attack/enterprise-attack.json",
        allow_query=True, maximum=4096,
    )
    query = parse_qs(parsed.query, strict_parsing=True)
    if set(query) != {"ref"} or len(query["ref"]) != 1:
        raise ValueError("official_attack_api_identity_invalid")
    ref = exact_git_ref(query["ref"][0], "official_attack_api_identity_invalid")
    return text, ref


def _normalize_fields(raw: object) -> dict[str, object]:
    if type(raw) is not dict or not set(raw).issubset(_STATUS_FIELDS):
        raise ValueError("official_attack_repository_status_invalid")
    out: dict[str, object] = {}
    for key, value in dict.items(raw):
        if key == "source_ref":
            out[key] = exact_git_ref(value, "official_attack_repository_source_ref_invalid")
        elif key in _TEXT_FIELDS:
            out[key] = exact_bounded_text(value, "official_attack_repository_status_text_invalid", maximum=256, allow_blank=key == "unavailable_reason")
        elif key in _BOOL_FIELDS:
            out[key] = exact_bool(value, "official_attack_repository_status_bool_invalid")
        elif key == "locked_resource_count":
            out[key] = exact_bounded_nonnegative_int(value, "official_attack_locked_resource_count_invalid", maximum=64)
        elif key == "object_counts":
            out[key] = _object_counts(value)
        elif key == "active_requirement_counts":
            out[key] = _requirement_counts(value)
        elif key == "activation_counts":
            out[key] = _activation_counts(value)
        elif key in {"expected_git_blob_sha1", "computed_git_blob_sha1", "dataset_version"}:
            out[key] = exact_hex(value, "official_attack_git_identity_invalid", length=40)
        elif key in {"local_sha256", "repository_digest", "activation_digest"}:
            out[key] = exact_hex(value, "official_attack_digest_invalid", length=64)
        elif key == "schema_version":
            if value != ATTACK_DOMAIN_SCHEMA_VERSION:
                raise ValueError("official_attack_schema_version_invalid")
            out[key] = ATTACK_DOMAIN_SCHEMA_VERSION
        elif key == "api_identity_url":
            api_identity_url, api_ref = _api_identity(value)
            out[key] = api_identity_url
            out["_api_ref"] = api_ref
        elif type(value) is float and not isfinite(value):
            raise ValueError("official_attack_repository_status_nonfinite")
        else:
            raise TypeError("official_attack_repository_status_value_invalid")
    api_ref = out.pop("_api_ref", None)
    if api_ref is not None and out.get("source_ref") != api_ref:
        raise ValueError("official_attack_api_source_ref_mismatch")
    return out


def canonical_runtime_repository_status(
    repository: AttackRepositorySnapshot | None,
    *,
    enabled: bool,
    status: dict[str, object],
) -> dict[str, object]:
    if repository is not None and type(repository) is not AttackRepositorySnapshot:
        raise TypeError("mitre_runtime_repository_invalid")
    exact_bool(enabled, "mitre_runtime_enabled_invalid")
    out = _normalize_fields(status)
    ready = repository is not None
    if ready:
        if not enabled:
            raise ValueError("mitre_runtime_disabled_repository_invalid")
        canonical = repository.to_record()
        canonical["source_ref"] = repository.version.source_ref
        for key, value in canonical.items():
            if key in out and out[key] != value:
                raise ValueError("mitre_runtime_repository_status_identity_mismatch")
            out[key] = value
        if out.get("unavailable_reason", "") != "":
            raise ValueError("mitre_runtime_ready_reason_invalid")
        out["unavailable_reason"] = ""
    else:
        if any(key in out for key in _IDENTITY_FIELDS):
            raise ValueError("mitre_runtime_unavailable_identity_invalid")
        reason = out.get("unavailable_reason")
        if type(reason) is not str or reason == "":
            raise ValueError("mitre_runtime_unavailable_reason_required")
    out["enabled"] = enabled
    out["available"] = ready
    return out


def validate_published_repository_status(
    raw: object,
    result: AttackMappingResult,
) -> dict[str, object]:
    """Validate repository state independently from one mapping evaluation.

    Repository availability and mapping readiness are distinct canonical facts.
    A repository may remain available while one bounded mapping evaluation fails
    closed; that failure must remain serializable as explicit unavailable mapping
    evidence rather than corrupting the repository-status contract.
    """
    if type(result) is not AttackMappingResult:
        raise TypeError("official_attack_mapping_result_required")
    out = _normalize_fields(raw)
    available = out.get("available")
    if type(available) is not bool or type(out.get("enabled")) is not bool:
        raise ValueError("official_attack_repository_availability_invalid")
    if available:
        if not _READY_REQUIRED.issubset(out):
            raise ValueError("official_attack_repository_status_incomplete")
        if out["enabled"] is not True or out["unavailable_reason"] != "":
            raise ValueError("official_attack_repository_ready_state_invalid")
        if out["expected_git_blob_sha1"] != out["dataset_version"] or out["computed_git_blob_sha1"] != out["dataset_version"]:
            raise ValueError("official_attack_repository_git_identity_mismatch")
        if out["lock_state"] not in _READY_LOCK_STATES or out["locked_resource_count"] < 1:
            raise ValueError("official_attack_repository_lock_state_invalid")
        if out["config_state"] not in _READY_CONFIG_STATES or out["refresh_state"] not in _READY_REFRESH_STATES:
            raise ValueError("official_attack_repository_control_state_invalid")
        if out["active_cache_source"] not in _READY_CACHE_SOURCES:
            raise ValueError("official_attack_repository_cache_source_invalid")
        if out["sha1_verification_state"] not in _READY_SHA_STATES or out["integrity_state"] not in _READY_INTEGRITY_STATES:
            raise ValueError("official_attack_repository_integrity_state_invalid")
        if out["activation_state"] not in _READY_ACTIVATION_STATES:
            raise ValueError("official_attack_repository_activation_state_invalid")
        online = out["active_cache_source"] == "github_contents_api"
        if out["api_identity_checked"] is not online or ("api_identity_url" in out) is not online:
            raise ValueError("official_attack_repository_api_state_invalid")
        if result.ready and (
            out["repository_digest"] != result.repository_digest
            or out["dataset_version"] != result.dataset_version
        ):
            raise ValueError("official_attack_repository_identity_mismatch")
    else:
        if any(key in out for key in _IDENTITY_FIELDS):
            raise ValueError("official_attack_repository_unavailable_state_identity_invalid")
        reason = out.get("unavailable_reason")
        if type(reason) is not str or reason == "":
            raise ValueError("official_attack_repository_unavailable_reason_required")
        if result.ready:
            raise ValueError("official_attack_mapping_ready_repository_unavailable")
    return out


__all__ = (
    "canonical_runtime_repository_status", "validate_published_repository_status",
)
