"""Canonical projection of immutable YARA load evidence into runtime status."""
from __future__ import annotations

from Virus_Scan.yara.loader import YaraLoadAttempt


def disabled_package_status(reason: str) -> dict[str, object]:
    if type(reason) is not str or not reason:
        raise TypeError("yara_publication_disabled_reason_invalid")
    return {
        "acquisition_source": "unavailable",
        "api_identity_checked": False,
        "archive_asset_id": 0,
        "archive_asset_name": "",
        "archive_sha256_computed": "",
        "archive_sha256_expected": "",
        "cache_hit": False,
        "cache_identity": "",
        "cache_schema_version": "",
        "compile_policy_version": "",
        "compilation_state": "disabled",
        "compiled_members": 0,
        "failed_members": 0,
        "failure_samples": (),
        "freshness_state": "not_run",
        "group_cache_count": 0,
        "group_cache_identities": (),
        "integrity_state": "disabled",
        "manifest_asset_id": 0,
        "manifest_asset_name": "",
        "manifest_sha256": "",
        "manifest_url": "",
        "package_kind": "",
        "partial_acceptance_threshold": 0.0,
        "platform_identity": "",
        "release_id": 0,
        "release_tag": "",
        "source_local_path": "",
        "source_trust": "unavailable",
        "source_url": "",
        "total_members": 0,
        "unavailable_reason": reason,
        "yara_engine_version": "unavailable",
        "yara_python_version": "unavailable",
    }


def load_attempt_status(
    attempt: YaraLoadAttempt | None,
    *,
    disabled_reason: str,
    group_attempts: tuple[YaraLoadAttempt, ...] = (),
) -> dict[str, object]:
    if attempt is None:
        return disabled_package_status(disabled_reason)
    if type(attempt) is not YaraLoadAttempt:
        raise TypeError("yara_publication_attempt_invalid")
    if type(group_attempts) is not tuple or any(
        type(item) is not YaraLoadAttempt for item in group_attempts
    ):
        raise TypeError("yara_publication_group_attempt_invalid")

    result = attempt.load_result
    source = attempt.source
    identity = attempt.identity
    status = disabled_package_status(result.reason if not result.ready else "ready")
    status.update({
        "cache_hit": attempt.cache_hit,
        "cache_identity": "" if identity is None else identity.digest,
        "cache_schema_version": "" if identity is None else identity.cache_schema_version,
        "compilation_state": result.state,
        "compile_policy_version": result.compile_policy_version,
        "compiled_members": result.compiled_members,
        "failed_members": result.failed_members,
        "failure_samples": result.failure_samples,
        "group_cache_count": len(group_attempts),
        "group_cache_identities": tuple(
            item.identity.digest
            for item in group_attempts
            if item.identity is not None
        ),
        "partial_acceptance_threshold": result.acceptance_threshold,
        "platform_identity": "" if identity is None else identity.platform_identity,
        "total_members": result.total_members,
        "unavailable_reason": "" if result.ready else result.reason,
        "yara_engine_version": (
            "unavailable" if identity is None else identity.yara_engine_version
        ),
        "yara_python_version": (
            "unavailable" if identity is None else identity.yara_python_version
        ),
    })
    if source is None:
        status["integrity_state"] = "unavailable"
        return status

    status.update({
        "archive_sha256_computed": source.archive_sha256,
        "package_kind": source.package_kind,
        "source_local_path": str(source.path),
        "source_trust": source.trust_state,
    })
    if source.trust_state == "custom_verified":
        status.update({
            "archive_sha256_expected": source.archive_sha256,
            "integrity_state": "explicit_expected_sha256_verified",
        })
        return status
    if source.trust_state == "custom_unverified":
        status["integrity_state"] = "custom_unverified"
        return status

    acquisition = source.acquisition
    if acquisition is None:
        raise ValueError("yara_publication_official_acquisition_missing")
    snapshot = acquisition.snapshot
    release = snapshot.identity
    status.update({
        "acquisition_source": acquisition.source,
        "api_identity_checked": acquisition.api_identity_checked,
        "archive_asset_id": release.archive_asset_id,
        "archive_asset_name": release.archive_name,
        "archive_sha256_computed": snapshot.computed_sha256,
        "archive_sha256_expected": snapshot.expected_sha256,
        "freshness_state": acquisition.freshness_state,
        "integrity_state": "official_manifest_sha256_verified",
        "manifest_asset_id": release.manifest_asset_id,
        "manifest_asset_name": release.manifest_name,
        "manifest_sha256": snapshot.manifest_sha256,
        "manifest_url": release.manifest_url,
        "release_id": release.release_id,
        "release_tag": release.release_tag,
        "source_url": release.archive_url,
    })
    return status


__all__ = ("disabled_package_status", "load_attempt_status")
