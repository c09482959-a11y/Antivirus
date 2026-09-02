"""Frozen canonical records for YARA release, archive, and load evidence."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath

from Virus_Scan.yara.validation import (
    archive_asset_name,
    bounded_float,
    bounded_int,
    exact_bool,
    manifest_asset_name,
    package_kind,
    release_asset_url,
    release_tag,
    sha256_text,
    version_text,
)
from Virus_Scan.yara.versioning import (
    YARA_ARCHIVE_POLICY_VERSION, YARA_COMPILE_POLICY_VERSION,
    YARA_RELEASE_CONTRACT_VERSION,
)

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_LOAD_STATES = (
    "fully_compiled", "partially_compiled_accepted", "partial_rejected",
    "dependency_unavailable", "integrity_failure", "custom_verified", "custom_unverified",
)


@dataclass(frozen=True, slots=True)
class YaraReleaseIdentity:
    release_id: int
    release_tag: str
    package_kind: str
    archive_asset_id: int
    archive_name: str
    archive_url: str
    manifest_asset_id: int
    manifest_name: str
    manifest_url: str
    release_contract_version: str = YARA_RELEASE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraReleaseIdentity:
            raise TypeError("yara_release_identity_owner_invalid")
        object.__setattr__(self, "release_id", bounded_int(self.release_id, "yara_release_id_invalid", minimum=1, maximum=1 << 63))
        object.__setattr__(self, "archive_asset_id", bounded_int(self.archive_asset_id, "yara_archive_asset_id_invalid", minimum=1, maximum=1 << 63))
        object.__setattr__(self, "manifest_asset_id", bounded_int(self.manifest_asset_id, "yara_manifest_asset_id_invalid", minimum=1, maximum=1 << 63))
        if self.archive_asset_id == self.manifest_asset_id:
            raise ValueError("yara_release_asset_identity_conflict")
        tag = release_tag(self.release_tag)
        kind = package_kind(self.package_kind)
        expected_archive = "yara-forge-rules-" + kind + ".zip"
        archive = archive_asset_name(self.archive_name)
        manifest = manifest_asset_name(self.manifest_name)
        if archive != expected_archive:
            raise ValueError("yara_release_archive_asset_invalid")
        object.__setattr__(self, "release_tag", tag)
        object.__setattr__(self, "package_kind", kind)
        object.__setattr__(self, "archive_name", archive)
        object.__setattr__(self, "manifest_name", manifest)
        object.__setattr__(self, "archive_url", release_asset_url(self.archive_url, tag=tag, name=archive))
        object.__setattr__(self, "manifest_url", release_asset_url(self.manifest_url, tag=tag, name=manifest))
        object.__setattr__(self, "release_contract_version", version_text(self.release_contract_version))


@dataclass(frozen=True, slots=True)
class YaraArchiveMember:
    name: str
    sha256: str
    compressed_size: int
    uncompressed_size: int

    def __post_init__(self) -> None:
        if type(self) is not YaraArchiveMember:
            raise TypeError("yara_archive_member_owner_invalid")
        object.__setattr__(self, "name", exact_bounded_text(self.name, "yara_member_name_invalid", maximum=4096))
        object.__setattr__(self, "sha256", sha256_text(self.sha256))
        object.__setattr__(self, "compressed_size", bounded_int(self.compressed_size, "yara_member_compressed_size_invalid", maximum=1 << 31))
        object.__setattr__(self, "uncompressed_size", bounded_int(self.uncompressed_size, "yara_member_size_invalid", maximum=1 << 31))


@dataclass(frozen=True, slots=True)
class YaraArchiveSnapshot:
    identity: YaraReleaseIdentity
    local_path: Path
    expected_sha256: str
    computed_sha256: str
    manifest_sha256: str
    members: tuple[YaraArchiveMember, ...]
    archive_policy_version: str = YARA_ARCHIVE_POLICY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraArchiveSnapshot or type(self.identity) is not YaraReleaseIdentity:
            raise TypeError("yara_archive_snapshot_owner_invalid")
        if type(self.local_path) not in _PATH_TYPES:
            raise TypeError("yara_archive_path_invalid")
        expected = sha256_text(self.expected_sha256)
        computed = sha256_text(self.computed_sha256)
        if expected != computed:
            raise ValueError("yara_archive_digest_mismatch")
        if type(self.members) is not tuple or not self.members or any(type(item) is not YaraArchiveMember for item in self.members):
            raise TypeError("yara_archive_members_invalid")
        names = tuple(item.name for item in self.members)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("yara_archive_member_order_invalid")
        object.__setattr__(self, "expected_sha256", expected)
        object.__setattr__(self, "computed_sha256", computed)
        object.__setattr__(self, "manifest_sha256", sha256_text(self.manifest_sha256))
        object.__setattr__(self, "archive_policy_version", version_text(self.archive_policy_version))


@dataclass(frozen=True, slots=True)
class YaraArchiveAcquisition:
    snapshot: YaraArchiveSnapshot
    source: str
    freshness_state: str
    api_identity_checked: bool

    def __post_init__(self) -> None:
        if type(self) is not YaraArchiveAcquisition or type(self.snapshot) is not YaraArchiveSnapshot:
            raise TypeError("yara_archive_acquisition_owner_invalid")
        source = exact_bounded_text(self.source, "yara_archive_source_invalid", maximum=64)
        freshness = exact_bounded_text(self.freshness_state, "yara_freshness_state_invalid", maximum=64)
        if source not in ("github_release_api", "offline_active_cache", "offline_last_known_good_cache"):
            raise ValueError("yara_archive_source_invalid")
        if freshness not in ("downloaded", "not_modified_revalidated", "local_revalidated", "last_known_good_retained"):
            raise ValueError("yara_freshness_state_invalid")
        checked = exact_bool(self.api_identity_checked, "yara_api_identity_checked_invalid")
        if checked != (source == "github_release_api"):
            raise ValueError("yara_api_identity_state_inconsistent")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "freshness_state", freshness)
        object.__setattr__(self, "api_identity_checked", checked)


@dataclass(frozen=True, slots=True)
class YaraRuleLoadResult:
    state: str
    ready: bool
    total_members: int
    compiled_members: int
    failed_members: int
    acceptance_threshold: float
    failure_samples: tuple[str, ...]
    reason: str
    compile_policy_version: str = YARA_COMPILE_POLICY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraRuleLoadResult:
            raise TypeError("yara_rule_load_result_owner_invalid")
        state = exact_bounded_text(self.state, "yara_load_state_invalid", maximum=64)
        if state not in _LOAD_STATES:
            raise ValueError("yara_load_state_invalid")
        ready = exact_bool(self.ready, "yara_load_ready_invalid")
        total = bounded_int(self.total_members, "yara_load_total_invalid", maximum=1_000_000)
        compiled = bounded_int(self.compiled_members, "yara_load_compiled_invalid", maximum=total)
        failed = bounded_int(self.failed_members, "yara_load_failed_invalid", maximum=total)
        if compiled + failed != total:
            raise ValueError("yara_load_counts_inconsistent")
        if type(self.failure_samples) is not tuple or len(self.failure_samples) > 32:
            raise TypeError("yara_load_failure_samples_invalid")
        samples = tuple(exact_bounded_text(item, "yara_load_failure_sample_invalid", maximum=256) for item in self.failure_samples)
        if samples != tuple(sorted(set(samples))):
            raise ValueError("yara_load_failure_samples_order_invalid")
        if ready != (state in ("fully_compiled", "partially_compiled_accepted", "custom_verified")):
            raise ValueError("yara_load_readiness_inconsistent")
        threshold = bounded_float(
            self.acceptance_threshold,
            "yara_load_threshold_invalid",
            minimum=0.5,
        )
        if len(samples) > failed:
            raise ValueError("yara_load_failure_samples_inconsistent")
        if state in ("fully_compiled", "custom_verified"):
            if total < 1 or compiled != total or failed != 0 or samples:
                raise ValueError("yara_load_ready_counts_invalid")
        elif state == "partially_compiled_accepted":
            if (
                total < 2
                or compiled < 1
                or compiled >= total
                or failed < 1
                or float(compiled) / float(total) < threshold
                or not samples
            ):
                raise ValueError("yara_load_partial_acceptance_invalid")
        elif state == "partial_rejected":
            if total < 1:
                raise ValueError("yara_load_partial_rejection_invalid")
        elif compiled != 0:
            raise ValueError("yara_load_unavailable_counts_invalid")
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "ready", ready)
        object.__setattr__(self, "acceptance_threshold", threshold)
        object.__setattr__(self, "failure_samples", samples)
        object.__setattr__(self, "reason", exact_bounded_text(self.reason, "yara_load_reason_invalid", maximum=256, allow_blank=ready))
        object.__setattr__(self, "compile_policy_version", version_text(self.compile_policy_version))


__all__ = ("YaraArchiveAcquisition", "YaraArchiveMember", "YaraArchiveSnapshot", "YaraReleaseIdentity", "YaraRuleLoadResult")
