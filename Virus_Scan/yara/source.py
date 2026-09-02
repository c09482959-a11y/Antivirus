"""Canonical immutable source identity for official and custom YARA rules."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
import zipfile

from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraArchiveAcquisition, YaraArchiveMember
from Virus_Scan.yara.integrity import file_sha256
from Virus_Scan.yara.rule_archive import validate_rule_archive
from Virus_Scan.yara.validation import package_kind, sha256_text

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_TRUST_STATES = ("official_verified", "custom_verified", "custom_unverified")


@dataclass(frozen=True, slots=True)
class YaraRuleSource:
    path: Path
    trust_state: str
    package_kind: str
    archive_sha256: str
    manifest_sha256: str
    members: tuple[YaraArchiveMember, ...]
    acquisition: YaraArchiveAcquisition | None = None

    def __post_init__(self) -> None:
        if type(self) is not YaraRuleSource or type(self.path) not in _PATH_TYPES:
            raise TypeError("yara_rule_source_owner_invalid")
        trust = exact_bounded_text(self.trust_state, "yara_source_trust_invalid", maximum=32)
        if trust not in _TRUST_STATES:
            raise ValueError("yara_source_trust_invalid")
        kind = package_kind(self.package_kind) if self.package_kind != "custom" else "custom"
        archive_digest = sha256_text(self.archive_sha256, "yara_source_sha256_invalid")
        manifest_digest = self.manifest_sha256
        if type(manifest_digest) is not str:
            raise TypeError("yara_source_manifest_sha256_invalid")
        manifest_digest = str.__str__(manifest_digest)
        if manifest_digest != "":
            manifest_digest = sha256_text(manifest_digest, "yara_source_manifest_sha256_invalid")
        if type(self.members) is not tuple or not self.members or any(type(item) is not YaraArchiveMember for item in self.members):
            raise TypeError("yara_source_members_invalid")
        names = tuple(item.name for item in self.members)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("yara_source_members_order_invalid")
        acquisition = self.acquisition
        if trust == "official_verified":
            if type(acquisition) is not YaraArchiveAcquisition:
                raise TypeError("yara_source_official_acquisition_required")
            snapshot = acquisition.snapshot
            if self.path != snapshot.local_path or archive_digest != snapshot.computed_sha256:
                raise ValueError("yara_source_official_identity_mismatch")
            if manifest_digest != snapshot.manifest_sha256 or self.members != snapshot.members:
                raise ValueError("yara_source_official_evidence_mismatch")
            if kind != snapshot.identity.package_kind:
                raise ValueError("yara_source_official_kind_mismatch")
        elif acquisition is not None or kind not in ("custom", "core", "extended") or manifest_digest != "":
            raise ValueError("yara_source_custom_identity_inconsistent")
        object.__setattr__(self, "trust_state", trust)
        object.__setattr__(self, "package_kind", kind)
        object.__setattr__(self, "archive_sha256", archive_digest)
        object.__setattr__(self, "manifest_sha256", manifest_digest)

    @property
    def cache_allowed(self) -> bool:
        return self.trust_state in ("official_verified", "custom_verified")


def official_rule_source(acquisition: YaraArchiveAcquisition) -> YaraRuleSource:
    if type(acquisition) is not YaraArchiveAcquisition:
        raise TypeError("yara_official_source_acquisition_invalid")
    snapshot = acquisition.snapshot
    return YaraRuleSource(
        path=snapshot.local_path,
        trust_state="official_verified",
        package_kind=snapshot.identity.package_kind,
        archive_sha256=snapshot.computed_sha256,
        manifest_sha256=snapshot.manifest_sha256,
        members=snapshot.members,
        acquisition=acquisition,
    )




def _expected_source_digest(config: YaraConfig, source_package: str) -> str:
    if source_package == "extended":
        return config.full_expected_sha256
    if source_package == "core":
        return config.light_expected_sha256
    if source_package == "custom":
        return config.custom_rule_expected_sha256
    raise ValueError("yara_custom_source_package_kind_invalid")


def custom_rule_source(
    path: Path,
    config: YaraConfig,
    *,
    package_kind: str,
) -> YaraRuleSource:
    if type(path) not in _PATH_TYPES or type(config) is not YaraConfig:
        raise TypeError("yara_custom_source_contract_invalid")
    if type(package_kind) is not str or package_kind not in ("custom", "core", "extended"):
        raise ValueError("yara_custom_source_package_kind_invalid")
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise ValueError("yara_custom_source_file_invalid")
    digest = file_sha256(path, maximum_bytes=config.maximum_archive_bytes)
    expected_digest = _expected_source_digest(config, package_kind)
    if expected_digest != "" and digest != expected_digest:
        raise ValueError("yara_custom_source_digest_mismatch")
    if zipfile.is_zipfile(path):
        if path.suffix.lower() != ".zip":
            raise ValueError("yara_custom_source_extension_invalid")
        members = validate_rule_archive(path, config)
    else:
        if path.suffix.lower() not in (".yar", ".yara"):
            raise ValueError("yara_custom_source_extension_invalid")
        size = path.stat().st_size
        if size < 1 or size > config.maximum_member_bytes:
            raise ValueError("yara_custom_source_size_invalid")
        members = (YaraArchiveMember(path.name, digest, size, size),)
    trust = "custom_verified" if expected_digest != "" else "custom_unverified"
    return YaraRuleSource(path, trust, package_kind, digest, "", members, None)


__all__ = ("YaraRuleSource", "custom_rule_source", "official_rule_source")
