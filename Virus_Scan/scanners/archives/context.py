"""Canonical shared context for one root archive expansion tree."""
from __future__ import annotations

from dataclasses import dataclass, field

from Virus_Scan.runtime.api import ArchiveScanLimits, ExtractionQuotaTracker, ResourceQuotaExceeded


@dataclass(slots=True)
class ArchiveMemberIdentityLedger:
    """Own exact member-path claims for every physical container in one root tree."""

    _claimed: set[tuple[str, str]] = field(default_factory=set)

    def __post_init__(self) -> None:
        if type(self) is not ArchiveMemberIdentityLedger:
            raise TypeError("archive_member_identity_ledger_owner_invalid")
        if type(self._claimed) is not set:
            raise TypeError("archive_member_identity_ledger_state_invalid")

    def claim(self, container_path: object, member_path: object) -> bool:
        container = _exact_identity_text(
            container_path, "archive_member_identity_container_invalid",
        )
        member = _exact_identity_text(
            member_path, "archive_member_identity_path_invalid",
        )
        identity = (container, member)
        if identity in self._claimed:
            return False
        self._claimed.add(identity)
        return True


@dataclass(slots=True)
class ArchiveContainerIdentityLedger:
    """Map physical extraction paths to deterministic artifact/member identities."""

    _logical_by_physical: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not ArchiveContainerIdentityLedger:
            raise TypeError("archive_container_identity_ledger_owner_invalid")
        if type(self._logical_by_physical) is not dict:
            raise TypeError("archive_container_identity_ledger_state_invalid")

    def register_root(self, physical_path: object) -> str:
        physical = _exact_identity_text(physical_path, "archive_container_physical_path_invalid")
        existing = self._logical_by_physical.get(physical)
        if existing is not None:
            return existing
        self._logical_by_physical[physical] = physical
        return physical

    def logical_identity(self, physical_path: object) -> str:
        physical = _exact_identity_text(physical_path, "archive_container_physical_path_invalid")
        return self._logical_by_physical.get(physical, physical)

    def register_member(
        self, *, parent_physical_path: object, member_name: object, extracted_physical_path: object,
    ) -> str:
        parent = self.logical_identity(parent_physical_path)
        member = _exact_identity_text(member_name, "archive_member_identity_path_invalid")
        extracted = _exact_identity_text(
            extracted_physical_path, "archive_member_extracted_path_invalid",
        )
        logical = "archive_member:" + parent + ":" + member
        existing = self._logical_by_physical.get(extracted)
        if existing is not None and existing != logical:
            raise ValueError("archive_extracted_path_identity_conflict")
        self._logical_by_physical[extracted] = logical
        return logical

    def member_identity(self, *, parent_physical_path: object, member_name: object) -> str:
        parent = self.logical_identity(parent_physical_path)
        member = _exact_identity_text(member_name, "archive_member_identity_path_invalid")
        return "archive_member:" + parent + ":" + member


@dataclass(frozen=True, slots=True)
class ArchiveScanContext:
    """One shared quota and identity authority reused below a root archive."""

    limits: ArchiveScanLimits
    quota: ExtractionQuotaTracker
    member_identities: ArchiveMemberIdentityLedger
    container_identities: ArchiveContainerIdentityLedger

    def __post_init__(self) -> None:
        if type(self) is not ArchiveScanContext:
            raise TypeError("archive_scan_context_owner_invalid")
        if type(self.limits) is not ArchiveScanLimits:
            raise TypeError("archive_scan_context_limits_invalid")
        if type(self.quota) is not ExtractionQuotaTracker:
            raise TypeError("archive_scan_context_quota_invalid")
        if type(self.member_identities) is not ArchiveMemberIdentityLedger:
            raise TypeError("archive_scan_context_member_identities_invalid")
        if type(self.container_identities) is not ArchiveContainerIdentityLedger:
            raise TypeError("archive_scan_context_container_identities_invalid")
        if self.quota.limits != self.limits:
            raise ValueError("archive_scan_context_limit_mismatch")

    @classmethod
    def create(cls, limits: object, *, initial_depth: object) -> "ArchiveScanContext":
        if type(limits) is not ArchiveScanLimits:
            raise TypeError("archive_scan_context_limits_invalid")
        if type(initial_depth) is not int or type(initial_depth) is bool or initial_depth < 0:
            raise ValueError("archive_scan_context_depth_invalid")
        quota = ExtractionQuotaTracker(limits=limits, depth=initial_depth)
        return cls(
            limits=quota.limits,
            quota=quota,
            member_identities=ArchiveMemberIdentityLedger(),
            container_identities=ArchiveContainerIdentityLedger(),
        )

    def register_root_identity(self, path: object) -> str:
        return self.container_identities.register_root(path)

    def logical_container_identity(self, path: object) -> str:
        return self.container_identities.logical_identity(path)

    def register_extracted_member_identity(
        self, *, container_path: object, member_name: object, extracted_path: object,
    ) -> str:
        return self.container_identities.register_member(
            parent_physical_path=container_path,
            member_name=member_name,
            extracted_physical_path=extracted_path,
        )

    def logical_member_identity(self, *, container_path: object, member_name: object) -> str:
        return self.container_identities.member_identity(
            parent_physical_path=container_path, member_name=member_name,
        )

    def check_depth(self, depth: object) -> int:
        if type(depth) is not int or type(depth) is bool or depth < 0:
            raise ResourceQuotaExceeded("archive_depth_unsupported")
        if depth > self.limits.max_depth:
            raise ResourceQuotaExceeded("archive_depth_limit")
        return depth


def _exact_identity_text(value: object, reason: str) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if not str.strip(text):
        raise ValueError(reason)
    return text


__all__ = (
    "ArchiveContainerIdentityLedger",
    "ArchiveMemberIdentityLedger",
    "ArchiveScanContext",
)
