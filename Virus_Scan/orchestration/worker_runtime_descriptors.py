"""Canonical parent-approved YARA and MITRE projections for spawned workers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.contracts.runtime_function_identity import is_runtime_native_function
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_worker_runtime
from Virus_Scan.orchestration.yara_initialization import initialize_yara_worker_runtime
from Virus_Scan.runtime.api import yara_dir


@dataclass(frozen=True, slots=True)
class WorkerYaraRuntimeDescriptor:
    initializer: object
    root: str
    enabled: bool
    available: bool
    scan_mode: str
    package_kind: str
    source_path: str
    source_digest: str
    compiled_cache_digest: str
    rule_catalog_digest: str
    unavailable_reason: str

    def __post_init__(self) -> None:
        if not is_runtime_native_function(self.initializer):
            raise TypeError("worker_yara_initializer_invalid")
        if type(self.root) is not str or self.root == "" or len(self.root) > 4096:
            raise ValueError("worker_yara_root_invalid")
        if type(self.enabled) is not bool or type(self.available) is not bool:
            raise TypeError("worker_yara_flags_invalid")
        if type(self.scan_mode) is not str or self.scan_mode == "" or len(self.scan_mode) > 32:
            raise ValueError("worker_yara_scan_mode_invalid")
        if type(self.package_kind) is not str or self.package_kind not in ("", "core", "extended"):
            raise ValueError("worker_yara_package_kind_invalid")
        for value, reason, maximum in (
            (self.source_path, "worker_yara_source_path_invalid", 4096),
            (self.unavailable_reason, "worker_yara_reason_invalid", 256),
        ):
            if type(value) is not str or len(value) > maximum:
                raise ValueError(reason)
        for value, reason in (
            (self.source_digest, "worker_yara_source_digest_invalid"),
            (self.compiled_cache_digest, "worker_yara_cache_digest_invalid"),
            (self.rule_catalog_digest, "worker_yara_catalog_digest_invalid"),
        ):
            if type(value) is not str:
                raise TypeError(reason)
        if self.available:
            if not self.enabled or self.package_kind not in ("core", "extended"):
                raise ValueError("worker_yara_available_state_invalid")
            if self.source_path == "" or any(
                len(value) != 64
                for value in (
                    self.source_digest,
                    self.compiled_cache_digest,
                    self.rule_catalog_digest,
                )
            ):
                raise ValueError("worker_yara_available_identity_invalid")
        elif any(
            (
                self.package_kind != "",
                self.source_path != "",
                self.source_digest != "",
                self.compiled_cache_digest != "",
                self.rule_catalog_digest != "",
            )
        ):
            raise ValueError("worker_yara_unavailable_identity_present")


@dataclass(frozen=True, slots=True)
class WorkerMitreRuntimeDescriptor:
    initializer: object
    root: str
    enabled: bool
    available: bool
    repository_digest: str
    dataset_version: str
    unavailable_reason: str

    def __post_init__(self) -> None:
        if not is_runtime_native_function(self.initializer):
            raise TypeError("worker_mitre_initializer_invalid")
        if type(self.root) is not str or self.root == "" or len(self.root) > 4096:
            raise ValueError("worker_mitre_root_invalid")
        if type(self.enabled) is not bool or type(self.available) is not bool:
            raise TypeError("worker_mitre_flags_invalid")
        if type(self.repository_digest) is not str or type(self.dataset_version) is not str:
            raise TypeError("worker_mitre_identity_invalid")
        if type(self.unavailable_reason) is not str or len(self.unavailable_reason) > 256:
            raise ValueError("worker_mitre_reason_invalid")
        if self.available:
            if not self.enabled:
                raise ValueError("worker_mitre_available_while_disabled")
            if len(self.repository_digest) != 64 or len(self.dataset_version) != 40:
                raise ValueError("worker_mitre_available_identity_invalid")
        elif self.repository_digest != "" or self.dataset_version != "":
            raise ValueError("worker_mitre_unavailable_identity_present")


def build_worker_yara_runtime_descriptor(
    scan_session_snapshot: ScanSessionSnapshot,
) -> WorkerYaraRuntimeDescriptor:
    """Project the exact parent-approved YARA state from the session owner."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("worker_scan_session_snapshot_required")
    identity = scan_session_snapshot.cache_execution_identity
    available = identity.yara_state == "verified"
    enabled = identity.yara_state != "disabled"
    return WorkerYaraRuntimeDescriptor(
        initializer=initialize_yara_worker_runtime,
        root=str(Path(yara_dir()).resolve()),
        enabled=enabled,
        available=available,
        scan_mode=scan_session_snapshot.yara_scan_mode,
        package_kind=identity.yara_package_kind if available else "",
        source_path=scan_session_snapshot.yara_source_path if available else "",
        source_digest=identity.yara_source_digest if available else "",
        compiled_cache_digest=identity.yara_compiled_cache_digest if available else "",
        rule_catalog_digest=identity.yara_rule_catalog_digest if available else "",
        unavailable_reason=scan_session_snapshot.yara_unavailable_reason,
    )


def build_worker_mitre_runtime_descriptor(
    scan_session_snapshot: ScanSessionSnapshot,
) -> WorkerMitreRuntimeDescriptor:
    """Project the exact parent-approved ATT&CK state from the session owner."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("worker_scan_session_snapshot_required")
    identity = scan_session_snapshot.cache_execution_identity
    return WorkerMitreRuntimeDescriptor(
        initializer=initialize_mitre_worker_runtime,
        root=scan_session_snapshot.mitre_root,
        enabled=identity.attack_state != "disabled",
        available=identity.attack_state == "available",
        repository_digest=identity.attack_repository_digest,
        dataset_version=identity.attack_dataset_version,
        unavailable_reason=scan_session_snapshot.attack_unavailable_reason,
    )


__all__ = (
    "WorkerMitreRuntimeDescriptor",
    "WorkerYaraRuntimeDescriptor",
    "build_worker_mitre_runtime_descriptor",
    "build_worker_yara_runtime_descriptor",
)
