"""Project canonical immutable resource roots into standalone distributions.

Runtime resource classification remains owned by ``Virus_Scan.runtime.resource_paths``.
This build-only module consumes that classification, validates every required source
file, and describes/validates the exact standalone projection. It never copies
runtime locks, caches, state, staging output, publications, or secrets.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.runtime.resource_paths import (
    RESOURCE_CLASSIFICATION_PACKAGE, RESOURCE_CLASSIFICATION_RUNTIME_CONTROL,
    ResourceRootSnapshot,
    resource_root_snapshot_from_program_root,
)

_COPY_CHUNK_BYTES = 1024 * 1024


class PackageResourceProjectionError(RuntimeError):
    """The standalone resource-root projection is incomplete or noncanonical."""


@dataclass(frozen=True, slots=True)
class PackageResourceRecord:
    root_name: str
    source_path: str
    relative_path: str
    size: int
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(_COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(repository_root: Path) -> ResourceRootSnapshot:
    root = repository_root.absolute()
    if path_contains_filesystem_alias(root) or not root.is_dir():
        raise PackageResourceProjectionError("standalone_repository_root_unavailable")
    return resource_root_snapshot_from_program_root(root)


def canonical_package_resource_records(repository_root: Path) -> tuple[PackageResourceRecord, ...]:
    """Return the exact manifest-owned package files for all governed roots."""
    snapshot = _snapshot(repository_root)
    program_root = Path(snapshot.program_root)
    records: list[PackageResourceRecord] = []
    for root_name, source_text in snapshot.standalone_package_resources():
        source = Path(source_text)
        root = source.parent
        if path_contains_filesystem_alias(root) or not root.is_dir():
            raise PackageResourceProjectionError(
                "standalone_package_resource_root_unavailable:" + root_name
            )
        if path_contains_filesystem_alias(source) or not source.is_file():
            raise PackageResourceProjectionError(
                "standalone_package_resource_source_unavailable:"
                + root_name
                + ":"
                + source.name
            )
        if snapshot.classify(source) not in {
            RESOURCE_CLASSIFICATION_PACKAGE, RESOURCE_CLASSIFICATION_RUNTIME_CONTROL,
        }:
            raise PackageResourceProjectionError(
                "standalone_package_resource_classification_invalid:"
                + root_name
                + ":"
                + source.name
            )
        records.append(
            PackageResourceRecord(
                root_name=root_name,
                source_path=source.as_posix(),
                relative_path=source.relative_to(program_root).as_posix(),
                size=source.stat().st_size,
                sha256=_sha256(source),
            )
        )
    return tuple(records)


def verify_standalone_package_resources(
    repository_root: Path,
    distribution_root: Path,
) -> tuple[PackageResourceRecord, ...]:
    """Verify exact classified package resources and reject runtime-state leakage."""
    records = canonical_package_resource_records(repository_root)
    expected = {record.relative_path: record for record in records}
    distribution = distribution_root.absolute()
    if path_contains_filesystem_alias(distribution) or not distribution.is_dir():
        raise PackageResourceProjectionError("standalone_distribution_root_unavailable")

    for relative_path, record in expected.items():
        target = distribution / relative_path
        if path_contains_filesystem_alias(target) or not target.is_file():
            raise PackageResourceProjectionError(
                "standalone_package_resource_target_unavailable:" + relative_path
            )
        if target.stat().st_size != record.size or _sha256(target) != record.sha256:
            raise PackageResourceProjectionError(
                "standalone_package_resource_target_integrity_failed:" + relative_path
            )

    snapshot = _snapshot(repository_root)
    for root_name, source_root in snapshot.governed_roots():
        target_root = distribution / Path(source_root).name
        if path_contains_filesystem_alias(target_root) or not target_root.is_dir():
            raise PackageResourceProjectionError(
                "standalone_package_resource_root_target_unavailable:" + root_name
            )
        actual: set[str] = set()
        pending = [target_root]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                relative = path.relative_to(distribution).as_posix()
                if path_contains_filesystem_alias(path):
                    actual.add(relative)
                elif path.is_dir():
                    pending.append(path)
                elif path.is_file():
                    actual.add(relative)
        allowed = {path for path in expected if path.startswith(root_name + "/")}
        extra = sorted(actual.difference(allowed))
        if extra:
            raise PackageResourceProjectionError(
                "standalone_package_runtime_state_present:" + extra[0]
            )

    return records


__all__ = (
    "PackageResourceProjectionError",
    "PackageResourceRecord",
    "canonical_package_resource_records",
    "verify_standalone_package_resources",
)
