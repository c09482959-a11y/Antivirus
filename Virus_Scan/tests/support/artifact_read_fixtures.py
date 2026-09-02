"""Current-schema artifact-read snapshots for tests."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_read_snapshot import (
    ArtifactReadSnapshot,
    build_artifact_read_snapshot,
)


def artifact_read_snapshot_fixture(path: object) -> ArtifactReadSnapshot:
    return build_artifact_read_snapshot(path)


__all__ = ("artifact_read_snapshot_fixture",)
