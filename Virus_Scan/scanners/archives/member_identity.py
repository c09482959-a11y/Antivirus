"""Canonical archive-member type and duplicate-path identity policy."""

from __future__ import annotations

from pathlib import Path
from stat import S_IFMT, S_ISDIR, S_ISREG
import zipfile

from Virus_Scan.scanners.archives.context import ArchiveScanContext
from Virus_Scan.scanners.archives.evidence import append_archive_member_policy_evidence
from Virus_Scan.scanners.archives.publication_requests import (
    append_archive_graph_publication_request_tags,
)
from Virus_Scan.scanners.archives.text_boundaries import (
    archive_exact_attr_int,
    archive_prefixed,
)


def zip_member_type_supported(member: zipfile.ZipInfo) -> bool:
    """Allow ZIP directories, regular files, and records with no Unix type bits."""
    create_system = archive_exact_attr_int(member, zipfile.ZipInfo, "create_system")
    external_attr = archive_exact_attr_int(member, zipfile.ZipInfo, "external_attr")
    if create_system != 3:
        return True
    mode = external_attr >> 16
    member_type = S_IFMT(mode)
    return member_type == 0 or S_ISREG(mode) or S_ISDIR(mode)


def claim_archive_member_path(
    context: ArchiveScanContext,
    *,
    container_path: str,
    extraction_root: str,
    target: Path,
) -> bool:
    """Claim one normalized extracted path under its exact physical container."""
    if type(context) is not ArchiveScanContext:
        raise TypeError("archive_scan_context_required")
    root = Path(extraction_root).resolve()
    member_identity = target.relative_to(root).as_posix()
    return context.member_identities.claim(
        context.logical_container_identity(container_path), member_identity,
    )


def append_duplicate_member_evidence(
    tags: list[str],
    *,
    path: str,
    member_name: str,
) -> None:
    """Publish one fail-closed duplicate-member identity decision."""
    tags[:] = append_archive_member_policy_evidence(
        tags,
        path=path,
        member_name=member_name,
        evidence_tag="archive_duplicate_member_path",
        reason=archive_prefixed("duplicate archive member path: ", member_name),
    )
    append_archive_graph_publication_request_tags(
        tags,
        parent_path=path,
        edge_requests=((
            path,
            archive_prefixed("archive_duplicate_member:", member_name),
            "archive_safety",
            2.0,
        ),),
    )


__all__ = (
    "append_duplicate_member_evidence",
    "claim_archive_member_path",
    "zip_member_type_supported",
)
