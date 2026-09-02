"""Canonical archive-member recursion and publication projection owner."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scanners.archives.context import ArchiveScanContext
from Virus_Scan.scanners.archives.publication_requests import (
    append_archive_graph_publication_request_tags,
)
from Virus_Scan.scanners.archives.text_boundaries import archive_prefixed
from Virus_Scan.utils.tagging import normalize_tags

ArchiveMemberScanner = Callable[[str, int], tuple[list[str], bool]]


def scan_and_publish_extracted_archive_member(
    *,
    path: str,
    name: str,
    extracted: str,
    archive_depth: int,
    context: ArchiveScanContext,
    tags: list[str],
    member_scanner: ArchiveMemberScanner,
) -> bool:
    """Bind one extracted member to logical identity, scan it, then publish facts."""
    context.register_extracted_member_identity(
        container_path=path,
        member_name=name,
        extracted_path=extracted,
    )
    inner_tags, inner_suspicious = member_scanner(extracted, archive_depth + 1)
    publish_archive_member_graph(
        path=path,
        name=name,
        extracted=extracted,
        context=context,
        tags=tags,
        norm_inner=normalize_tags(inner_tags),
    )
    return bool(inner_suspicious)


def publish_archive_member_graph(
    *,
    path: str,
    name: str,
    extracted: str,
    context: ArchiveScanContext,
    tags: list[str],
    norm_inner: list[str],
) -> None:
    """Project one member and its findings through stable logical identities."""
    tags.extend([archive_prefixed("archive_inner:", tag) for tag in norm_inner[:60]])
    tags.extend(norm_inner)
    parent_identity = context.logical_container_identity(path)
    child = context.logical_member_identity(container_path=path, member_name=name)
    edge_requests = [(parent_identity, child, "archive_member", 1.0)]
    edge_requests.extend(
        (child, archive_prefixed("tag:", tag), "tag", 0.8)
        for tag in norm_inner[:80]
    )
    append_archive_graph_publication_request_tags(
        tags,
        parent_path=parent_identity,
        member_name=name,
        extracted_path=extracted,
        member_tags=tuple(norm_inner),
        edge_requests=tuple(edge_requests),
    )


__all__ = (
    "ArchiveMemberScanner",
    "publish_archive_member_graph",
    "scan_and_publish_extracted_archive_member",
)
