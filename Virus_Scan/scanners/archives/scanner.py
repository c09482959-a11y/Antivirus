"""Archive recursion orchestration."""

from __future__ import annotations

from functools import partial
from dataclasses import replace

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.runtime.api import ArchiveScanLimits
from Virus_Scan.runtime.api import ExtractionQuotaTracker, ResourceQuotaExceeded
from Virus_Scan.runtime.api import is_programmer_error
from Virus_Scan.scanners.archives.context import ArchiveScanContext
from Virus_Scan.scanners.archives.evidence import append_archive_container_policy_evidence, append_archive_quota_evidence
from Virus_Scan.scanners.archives.malformed import ARCHIVE_SCAN_EXCEPTIONS, append_archive_failure_evidence
from Virus_Scan.scanners.archives.member_scan import scan_archive_member
from Virus_Scan.scanners.archives.member_view import ArchiveContainerKind, detect_archive_container_kind
from Virus_Scan.scanners.archives.tar_scanner import scan_tar_archive
from Virus_Scan.scanners.archives.zip_scanner import scan_zip_archive
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.scanners.archives.text_boundaries import archive_delimited_join, archive_prefixed, archive_lower_text, archive_nonnegative_int

_ARCHIVE_POLICY = load_archive_policy_snapshot()
_ARCHIVE_EXTENSIONS = frozenset({"zip", "tar", "gz", "tgz", "bz2", "xz", "rpa", "rar", "7z"})


def _resolved_archive_limits(
    *, max_depth: int, max_members: int, max_member_size: int,
) -> ArchiveScanLimits:
    runtime_limits = ArchiveScanLimits.from_env()
    depth = min(archive_nonnegative_int(max_depth), archive_nonnegative_int(runtime_limits.max_depth))
    members = min(archive_nonnegative_int(max_members), archive_nonnegative_int(runtime_limits.max_members))
    member_size = min(
        archive_nonnegative_int(max_member_size),
        archive_nonnegative_int(runtime_limits.max_member_size),
    )
    return replace(
        runtime_limits,
        max_depth=depth,
        max_members=members,
        max_member_size=member_size,
    )


def scan_extracted_archive_member(
    path: str,
    archive_depth: int = 0,
    max_depth: int = _ARCHIVE_POLICY.default_max_depth,
    max_members: int = _ARCHIVE_POLICY.default_max_members,
    max_member_size: int = _ARCHIVE_POLICY.default_max_member_size,
) -> tuple[list[str], bool]:
    """Scan one independently supplied member under one new root archive context."""
    limits = _resolved_archive_limits(
        max_depth=max_depth, max_members=max_members, max_member_size=max_member_size,
    )
    context = ArchiveScanContext.create(limits, initial_depth=archive_nonnegative_int(archive_depth))
    context.register_root_identity(path)
    return _scan_extracted_archive_member_with_context(path, archive_depth, context)


def _scan_extracted_archive_member_with_context(
    path: str, archive_depth: int, context: ArchiveScanContext,
) -> tuple[list[str], bool]:
    archive_scanner = partial(_scan_archive_file_with_context, context=context)
    return scan_archive_member(path, archive_depth, archive_scanner)


def scan_archive_file(
    path: str,
    archive_depth: int = 0,
    max_depth: int = _ARCHIVE_POLICY.default_max_depth,
    max_members: int = _ARCHIVE_POLICY.default_max_members,
    max_member_size: int = _ARCHIVE_POLICY.default_max_member_size,
) -> tuple[list[str], bool]:
    """Scan one root archive using one shared quota context for its full tree."""
    limits = _resolved_archive_limits(
        max_depth=max_depth, max_members=max_members, max_member_size=max_member_size,
    )
    context = ArchiveScanContext.create(limits, initial_depth=archive_nonnegative_int(archive_depth))
    context.register_root_identity(path)
    try:
        container_kind = detect_archive_container_kind(path)
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        tags = append_archive_failure_evidence(
            ["archive"], "scan_archive_file.identity", exc, path, "archive_identity_error",
        )
        return (normalize_tags(tags), True)
    return _scan_archive_file_with_context(
        path, archive_depth, container_kind, context=context,
    )


def _scan_archive_file_with_context(
    path: str,
    archive_depth: int,
    container_kind: ArchiveContainerKind,
    *,
    context: ArchiveScanContext,
) -> tuple[list[str], bool]:
    if type(context) is not ArchiveScanContext:
        raise TypeError("archive_scan_context_required")
    if type(container_kind) is not str or container_kind not in {"zip", "tar", "unknown"}:
        raise TypeError("archive_container_kind_invalid")
    tags = ["archive"]
    suspicious = False
    try:
        context.check_depth(archive_nonnegative_int(archive_depth))
    except ResourceQuotaExceeded as exc:
        append_archive_quota_evidence(tags, exc)
        return (normalize_tags(tags), True)
    try:
        member_scanner = partial(
            _scan_extracted_archive_member_with_context,
            context=context,
        )
        if container_kind == "zip":
            suspicious = scan_zip_archive(
                path, archive_depth, context.limits.max_members, context, tags, member_scanner,
            )
        elif container_kind == "tar":
            suspicious = scan_tar_archive(
                path, archive_depth, context.limits.max_members, context, tags, member_scanner,
            )
        else:
            suspicious = _append_unknown_or_malformed_container_tags(path, tags)
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        tags = append_archive_failure_evidence(
            tags, "scan_archive_file", exc, path, "archive_scan_error",
        )
        suspicious = True
    return (normalize_tags(tags), suspicious)


def _append_unknown_or_malformed_container_tags(path: str, tags: list[str]) -> bool:
    tags.append("unknown_archive")
    ext = archive_lower_text(get_scan_extension(path)).lstrip(".")
    if ext in _ARCHIVE_EXTENSIONS:
        tags.extend(["malformed_container", archive_delimited_join("_", "malformed", ext, "container")])
        tags[:] = append_archive_container_policy_evidence(
            tags,
            path=path,
            evidence_tag="archive_unsupported_container",
            reason=archive_prefixed("unsupported or malformed archive container extension: ", ext),
        )
        return True
    return False


__all__ = ("scan_archive_file", "scan_extracted_archive_member")
