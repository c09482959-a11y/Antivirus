"""ZIP archive recursion scanner."""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Callable
import zipfile

from Virus_Scan.scanners.archives.path_safety import safe_archive_child_path_with_reason
from Virus_Scan.runtime.api import archive_ecosystem_score
from Virus_Scan.runtime.api import ResourceQuotaExceeded, extract_zip_member_with_quota
from Virus_Scan.runtime.api import record_detector_error
from Virus_Scan.scanners.archives.bounds import member_limit_tags
from Virus_Scan.scanners.archives.context import ArchiveScanContext
from Virus_Scan.scanners.archives.evidence import (
    ArchiveMemberFailureRequest,
    append_archive_member_failure_evidence,
    append_archive_member_policy_evidence,
    append_archive_quota_evidence,
)
from Virus_Scan.scanners.archives.ecosystem import ArchiveEcosystemGateRequest, apply_ecosystem_gate, archive_ecosystem_inputs
from Virus_Scan.scanners.archives.ecosystem_evidence import append_archive_ecosystem_failure_evidence
from Virus_Scan.scanners.archives.malformed import ARCHIVE_SCAN_EXCEPTIONS
from Virus_Scan.scanners.archives.member_publication import scan_and_publish_extracted_archive_member
from Virus_Scan.scanners.archives.member_identity import (
    append_duplicate_member_evidence,
    claim_archive_member_path,
    zip_member_type_supported,
)
from Virus_Scan.scanners.archives.publication_requests import append_archive_graph_publication_request_tags
from Virus_Scan.scanners.archives.text_boundaries import archive_colon_join, archive_exact_attr_int, archive_exact_attr_text, archive_prefixed

ArchiveMemberScanner = Callable[[str, int], tuple[list[str], bool]]


def scan_zip_archive(path: str, archive_depth: int, max_members: int, context: ArchiveScanContext, tags: list[str], member_scanner: ArchiveMemberScanner) -> bool:
    """Scan ZIP members with archive-owned recursion and graph evidence."""
    suspicious = False
    tags.append("zip_archive")
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(path, "r") as archive:
        infos, original_count, suspicious = _bounded_zip_infos(
            path,
            archive,
            archive_depth,
            max_members,
            tags,
            suspicious=suspicious,
        )
        suspicious = member_limit_tags(tags, original_count, max_members, context.quota) or suspicious
        for member in infos[:max_members]:
            member_suspicious, stop = _scan_zip_member(
                path, archive_depth, archive, member, tmp, context, tags, member_scanner,
            )
            suspicious = suspicious or member_suspicious
            if stop:
                break
    return suspicious


def _bounded_zip_infos(path: str, archive: zipfile.ZipFile, archive_depth: int, max_members: int, tags: list[str], *, suspicious: bool) -> tuple[list[zipfile.ZipInfo], int, bool]:
    infos = archive.infolist()
    original_count = len(infos)
    try:
        if any(type(info) is not zipfile.ZipInfo for info in infos):
            raise TypeError("unsafe_zip_member_record")
        names = tuple(archive_exact_attr_text(info, zipfile.ZipInfo, "filename") for info in infos)
        ecosystem_inputs = archive_ecosystem_inputs(
            members=original_count,
            compressed_bytes=sum(archive_exact_attr_int(info, zipfile.ZipInfo, "compress_size") for info in infos),
            extracted_bytes=sum(archive_exact_attr_int(info, zipfile.ZipInfo, "file_size") for info in infos),
            depth=archive_depth,
            names=names,
        )
        ecosystem = archive_ecosystem_score(
            members=int(ecosystem_inputs["members"]),
            compressed_bytes=int(ecosystem_inputs["compressed_bytes"]),
            extracted_bytes=int(ecosystem_inputs["extracted_bytes"]),
            depth=int(ecosystem_inputs["depth"]),
            nested_archives=int(ecosystem_inputs["nested_archives"]),
            corrupt_members=int(ecosystem_inputs["corrupt_members"]),
            distinct_extensions=int(ecosystem_inputs["distinct_extensions"]),
        )
        suspicious, member_limit = apply_ecosystem_gate(ArchiveEcosystemGateRequest(tags, suspicious, ecosystem.score, original_count, max_members, path))
        infos = infos[:member_limit]
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        record_detector_error("scan_archive_file.ecosystem_score", exc, context={"file": path})
        tags[:] = append_archive_ecosystem_failure_evidence(tags, path=path)
        suspicious = True
    return infos, original_count, suspicious


def _scan_zip_member(
    path: str,
    archive_depth: int,
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    tmp: str,
    context: ArchiveScanContext,
    tags: list[str],
    member_scanner: ArchiveMemberScanner,
) -> tuple[bool, bool]:
    name = archive_exact_attr_text(member, zipfile.ZipInfo, "filename")
    try:
        if member.is_dir():
            return False, False
        if not zip_member_type_supported(member):
            _append_member_policy(
                tags,
                path,
                name,
                "archive_unsupported_member_type",
                archive_prefixed("unsupported zip member type: ", name),
            )
            append_archive_graph_publication_request_tags(
                tags,
                parent_path=context.logical_container_identity(path),
                edge_requests=((
                    context.logical_container_identity(path),
                    archive_prefixed("archive_unsupported_member:", name),
                    "archive_safety",
                    1.5,
                ),),
            )
            return True, False
        target, path_reason = safe_archive_child_path_with_reason(tmp, name)
        if target is None:
            _append_member_policy(tags, path, name, "archive_blocked_unsafe_path", archive_prefixed("unsafe archive member path: ", path_reason))
            append_archive_graph_publication_request_tags(
                tags,
                parent_path=context.logical_container_identity(path),
                edge_requests=((context.logical_container_identity(path), archive_prefixed("archive_blocked:", name), "archive_safety", 2.0),),
            )
            return True, False
        if not claim_archive_member_path(
            context,
            container_path=path,
            extraction_root=tmp,
            target=target,
        ):
            append_duplicate_member_evidence(tags, path=path, member_name=name)
            return True, False
        extracted = extract_zip_member_with_quota(
            archive, member, tmp, tracker=context.quota,
        )
        if not extracted or not Path(extracted).is_file():
            _append_member_policy(tags, path, name, "archive_member_missing_after_extract", archive_prefixed("archive member did not materialize after extraction: ", name))
            return True, False
        inner_suspicious = scan_and_publish_extracted_archive_member(
            path=path, name=name, extracted=extracted, archive_depth=archive_depth,
            context=context, tags=tags, member_scanner=member_scanner,
        )
        return inner_suspicious, False
    except ResourceQuotaExceeded as exc:
        tag = append_archive_quota_evidence(tags, exc, member_name=name)
        append_archive_graph_publication_request_tags(
            tags,
            parent_path=context.logical_container_identity(path),
            edge_requests=((context.logical_container_identity(path), archive_colon_join("archive_quota", name, tag), "archive_quota", 2.0),),
        )
        return True, tag in {"archive_total_file_limit", "archive_total_byte_limit"}
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        record_detector_error("scan_archive_file.member", exc, context={"file": path, "member": name})
        tags[:] = append_archive_member_failure_evidence(ArchiveMemberFailureRequest(tags, "scan_archive_file.member", exc, path, name, "archive_member_scan_error"))
        return True, False





def _append_member_policy(tags: list[str], path: str, name: str, evidence_tag: str, reason: str) -> None:
    tags[:] = append_archive_member_policy_evidence(tags, path=path, member_name=name, evidence_tag=evidence_tag, reason=reason)



__all__ = ("scan_zip_archive",)
