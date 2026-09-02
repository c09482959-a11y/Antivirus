"""TAR archive boundary scanner."""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Callable
import tarfile

from Virus_Scan.scanners.archives.path_safety import safe_archive_child_path_with_reason
from Virus_Scan.runtime.api import archive_ecosystem_score
from Virus_Scan.runtime.api import ResourceQuotaExceeded
from Virus_Scan.runtime.api import record_detector_error
from Virus_Scan.scanners.archives.bounds import member_limit_tags
from Virus_Scan.scanners.archives.context import ArchiveScanContext
from Virus_Scan.scanners.archives.ecosystem import ArchiveEcosystemGateRequest, apply_ecosystem_gate, archive_ecosystem_inputs
from Virus_Scan.scanners.archives.ecosystem_evidence import append_archive_ecosystem_failure_evidence
from Virus_Scan.scanners.archives.evidence import (
    ArchiveMemberFailureRequest,
    append_archive_member_failure_evidence,
    append_archive_member_policy_evidence,
    append_archive_quota_evidence,
)
from Virus_Scan.scanners.archives.malformed import ARCHIVE_SCAN_EXCEPTIONS
from Virus_Scan.scanners.archives.member_publication import scan_and_publish_extracted_archive_member
from Virus_Scan.scanners.archives.member_identity import (
    append_duplicate_member_evidence,
    claim_archive_member_path,
)
from Virus_Scan.scanners.archives.publication_requests import append_archive_graph_publication_request_tags
from Virus_Scan.scanners.archives.text_boundaries import archive_colon_join, archive_exact_attr_int, archive_exact_attr_text, archive_prefixed

ArchiveMemberScanner = Callable[[str, int], tuple[list[str], bool]]


def scan_tar_archive(path: str, archive_depth: int, max_members: int, context: ArchiveScanContext, tags: list[str], member_scanner: ArchiveMemberScanner) -> bool:
    """Scan TAR members with archive-owned recursion/size evidence."""
    suspicious = False
    tags.append("tar_archive")
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(path, "r:*") as archive:
        members, original_count, suspicious = _bounded_tar_members(
            path,
            archive,
            archive_depth,
            max_members,
            tags,
            suspicious=suspicious,
        )
        suspicious = member_limit_tags(tags, original_count, max_members, context.quota) or suspicious
        for member in members[:max_members]:
            member_suspicious, stop = _scan_tar_member(
                path, archive_depth, archive, member, tmp, context, tags, member_scanner,
            )
            suspicious = suspicious or member_suspicious
            if stop:
                break
    return suspicious


def _bounded_tar_members(path: str, archive: tarfile.TarFile, archive_depth: int, max_members: int, tags: list[str], *, suspicious: bool) -> tuple[list[tarfile.TarInfo], int, bool]:
    members = archive.getmembers()
    original_count = len(members)
    try:
        if any(type(member) is not tarfile.TarInfo for member in members):
            raise TypeError("unsafe_tar_member_record")
        names = tuple(archive_exact_attr_text(member, tarfile.TarInfo, "name") for member in members)
        ecosystem_inputs = archive_ecosystem_inputs(
            members=original_count,
            compressed_bytes=Path(path).stat().st_size,
            extracted_bytes=sum(archive_exact_attr_int(member, tarfile.TarInfo, "size") for member in members),
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
        members = members[:member_limit]
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        record_detector_error("scan_archive_file.tar_ecosystem_score", exc, context={"file": path})
        tags[:] = append_archive_ecosystem_failure_evidence(tags, path=path)
        suspicious = True
    return members, original_count, suspicious


def _scan_tar_member(
    path: str,
    archive_depth: int,
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    tmp: str,
    context: ArchiveScanContext,
    tags: list[str],
    member_scanner: ArchiveMemberScanner,
) -> tuple[bool, bool]:
    name = archive_exact_attr_text(member, tarfile.TarInfo, "name")
    try:
        if not member.isfile():
            if member.isdir():
                return False, False
            _append_member_policy(tags, path, name, "archive_unsupported_member_type", archive_prefixed("unsupported tar member type: ", name))
            append_archive_graph_publication_request_tags(
                tags,
                parent_path=context.logical_container_identity(path),
                edge_requests=((context.logical_container_identity(path), archive_prefixed("archive_unsupported_member:", name), "archive_safety", 1.5),),
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
        context.quota.allow_tar_member(member)
        extracted = _extract_tar_member(archive, member, target.as_posix())
        context.quota.record_tar_member(member)
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
        record_detector_error("scan_archive_file.tar_member", exc, context={"file": path, "member": name})
        tags[:] = append_archive_member_failure_evidence(ArchiveMemberFailureRequest(tags, "scan_archive_file.tar_member", exc, path, name, "archive_member_scan_error"))
        return True, False




def _append_member_policy(tags: list[str], path: str, name: str, evidence_tag: str, reason: str) -> None:
    tags[:] = append_archive_member_policy_evidence(tags, path=path, member_name=name, evidence_tag=evidence_tag, reason=reason)



def _extract_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, target: str) -> str:
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    source = archive.extractfile(member)
    if source is None:
        raise tarfile.ExtractError(archive_prefixed("tar member has no extractable stream: ", archive_exact_attr_text(member, tarfile.TarInfo, "name")))
    with source, Path(target).open("wb") as output:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
    return target


__all__ = ("scan_tar_archive",)
