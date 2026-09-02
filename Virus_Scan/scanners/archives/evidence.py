"""Archive evidence helpers for bounded archive/RPA scanners."""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.runtime.api import ResourceQuotaExceeded, quota_tag
from Virus_Scan.scanners.archives.evidence_no_hook import (
    append_final_json_marker as _append_final_json_marker,
    append_unique,
    archive_evidence_path,
    archive_evidence_present,
    archive_evidence_tag,
    archive_evidence_tags,
    with_extraction_failure,
)
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags

@dataclass(frozen=True, slots=True)
class ArchiveMemberFailureRequest:
    tags: list[str]
    scanner_name: object
    error: BaseException | str
    path: object
    member_name: object = None
    failure_tag: object = "archive_member_scan_error"

def append_archive_quota_evidence(tags: list[str], exc: ResourceQuotaExceeded, *, member_name: str | None = None) -> str:
    """Append deterministic archive quota evidence and return the canonical quota tag."""
    tag = quota_tag(exc)
    evidence_tags = with_extraction_failure(tags)
    append_unique(evidence_tags, tag)
    append_unique(evidence_tags, "archive_member_quota_exceeded")
    if archive_evidence_present(member_name):
        append_unique(evidence_tags, "archive_member_quota_member")
    evidence_tags = scanner_failure_evidence_tags(
        "archive",
        "archive_quota",
        exc,
        evidence_tags,
        error_category="archive_quota_boundary",
        error_source="archives.evidence.append_archive_quota_evidence",
        file_type="archive",
    )
    _append_final_json_marker(evidence_tags)
    if type(tags) is list:
        tags[:] = evidence_tags
    return tag

def append_archive_member_failure_evidence(request: ArchiveMemberFailureRequest) -> list[str]:
    """Append deterministic archive-member failure evidence for JSON publication."""
    evidence_tags = with_extraction_failure(request.tags)
    safe_scanner_name = archive_evidence_tag(request.scanner_name, "archive_member_scanner_name_unsafe")
    safe_failure_tag = archive_evidence_tag(request.failure_tag, "archive_member_failure_tag_unsafe")
    if archive_evidence_present(request.member_name):
        append_unique(evidence_tags, "archive_member_failure_member")
    evidence_tags = scanner_failure_evidence_tags(
        "archive",
        safe_failure_tag,
        request.error,
        [*evidence_tags, safe_failure_tag, 'archive_member_failure_evidence_recorded'],
        input_path=archive_evidence_path(request.path),
        error_category="archive_member_boundary_failure",
        error_source=safe_scanner_name,
        file_type="archive_member",
    )
    _append_final_json_marker(evidence_tags)
    return evidence_tags

def append_archive_member_policy_evidence(
    tags: list[str],
    *,
    path: str,
    member_name: str | None = None,
    evidence_tag: str,
    reason: str,
) -> list[str]:
    """Append archive-member policy/boundary evidence without hiding it as clean output."""
    safe_reason = archive_evidence_tag(reason, "archive_member_policy_reason_unsafe")
    return append_archive_member_failure_evidence(
        ArchiveMemberFailureRequest(
            tags,
            "archives.member_policy",
            ValueError(safe_reason),
            path,
            member_name,
            evidence_tag,
        )
    )

def append_archive_container_policy_evidence(
    tags: list[str],
    *,
    path: str,
    evidence_tag: str,
    reason: str,
) -> list[str]:
    """Append malformed/unsupported archive-container evidence for downstream JSON."""
    evidence_tags = with_extraction_failure(tags)
    safe_evidence_tag = archive_evidence_tag(evidence_tag, "archive_container_evidence_tag_unsafe")
    safe_reason = archive_evidence_tag(reason, "archive_container_reason_unsafe")
    evidence_tags = scanner_failure_evidence_tags(
        "archive",
        safe_evidence_tag,
        ValueError(safe_reason),
        [*evidence_tags, safe_evidence_tag, 'archive_container_failure_evidence_recorded'],
        input_path=archive_evidence_path(path),
        error_category="archive_container_boundary_failure",
        error_source="archives.scanner.container_policy",
        file_type="archive",
    )
    _append_final_json_marker(evidence_tags)
    return evidence_tags

def append_archive_member_finding_publication_evidence(
    tags: list[str],
    *,
    path: str,
    member_name: str | None = None,
    finding_tag: str,
) -> list[str]:
    """Append archive-owned publication evidence for suspicious member findings.

    This is intentionally not failure evidence: payload/pickle detections are
    positive scanner findings, but Phase 9 requires that archive/RPA member
    findings that affect output are visible to downstream final JSON/evidence
    publication instead of remaining only as local member tags.
    """
    del path  # Explicitly unused contract parameters.
    evidence_tags = archive_evidence_tags(tags)
    safe_finding_tag = archive_evidence_tag(finding_tag, "archive_member_finding_tag_unsafe")
    for tag in (
        safe_finding_tag,
        "archive_member_finding_evidence_recorded",
        "archive_member_finding:" + safe_finding_tag,
    ):
        append_unique(evidence_tags, tag)
    if archive_evidence_present(member_name):
        append_unique(evidence_tags, "archive_member_finding_member")
    _append_final_json_marker(evidence_tags)
    return evidence_tags

def append_archive_member_payload_failure_publication_evidence(
    tags: list[str],
    *,
    path: str,
    member_name: str | None = None,
    failure_tag: str = "archive_member_payload_failure",
) -> list[str]:
    """Append archive-owned publication evidence for member payload/pickle failures.

    Payload and pickle scanners own their own failure/degraded tags, but Phase 9
    requires archive/RPA member failures that affect archive output to be visible
    to downstream final JSON through an archive-owned publication marker too.
    """
    del path  # Explicitly unused contract parameters.
    evidence_tags = archive_evidence_tags(tags)
    safe_failure_tag = archive_evidence_tag(failure_tag, "archive_member_payload_failure_tag_unsafe")
    for tag in (
        safe_failure_tag,
        "archive_member_payload_failure_evidence_recorded",
        "archive_member_payload_failure:" + safe_failure_tag,
    ):
        append_unique(evidence_tags, tag)
    if archive_evidence_present(member_name):
        append_unique(evidence_tags, "archive_member_payload_failure_member")
    _append_final_json_marker(evidence_tags)
    return evidence_tags

__all__ = (
    'ArchiveMemberFailureRequest',
    'append_archive_container_policy_evidence',
    'append_archive_member_failure_evidence',
    'append_archive_member_finding_publication_evidence',
    'append_archive_member_payload_failure_publication_evidence',
    'append_archive_member_policy_evidence',
    'append_archive_quota_evidence',
)
