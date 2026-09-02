"""Archive recursion/member bound evidence helpers."""

from __future__ import annotations

from Virus_Scan.runtime.api import ExtractionQuotaTracker, ResourceQuotaExceeded
from Virus_Scan.scanners.archives.evidence import append_archive_quota_evidence


def member_limit_tags(tags: list[str], member_count: int, max_members: int, quota: ExtractionQuotaTracker) -> bool:
    """Append explicit member-count boundary evidence and return suspicious state."""
    suspicious = False
    if member_count > max_members:
        append_archive_quota_evidence(tags, ResourceQuotaExceeded("archive_member_limit"))
        suspicious = True
    try:
        quota.check_member_count(member_count)
    except ResourceQuotaExceeded as exc:
        append_archive_quota_evidence(tags, exc)
        suspicious = True
    return suspicious


__all__ = ("member_limit_tags",)
