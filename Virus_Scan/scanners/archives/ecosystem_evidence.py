"""Archive ecosystem boundary evidence helpers."""

from __future__ import annotations

from Virus_Scan.scanners.archives.evidence_no_hook import append_final_json_marker as _append_final_json_marker, append_unique, archive_evidence_present, archive_evidence_tag, archive_evidence_tags


def append_archive_ecosystem_boundary_evidence(
    tags: list[str],
    *,
    path: str | None = None,
    boundary_tag: str,
    score: float,
    limited: bool,
) -> list[str]:
    """Append archive-owned ecosystem boundary evidence for downstream JSON.

    Archive ecosystem scoring can intentionally reduce member traversal or mark
    the container suspicious before individual member extraction. That decision
    affects final scanner output, so Phase 9 requires an archive-owned evidence
    marker instead of a bare local tag.
    """
    del score  # Explicitly unused contract parameters.
    evidence_tags = archive_evidence_tags(tags)
    safe_boundary_tag = archive_evidence_tag(boundary_tag, "archive_ecosystem_boundary_tag_unsafe")
    for tag in (
        safe_boundary_tag,
        "archive_ecosystem_boundary_evidence_recorded",
        "archive_ecosystem_boundary:" + safe_boundary_tag,
    ):
        append_unique(evidence_tags, tag)
    if archive_evidence_present(path):
        append_unique(evidence_tags, "archive_ecosystem_boundary_path")
    append_unique(evidence_tags, "archive_ecosystem_boundary_score")
    if type(limited) is not bool:
        append_unique(evidence_tags, "archive_ecosystem_limited_flag_unsafe")
    if type(limited) is bool and limited:
        for tag in ("scanner_degraded", "scan_incomplete", "archive_ecosystem_member_scan_limited"):
            append_unique(evidence_tags, tag)
    _append_final_json_marker(evidence_tags)
    return evidence_tags


def append_archive_ecosystem_failure_evidence(
    tags: list[str],
    *,
    path: str | None = None,
    reason_tag: str = "archive_ecosystem_score_failure",
) -> list[str]:
    """Append archive-owned evidence when ecosystem scoring itself fails.

    Ecosystem scoring is part of the archive recursion boundary.  If it cannot
    produce a score, the archive scanner must publish a degraded archive state
    instead of only logging the failure and continuing as if the boundary check
    succeeded.
    """
    evidence_tags = archive_evidence_tags(tags)
    safe_reason_tag = archive_evidence_tag(reason_tag, "archive_ecosystem_failure_tag_unsafe")
    for tag in (
        safe_reason_tag,
        "archive_ecosystem_failure_evidence_recorded",
        "archive_ecosystem_failure:" + safe_reason_tag,
        "scanner_degraded",
        "scan_incomplete",
    ):
        append_unique(evidence_tags, tag)
    if archive_evidence_present(path):
        append_unique(evidence_tags, "archive_ecosystem_failure_path")
    _append_final_json_marker(evidence_tags)
    return evidence_tags


__all__ = ("append_archive_ecosystem_boundary_evidence", "append_archive_ecosystem_failure_evidence",)
