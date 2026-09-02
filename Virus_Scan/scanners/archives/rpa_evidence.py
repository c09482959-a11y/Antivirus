"""Archive-owned RPA evidence publication helpers."""

from __future__ import annotations

from Virus_Scan.scanners.archives.evidence_no_hook import append_final_json_marker as _append_final_json_marker, append_unique, archive_evidence_path, archive_evidence_present, archive_evidence_tag, archive_evidence_tags, with_extraction_failure
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags


def append_archive_rpa_finding_publication_evidence(
    tags: list[str],
    *,
    path: str,
    finding_tag: str,
) -> list[str]:
    """Append archive-owned publication evidence for raw/custom RPA findings."""
    evidence_tags = archive_evidence_tags(tags)
    safe_finding_tag = archive_evidence_tag(finding_tag, "archive_rpa_finding_tag_unsafe")
    for tag in (safe_finding_tag, "archive_rpa_finding_evidence_recorded", "archive_rpa_finding:" + safe_finding_tag):
        append_unique(evidence_tags, tag)
    if archive_evidence_present(path):
        append_unique(evidence_tags, "archive_rpa_finding_path")
    _append_final_json_marker(evidence_tags)
    return evidence_tags


def append_archive_rpa_failure_publication_evidence(
    tags: list[str],
    *,
    path: str,
    stage: str,
    exc: BaseException | str,
    failure_tag: str = "rpa_scan_error",
) -> list[str]:
    """Append immutable archive/RPA failure evidence for downstream JSON."""
    evidence_base = with_extraction_failure(tags)
    safe_stage = archive_evidence_tag(stage, "archive_rpa_stage_unsafe")
    safe_failure_tag = archive_evidence_tag(failure_tag, "archive_rpa_failure_tag_unsafe")
    evidence_tags = scanner_failure_evidence_tags(
        "archive",
        safe_stage,
        exc,
        [*evidence_base, safe_failure_tag, 'rpa_failure_evidence_recorded', 'archive_rpa_failure_evidence_recorded', 'archive_rpa_failure:' + safe_failure_tag],
        input_path=archive_evidence_path(path),
        error_category="archive_rpa_boundary_failure",
        error_source="archives.rpa." + safe_stage,
        file_type="rpa",
    )
    if archive_evidence_present(path):
        append_unique(evidence_tags, "archive_rpa_failure_path")
    _append_final_json_marker(evidence_tags)
    return evidence_tags


__all__ = (
    "append_archive_rpa_failure_publication_evidence",
    "append_archive_rpa_finding_publication_evidence",
)
