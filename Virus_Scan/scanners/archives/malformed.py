"""Archive malformed-input exception and evidence helpers."""

from __future__ import annotations

from tarfile import TarError
from zipfile import BadZipFile

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.runtime.api import EXTRACTION_FAILURE, append_failure_domain
from Virus_Scan.runtime.api import record_detector_error
from Virus_Scan.runtime.api import scanner_failure_tags
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags

ARCHIVE_SCAN_EXCEPTIONS = (*IO_CONFIGURATION_ERRORS, BadZipFile, TarError)


def append_archive_failure_evidence(tags: list[str], scanner_name: str, exc: BaseException, path: str, failure_tag: str) -> list[str]:
    """Append deterministic malformed/degraded archive evidence for recoverable archive errors."""
    record_detector_error(scanner_name, exc, context={"file": path})
    append_failure_domain(tags, EXTRACTION_FAILURE)
    evidence_tags = scanner_failure_tags(scanner_name, exc, [*tags, failure_tag])
    evidence_tags = scanner_failure_evidence_tags(
        "archive",
        failure_tag,
        exc,
        evidence_tags,
        input_path=path,
        error_category="archive_recoverable_failure",
        error_source=scanner_name,
        file_type="archive",
    )
    if "archive_final_json_must_record" not in evidence_tags:
        evidence_tags.append("archive_final_json_must_record")
    return evidence_tags


__all__ = ("ARCHIVE_SCAN_EXCEPTIONS", "append_archive_failure_evidence")
