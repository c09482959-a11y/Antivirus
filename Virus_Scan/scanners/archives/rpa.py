"""Ren'Py RPA scanner boundary."""

from __future__ import annotations

from pathlib import Path
import zipfile

from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.scanners.archives.rpa_evidence import append_archive_rpa_failure_publication_evidence
from Virus_Scan.scanners.archives.rpa_raw import scan_raw_rpa_text
from Virus_Scan.scanners.archives.malformed import ARCHIVE_SCAN_EXCEPTIONS
from Virus_Scan.scanners.archives.rpa_member_behavior import rpa_decoded_member_behavior_tags
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.scanners.api.pickle_contracts import pickle_embedded_payload_tags
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    normalize_tags,
)

from Virus_Scan.scanners.archives.scanner import scan_archive_file
from Virus_Scan.scanners.archives.text_boundaries import archive_colon_join
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

_ARCHIVE_POLICY = load_archive_policy_snapshot()
_RPA_DEGRADED_MARKERS = frozenset({
    "scanner_failure",
    "scanner_degraded",
    "scan_incomplete",
    "pickle_final_json_must_record",
    "pickle_failure_evidence_recorded",
    "rpa_failure_evidence_recorded",
    "archive_final_json_must_record",
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    DETECTION_STAGE_DEGRADED_TAG,
})


def _rpa_degraded_or_failure_tags(values: list[str]) -> bool:
    lowered = {tag.lower() for tag in normalize_tags(values)}
    if lowered & _RPA_DEGRADED_MARKERS:
        return True
    return any(tag.startswith("scanner_failure_evidence:") for tag in lowered)


def _append_rpa_failure_publication_tags(
    tags: list[str],
    *,
    path: str,
    stage: str,
    exc: BaseException | str,
    failure_tag: str,
) -> None:
    tags[:] = append_archive_rpa_failure_publication_evidence(
        tags,
        path=path,
        stage=stage,
        exc=exc,
        failure_tag=failure_tag,
    )


def _scan_rpa_pickle_payload(data: bytes, path: str, tags: list[str]) -> bool:
    pickle_tags = list(pickle_embedded_payload_tags(data, path=path) or [])
    tags.extend(pickle_tags)
    if not _rpa_degraded_or_failure_tags(pickle_tags):
        return False
    _append_rpa_failure_publication_tags(
        tags,
        path=path,
        stage="rpa_pickle_payload",
        exc="rpa pickle payload degraded/failure evidence present",
        failure_tag="rpa_pickle_payload_failure",
    )
    return True


def _scan_rpa_decoded_member_behavior(data: bytes, path: str, tags: list[str]) -> bool:
    behavior_tags = list(rpa_decoded_member_behavior_tags(data, path=path) or [])
    tags.extend(behavior_tags)
    if not _rpa_degraded_or_failure_tags(behavior_tags):
        return False
    _append_rpa_failure_publication_tags(
        tags,
        path=path,
        stage="rpa_decoded_member_behavior",
        exc="rpa decoded member behavior degraded/failure evidence present",
        failure_tag="rpa_decoded_member_failure",
    )
    return True


def _scan_rpa_zip_container(path: str, tags: list[str]) -> bool:
    tags.append("rpa_zip_container")
    tags.append("rpa_raw_backpressure_bounded")
    archive_tags, archive_suspicious = scan_archive_file(
        path,
        archive_depth=0,
        max_depth=_ARCHIVE_POLICY.rpa_zip_max_depth,
        max_members=_ARCHIVE_POLICY.rpa_zip_max_members,
        max_member_size=_ARCHIVE_POLICY.rpa_zip_max_member_size,
    )
    tags.extend(archive_tags)
    return bool(archive_suspicious)


def scan_rpa_file(path: str) -> tuple[list[str], bool]:
    """Scan a Ren'Py RPA archive or RPA-like raw container."""
    tags = ["rpa_archive", "renpy_asset_archive", "rpa_raw_backpressure_bounded"]
    suspicious = False
    try:
        with Path(path).open("rb") as file_obj:
            data = file_obj.read(min(Path(path).stat().st_size, _ARCHIVE_POLICY.rpa_read_max_bytes))
        text = data.decode("latin1", errors="ignore").lower()
        try:
            suspicious = _scan_rpa_pickle_payload(data, path, tags) or suspicious
        except ARCHIVE_SCAN_EXCEPTIONS as exc:
            tags.extend(scanner_failure_tags("scan_rpa_file.pickle_payload", exc, ["rpa_pickle_payload_scan_error"]))
            suspicious = True
            _append_rpa_failure_publication_tags(
                tags,
                path=path,
                stage="rpa_pickle_payload",
                exc=exc,
                failure_tag="rpa_pickle_payload_scan_error",
            )
            log_error(archive_colon_join("rpa pickle graph scan failed for", path, no_hook_type_name(exc)))
        try:
            suspicious = _scan_rpa_decoded_member_behavior(data, path, tags) or suspicious
        except ARCHIVE_SCAN_EXCEPTIONS as exc:
            tags.extend(scanner_failure_tags("scan_rpa_file.decoded_member_behavior", exc, ["rpa_decoded_member_scan_error"]))
            suspicious = True
            _append_rpa_failure_publication_tags(
                tags,
                path=path,
                stage="rpa_decoded_member_behavior",
                exc=exc,
                failure_tag="rpa_decoded_member_scan_error",
            )
            log_error(archive_colon_join("rpa decoded member behavior scan failed for", path, no_hook_type_name(exc)))
        if zipfile.is_zipfile(path):
            suspicious = _scan_rpa_zip_container(path, tags) or suspicious
        else:
            suspicious = scan_raw_rpa_text(path, data, text, tags) or suspicious
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        log_error(archive_colon_join("scan_rpa_file failed for", path, no_hook_type_name(exc)))
        tags = scanner_failure_tags("scan_rpa_file", exc, [*tags, 'rpa_scan_error'])
        suspicious = True
        _append_rpa_failure_publication_tags(
            tags,
            path=path,
            stage="rpa_scan",
            exc=exc,
            failure_tag="rpa_scan_error",
        )
    if _rpa_degraded_or_failure_tags(tags):
        suspicious = True
        if "archive_rpa_failure_evidence_recorded" not in tags:
            _append_rpa_failure_publication_tags(
                tags,
                path=path,
                stage="rpa_degraded",
                exc="rpa degraded/failure evidence present",
                failure_tag="rpa_degraded_failure",
            )
    return (normalize_tags(tags), suspicious)


__all__ = ("scan_rpa_file",)
