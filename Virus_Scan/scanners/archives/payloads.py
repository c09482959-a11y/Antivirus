"""Archive member payload and pickle evidence boundary."""

from __future__ import annotations

from Virus_Scan.scanners.archives.evidence import (
    append_archive_member_finding_publication_evidence,
    append_archive_member_payload_failure_publication_evidence,
)
from Virus_Scan.scanners.archives.malformed import ARCHIVE_SCAN_EXCEPTIONS, append_archive_failure_evidence
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.scanners.api.payload_contracts import decoded_payload_behavior_tags, decoded_payload_tags, embedded_payload_records_from_bytes
from Virus_Scan.scanners.api.pickle_contracts import pickle_embedded_payload_tags
from Virus_Scan.scanners.archives.payload_no_hook import archive_payload_behavior_record, archive_payload_items, archive_payload_magic_tag, archive_payload_mapping_value, archive_payload_path
from Virus_Scan.scanners.archives.payload_publication_contracts import ArchivePayloadPublicationRequest
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE, normalize_tags

_ARCHIVE_POLICY = load_archive_policy_snapshot()
_PICKLE_SUSPICIOUS_TAGS = frozenset({
    "pickle_dangerous_global",
    "pickle_reduce_opcode",
    "process_exec",
    "script_execution",
})
_PAYLOAD_SUSPICIOUS_TAGS = frozenset({
    "payload_decode_confirmed",
    "decoded_binary_payload",
    "decoded_pe_payload",
    "encoded_payload",
})
_FAILURE_EVIDENCE_TAGS = frozenset({
    "scanner_failure",
    "scanner_degraded",
    "scan_incomplete",
    "scanner_failure_evidence_recorded",
    "pickle_failure_evidence_recorded",
    "payload_failure_evidence_recorded",
    "payload_decode_failure",
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    DETECTION_STAGE_DEGRADED_TAG,
})

def archive_member_payload_tags(path: str, raw: bytes, text: str) -> tuple[list[str], bool]:
    """Return archive-owned payload/pickle tags for one extracted member."""
    tags: list[str] = []
    suspicious = False
    try:
        safe_path = archive_payload_path(path)
        if type(raw) is not bytes:
            raise TypeError("archive_member_payload_bytes_invalid")
        if len(raw) > _ARCHIVE_POLICY.member_text_max_size:
            raise ValueError("archive_member_payload_bytes_oversize")
        if type(text) is not str:
            raise TypeError("archive_member_payload_text_invalid")
        suspicious = _append_pickle_payload_tags(tags, raw, safe_path) or suspicious
        suspicious = _append_decoded_payload_tags(tags, text, safe_path) or suspicious
        suspicious = _append_embedded_payload_record_tags(tags, raw, safe_path) or suspicious
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        tags = append_archive_failure_evidence(tags, "archive_member_payload_tags", exc, path, "archive_member_payload_scan_error")
        suspicious = True
    return (normalize_tags(tags), suspicious)

def _append_pickle_payload_tags(tags: list[str], raw: bytes, path: str) -> bool:
    pickle_tags = list(pickle_embedded_payload_tags(raw, path=path) or [])
    if not pickle_tags:
        return False
    tags.extend(["archive_member_pickle_payload"])
    tags.extend(pickle_tags)
    return _publish_finding_or_failure(
        ArchivePayloadPublicationRequest(
            tags=tags,
            observed_tags=pickle_tags,
            suspicious_tags=_PICKLE_SUSPICIOUS_TAGS,
            path=path,
            finding_tag="archive_member_pickle_payload_finding",
            failure_tag="archive_member_pickle_payload_failure",
        )
    )

def _append_decoded_payload_tags(tags: list[str], text: str, path: str) -> bool:
    decoded_tags = list(decoded_payload_tags(text, path=path, finalize=False) or [])
    if not decoded_tags:
        return False
    tags.extend(["archive_member_decoded_payload_observed"])
    tags.extend(decoded_tags)
    return _publish_finding_or_failure(
        ArchivePayloadPublicationRequest(
            tags=tags,
            observed_tags=decoded_tags,
            suspicious_tags=_PAYLOAD_SUSPICIOUS_TAGS,
            path=path,
            finding_tag="archive_member_decoded_payload_finding",
            failure_tag="archive_member_decoded_payload_failure",
        )
    )

def _append_embedded_payload_record_tags(tags: list[str], raw: bytes, path: str) -> bool:
    suspicious = False
    records = archive_payload_items(embedded_payload_records_from_bytes(raw, encoding_hint="archive_member"), limit=32)
    if records is None:
        tags.extend(["archive_member_payload_decode_failure", "archive_member_payload_record_sequence_unsafe"])
        tags[:] = append_archive_member_payload_failure_publication_evidence(
            tags,
            path=path,
            member_name=path,
            failure_tag="archive_member_payload_record_sequence_unsafe",
        )
        return True
    for record in records:
        record_tags = _record_behavior_tags(record)
        if record_tags:
            tags.extend(["archive_member_embedded_payload_observed"])
            tags.extend(record_tags)
            suspicious = _publish_finding_or_failure(
                ArchivePayloadPublicationRequest(
                    tags=tags,
                    observed_tags=record_tags,
                    suspicious_tags=_PAYLOAD_SUSPICIOUS_TAGS,
                    path=path,
                    finding_tag="archive_member_embedded_payload_finding",
                    failure_tag="archive_member_embedded_payload_failure",
                )
            ) or suspicious
        failure_tags, failure_reason = archive_payload_mapping_value(record, "failure_tags")
        normalized_failure_tags = normalize_tags(failure_tags)
        if failure_reason or normalized_failure_tags:
            tags.extend(["archive_member_payload_decode_failure"])
            if failure_reason:
                tags.append(failure_reason)
            tags.extend(normalized_failure_tags)
            tags[:] = append_archive_member_payload_failure_publication_evidence(
                tags,
                path=path,
                member_name=path,
                failure_tag="archive_member_payload_decode_failure",
            )
            suspicious = True
    return suspicious

def _record_behavior_tags(record: object) -> list[str]:
    safe_record, failures = archive_payload_behavior_record(record)
    record_tags = list(decoded_payload_behavior_tags(safe_record, []) or [])
    for failure in failures:
        record_tags.extend([failure, "payload_failure_evidence_recorded", "archive_final_json_must_record"])
    magic_value, magic_reason = archive_payload_mapping_value(record, "binary_magic")
    if magic_value is not None or magic_reason:
        magic, reason = archive_payload_magic_tag(magic_value)
        if magic_reason or reason:
            record_tags.extend([magic_reason or reason, "payload_failure_evidence_recorded", "archive_final_json_must_record"])
        else:
            record_tags.extend(["payload_decode_candidate", "decoded_binary_payload", "decoded_" + magic + "_payload"])
    return record_tags


def _publish_finding_or_failure(request: ArchivePayloadPublicationRequest) -> bool:
    suspicious = _has_suspicious_tag(request.observed_tags, request.suspicious_tags)
    failure = _has_failure_evidence_tag(request.observed_tags)
    if suspicious:
        request.tags[:] = append_archive_member_finding_publication_evidence(
            request.tags,
            path=request.path,
            member_name=request.path,
            finding_tag=request.finding_tag,
        )
    if failure:
        request.tags[:] = append_archive_member_payload_failure_publication_evidence(
            request.tags,
            path=request.path,
            member_name=request.path,
            failure_tag=request.failure_tag,
        )
    return suspicious or failure


def _has_suspicious_tag(tags: list[str], needles: frozenset[str]) -> bool:
    lowered = {tag.lower() for tag in normalize_tags(tags)}
    return bool(lowered & needles)


def _has_failure_evidence_tag(tags: list[str]) -> bool:
    lowered = {tag.lower() for tag in normalize_tags(tags)}
    if lowered & _FAILURE_EVIDENCE_TAGS:
        return True
    return any(
        tag.startswith("scanner_failure_evidence:") or tag.endswith("_final_json_must_record")
        for tag in lowered
    )


__all__ = ("archive_member_payload_tags",)
