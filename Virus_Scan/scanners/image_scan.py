"""Scanner-owned public image file scanning path."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import (
    deep_scan_fast_assets_enabled,
    deep_scan_thorough_enabled,
    has_any_tag,
    log_error,
    report_scan_stage_progress,
)
from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.binary_appended_payload import scan_appended_payload
from Virus_Scan.scanners.contracts import scanner_contract_bool, scanner_contract_error_message, scanner_contract_join, scanner_contract_text, scanner_failure_evidence_tags
from Virus_Scan.scanners.image_evidence_cache import remember_scan_evidence as _remember_scan_evidence
from Virus_Scan.scanners.config import load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.image_limits import IMAGE_STEGO_MAX_FILE_BYTES
from Virus_Scan.scanners.image_malformed import fast_image_sample_malformed_status
from Virus_Scan.scanners.image_stego import scan_image_stego
from Virus_Scan.scanners.image_tags import rewrite_stego_tags
from Virus_Scan.utils.fast_assets import scan_image_file_fast_triage
from Virus_Scan.utils.tagging import normalize_tags

_SCANNER_LIMITS_POLICY = load_scanner_limits_policy_snapshot()
_SUSPICIOUS_IMAGE_NEEDLES = tuple(
    item.encode("latin1", errors="ignore")
    for item in _SCANNER_LIMITS_POLICY.image_suspicious_binary_needles
)


def _fast_path_image_scan(path: object, artifact_read_snapshot: object) -> object:
    fast_tags, fast_suspicious, fast_sample = scan_image_file_fast_triage(
        path, artifact_read_snapshot=artifact_read_snapshot,
    )
    appended_suspicious = scan_appended_payload(fast_sample, fast_tags)
    fast_suspicious = scanner_contract_bool(fast_suspicious, replacement=False) or scanner_contract_bool(appended_suspicious, replacement=False)
    fast_malformed_status = fast_image_sample_malformed_status(path, fast_sample)
    fast_malformed = fast_malformed_status == "malformed"
    fast_magic_probe_failed = fast_malformed_status == "probe_error"
    fast_decode_failed = has_any_tag(fast_tags, "image_decode_failed", "malformed_image_input")
    if fast_malformed or fast_decode_failed or fast_magic_probe_failed:
        if fast_magic_probe_failed:
            failure_reason = "fast image magic validation failed before a clean/malformed decision"
        else:
            failure_reason = "image extension does not match sampled image magic" if fast_malformed else "fast image triage could not decode image data"
        fast_tags.extend(scanner_failure_evidence_tags(
            "image",
            "fast_image_magic_validation",
            ValueError(failure_reason),
            ["image_decode_failed", "malformed_image_input", "image_fast_triage_malformed"] + (["image_fast_magic_probe_error"] if fast_magic_probe_failed else []),
            input_path=path,
            state="malformed",
            error_category="malformed_image",
        ))
        fast_tags.extend(["image_final_json_must_record", "image_malformed_evidence_recorded"])
    fast_tags = rewrite_stego_tags(fast_tags, data=fast_sample, path=path)
    if fast_malformed or fast_decode_failed:
        fast_tags = [tag for tag in fast_tags if scanner_contract_text(tag, replacement="").lower() not in {"image_fast_triage_clean", "asset_fast_triage_clean"}]
        report_scan_stage_progress("image_fast_triage_malformed")
        return (normalize_tags(fast_tags), True, True)
    if fast_suspicious:
        try:
            _remember_scan_evidence(path, strings_blob=fast_sample.decode("latin1", errors="ignore"), raw_sample=fast_sample, image_fast_sampled=True)
        except SCAN_CONTENT_ERRORS as log_exc:
            record_suppressed_failure("log_error_failure", log_exc, domain="telemetry")
    if not fast_suspicious:
        report_scan_stage_progress("image_fast_triage_clean")
        return (normalize_tags(fast_tags), False, True)
    return (normalize_tags(fast_tags), fast_suspicious, False)


def _try_fast_image_scan(
    path: object,
    artifact_read_snapshot: object,
    deep_scan_fast_assets_reader: object,
) -> tuple[object, bool, bool]:
    tags: object = ()
    suspicious = False
    handled = False
    if deep_scan_fast_assets_reader() and not deep_scan_thorough_enabled():
        try:
            tags, suspicious, handled = _fast_path_image_scan(path, artifact_read_snapshot)
        except SCAN_CONTENT_ERRORS as exc:
            if is_programmer_error(exc):
                raise
            log_error(scanner_contract_join(
                "scan_image_file_fast_triage failed for ",
                scanner_contract_text(path, replacement=""),
                ": ",
                scanner_contract_error_message(exc),
            ))
    return tags, suspicious, handled


def _read_image_scan_data(path: object, artifact_read_snapshot: object) -> tuple[object, object]:
    data: object = None
    failure: object = None
    try:
        snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
        if not snapshot.complete:
            raise OSError(snapshot.unavailable_reason or "image_input_unavailable")
        report_scan_stage_progress("image_read_start")
        expected = min(snapshot.size, IMAGE_STEGO_MAX_FILE_BYTES)
        data = snapshot.read_prefix(expected)
        if len(data) != expected:
            raise OSError("image_snapshot_view_incomplete")
        report_scan_stage_progress("image_read_done", bytes_delta=len(data))
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        log_error(scanner_contract_join(
            "scan_image_file input read failed for ",
            scanner_contract_text(path, replacement=""),
            ": ",
            scanner_contract_error_message(exc),
        ))
        failure = (normalize_tags(scanner_failure_tags("scan_image_file.read", exc, ["image"])), True)
    return data, failure


def _scan_image_data(path: object, data: object) -> tuple[object, bool]:
    tags = ["image"]
    suspicious = False
    low = data.lower() if data else b""
    if b"http://" in data or b"https://" in data:
        tags.append("image_metadata_url_reference")
    if b"powershell" in low:
        tags.append("embedded_command")
        suspicious = True
    if any(needle in low for needle in _SUSPICIOUS_IMAGE_NEEDLES):
        tags += ["embedded_command_or_url", "image_embedded_suspicious_string"]
        suspicious = True
    stego_tags, stego_suspicious = scan_image_stego(path, data=data)
    tags.extend(stego_tags or [])
    if has_any_tag(stego_tags, "image_appended_payload", "image_payload_confirmed"):
        tags.append("image_appended_payload")
    suspicious = suspicious or bool(stego_suspicious)
    tags = rewrite_stego_tags(tags, data=data, path=path)
    return normalize_tags(tags), suspicious


def scan_image_file(
    path: object, *, artifact_read_snapshot: object,
    deep_scan_fast_assets_reader: object = deep_scan_fast_assets_enabled,
) -> object:
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    report_scan_stage_progress("image_scan_start")
    if not snapshot.complete:
        data, failure = _read_image_scan_data(path, snapshot)
        del data
        return failure
    fast_tags, fast_suspicious, fast_handled = _try_fast_image_scan(
        path, snapshot, deep_scan_fast_assets_reader,
    )
    if fast_handled:
        return fast_tags, fast_suspicious
    data, failure = _read_image_scan_data(path, snapshot)
    if failure is not None:
        return failure
    return _scan_image_data(path, data)


__all__ = ("scan_image_file",)
