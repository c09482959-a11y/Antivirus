"""Canonical detection enrichment owner for fast image triage evidence."""

from Virus_Scan.detection.evidence.artifacts.scan_cache import remember_scan_evidence
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.utils.fast_assets import scan_image_file_fast_triage


def scan_image_file_fast(path: object, *, artifact_read_snapshot: object) -> object:
    """Return normalized fast image triage tags and suspicion state."""
    sample = b""
    try:
        sample_bytes = 131072
        tags, suspicious, sample = scan_image_file_fast_triage(
            path, artifact_read_snapshot=artifact_read_snapshot, sample_bytes=sample_bytes,
        )
        if suspicious:
            try:
                remember_scan_evidence(path, strings_blob=sample.decode("latin1", errors="ignore"), raw_sample=sample, image_fast_sampled=True)
            except TAG_SCAN_RECOVERABLE_EXCEPTIONS as _umige_log_exc:
                tags = list(tags) + list(failure_tags_for_stage('image_fast_scan_evidence_cache', _umige_log_exc, context=path))
                suspicious = True
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        tags = ["image", "image_fast_triage", "asset_fast_triage", "image_fast_triage_error", *failure_tags_for_stage('image_fast_triage', e, context=path)]
        suspicious = True
    return (normalize_tags(tags), suspicious)
