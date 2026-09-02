"""Scanner-owned binary embedded-pickle payload observation."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scanners.api.pickle_contracts import pickle_embedded_payload_tags
from Virus_Scan.scanners.contracts.scanner_evidence import scanner_failure_evidence_tags

BINARY_EMBEDDED_PICKLE_MAX_BYTES = 10 * 1024 * 1024


def scan_binary_embedded_pickle_payloads(path: object, *, artifact_read_snapshot: object) -> list[str]:
    """Return scanner-owned tags for pickle payloads embedded in a binary file.

    The detection binary-static layer must not call scanner pickle helpers.  This
    collector keeps pickle/payload extraction in the scanner domain while the
    router can merge the resulting raw observation tags beside detection tags.
    """
    try:
        snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
        if not snapshot.complete:
            raise OSError(snapshot.unavailable_reason or "binary_embedded_pickle_input_unavailable")
        sample_size = min(snapshot.size, BINARY_EMBEDDED_PICKLE_MAX_BYTES)
        data = snapshot.read_prefix(sample_size)
        if len(data) != sample_size:
            raise OSError("binary_embedded_pickle_snapshot_view_incomplete")
        if not data:
            return []
        return list(pickle_embedded_payload_tags(data=data, path=path) or [])
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        return scanner_failure_evidence_tags(
            "binary",
            "binary_embedded_pickle_payloads",
            exc,
            ["binary_embedded_pickle_payload_scan_error", "scanner_degraded"],
            input_path=path,
            error_category="binary_embedded_pickle_boundary_failure",
            error_source="scanners.binary_embedded_pickle.scan_binary_embedded_pickle_payloads",
            file_type="binary",
        )


__all__ = ("BINARY_EMBEDDED_PICKLE_MAX_BYTES", "scan_binary_embedded_pickle_payloads")
