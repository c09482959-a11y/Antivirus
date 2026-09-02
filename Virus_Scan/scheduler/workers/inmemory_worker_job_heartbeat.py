"""Worker-owned heartbeat annotation for in-memory worker job outputs."""
from __future__ import annotations

from typing import Mapping


def annotate_thread_progress_heartbeat_failure(output: object, evidence: Mapping[str, object] | None) -> object:
    """Attach worker heartbeat failure evidence to successful worker output when possible."""
    if not evidence:
        return output

    def annotate_result(result: Mapping[str, object]) -> dict[str, object]:
        annotated = dict(result)
        integrity = dict(annotated.get("scan_integrity") or {})
        integrity["worker_thread_progress_heartbeat_failed"] = True
        integrity["worker_thread_progress_heartbeat_evidence"] = dict(evidence)
        integrity["had_degraded_stage"] = True
        integrity["allow_learning"] = False
        annotated["scan_integrity"] = integrity
        annotated["worker_thread_progress_heartbeat_failed"] = True
        return annotated

    if isinstance(output, tuple) and len(output) == 2 and isinstance(output[1], Mapping):
        return (output[0], annotate_result(output[1]))
    if isinstance(output, Mapping):
        return annotate_result(output)
    return output


__all__ = ("annotate_thread_progress_heartbeat_failure",)
