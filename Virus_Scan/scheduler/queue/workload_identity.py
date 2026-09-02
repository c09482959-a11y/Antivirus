"""Scheduler-owned workload identity sniffing for queue admission.

This module owns only the cheap header/magic classification used before queue
admission. Full detector/scoring identity validation remains outside scheduler.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_path_text,
)
from Virus_Scan.scheduler.queue.workload_identity_outcome import (
    WorkloadIdentityDecision,
    workload_from_identity_outcome,
)
from Virus_Scan.scheduler.queue.workload_identity_magic import (
    identify_workload_magic_header,
    unknown_workload_magic_identity,
)


def _sniff_workload_identity(path: str | os.PathLike[str] | None) -> Mapping[str, object]:
    """Cheap magic/header classifier for scheduler admission.

    This intentionally runs before workers are submitted so extensionless or
    misnamed passive files do not get admitted through the generic lane.  It is
    best-effort and never raises; detector/scoring code still performs the full
    identity validation later.

    Do not import the full routing.sniff_file_identity here: queue admission owns
    a minimal magic-header pass, while detector/scoring code performs the full
    canonical identity validation after dispatch.
    """
    filesystem_path, path_reason = scheduler_filesystem_path(path)
    if path_reason or filesystem_path == "":
        return immutable_mapping({
            "ext": "",
            "magic_stage": "unknown",
            "magic_type": "unknown",
            "confidence": 0.0,
            "tags": (),
            "path_unavailable_reason": path_reason or "scheduler_path_missing",
        })
    try:
        path_text, _path_text_reason = scheduler_path_text(filesystem_path)
        ext = os.path.splitext(path_text)[1].lower()
        header = read_artifact_prefix(filesystem_path, 8192)
    except RECOVERABLE_RUNTIME_ERRORS:
        return immutable_mapping({
            "ext": "",
            "magic_stage": "unknown",
            "magic_type": "unknown",
            "confidence": 0.0,
            "tags": (),
            "path_unavailable_reason": "scheduler_workload_identity_read_failed",
        })
    if not header:
        identity = unknown_workload_magic_identity()
    else:
        identity = identify_workload_magic_header(filesystem_path, header, ext)
    return immutable_mapping({
        "ext": ext,
        "magic_stage": identity.stage,
        "magic_type": identity.magic_type,
        "confidence": identity.confidence,
        "tags": identity.tags,
    })


__all__ = (
    "WorkloadIdentityDecision",
    "_sniff_workload_identity",
    "workload_from_identity_outcome",
)
