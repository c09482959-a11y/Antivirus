"""Worker-owned metadata projection helpers.

Worker lifecycle/result modules annotate worker outputs with immutable worker
identity facts here instead of reaching into evidence-writer ownership.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_text
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


@dataclass(frozen=True, slots=True)
class WorkerMetadataAnnotation:
    """Immutable evidence describing worker metadata attached to a result."""

    scheduler_mode: str
    worker_id: str
    worker_pid: int | str | None = None
    worker_metadata_evidence: tuple[dict[str, object], ...] = ()

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "scheduler_mode": self.scheduler_mode,
            "worker_id": self.worker_id,
        }
        if self.worker_pid is not None:
            payload["worker_pid"] = self.worker_pid
        if self.worker_metadata_evidence:
            payload["worker_metadata_evidence"] = [
                materialize_scheduler_mapping(item) for item in self.worker_metadata_evidence
            ]
        return payload


def _worker_metadata_rejection(value: object, *, field_name: str, reason: str) -> dict[str, object]:
    evidence = dict(unsupported_scheduler_value_evidence(value, field_name=field_name))
    evidence["reason"] = reason
    evidence["worker_metadata_field"] = field_name
    return evidence



def _safe_metadata_text(
    primary: object,
    secondary_value: object,
    *,
    replacement_text: str,
    field_name: str,
    unsupported_reason: str,
) -> tuple[str, tuple[dict[str, object], ...]]:
    evidence: list[dict[str, object]] = []
    if primary is not None and (type(primary) is not str or str.__str__(primary) != ""):
        text, reason = scheduler_text(primary, replacement_text="", unsupported_reason=unsupported_reason)
        if reason == "" and text:
            return text, ()
        evidence.append(_worker_metadata_rejection(primary, field_name=field_name, reason=reason or unsupported_reason))
    if secondary_value is not None and (type(secondary_value) is not str or str.__str__(secondary_value) != ""):
        secondary_reason = str.__add__(unsupported_reason, "_secondary")
        text, reason = scheduler_text(secondary_value, replacement_text="", unsupported_reason=secondary_reason)
        if reason == "" and text:
            return text, tuple(evidence)
        evidence.append(_worker_metadata_rejection(secondary_value, field_name=str.__add__(field_name, "_secondary"), reason=reason or secondary_reason))
    return replacement_text, tuple(evidence)


def _safe_metadata_pid_text(text: str) -> tuple[int | str | None, str]:
    if text == "":
        return None, "worker_pid_empty"
    try:
        return int(text), ""
    except ValueError:
        return text, ""


def _safe_metadata_pid(worker_pid: object) -> tuple[int | str | None, tuple[dict[str, object], ...]]:
    if worker_pid is None:
        return None, ()
    if type(worker_pid) is int and type(worker_pid) is not bool:
        return worker_pid, ()
    if type(worker_pid) is str:
        pid_value, reason = _safe_metadata_pid_text(str.__str__(worker_pid))
        if reason == "":
            return pid_value, ()
        return None, (_worker_metadata_rejection(worker_pid, field_name="worker_pid", reason=reason),)
    if type(worker_pid) is float and math.isfinite(worker_pid) and worker_pid.is_integer():
        return int(worker_pid), ()
    if type(worker_pid) is bytes:
        pid_value, reason = _safe_metadata_pid_text(bytes(worker_pid).decode("utf-8", "replace"))
        if reason == "":
            return pid_value, ()
        return None, (_worker_metadata_rejection(worker_pid, field_name="worker_pid", reason=reason),)
    if type(worker_pid) is bytearray:
        pid_value, reason = _safe_metadata_pid_text(bytes(worker_pid).decode("utf-8", "replace"))
        if reason == "":
            return pid_value, ()
        return None, (_worker_metadata_rejection(worker_pid, field_name="worker_pid", reason=reason),)
    return None, (_worker_metadata_rejection(worker_pid, field_name="worker_pid", reason="worker_pid_rejected"),)


def build_worker_metadata_annotation(
    *,
    scheduler_mode: object,
    worker_id: object,
    worker_pid: object | None = None,
    secondary_scheduler_mode: object = None,
    secondary_worker_id: object = None,
) -> WorkerMetadataAnnotation:
    """Return immutable worker metadata annotation evidence without caller hooks."""
    evidence: list[dict[str, object]] = []
    scheduler_mode_value, scheduler_mode_evidence = _safe_metadata_text(
        scheduler_mode,
        secondary_scheduler_mode,
        replacement_text="unknown",
        field_name="scheduler_mode",
        unsupported_reason="worker_scheduler_mode_rejected",
    )
    evidence.extend(scheduler_mode_evidence)
    worker_id_value, worker_id_evidence = _safe_metadata_text(
        worker_id,
        secondary_worker_id,
        replacement_text="worker",
        field_name="worker_id",
        unsupported_reason="worker_id_rejected",
    )
    evidence.extend(worker_id_evidence)
    pid_value, pid_evidence = _safe_metadata_pid(worker_pid)
    evidence.extend(pid_evidence)
    return WorkerMetadataAnnotation(
        scheduler_mode=scheduler_mode_value,
        worker_id=worker_id_value,
        worker_pid=pid_value,
        worker_metadata_evidence=tuple(evidence),
    )


def attach_worker_metadata(result: object, *, scheduler_mode: object, worker_id: object, worker_pid: object | None = None) -> object:
    """Return a worker result annotated with explicit scheduler worker ownership."""
    if type(result) is not dict:
        return result
    annotation = build_worker_metadata_annotation(
        scheduler_mode=scheduler_mode,
        worker_id=worker_id,
        worker_pid=worker_pid,
        secondary_scheduler_mode=dict.get(result, "scheduler_mode"),
        secondary_worker_id=dict.get(result, "worker_id"),
    )
    annotated = dict(result)
    annotated.update(annotation.as_dict())
    return annotated


__all__ = (
    "WorkerMetadataAnnotation",
    "attach_worker_metadata",
    "build_worker_metadata_annotation",
)
