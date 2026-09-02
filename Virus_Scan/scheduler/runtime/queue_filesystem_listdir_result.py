"""Explicit no-hook queue listdir failure evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


@dataclass(frozen=True, slots=True)
class QueueListdirFailure(RuntimeError):
    """Non-iterable scheduler filesystem failure carrying durable evidence."""

    reason: str
    path_evidence: Mapping[str, object]
    error_evidence: Mapping[str, object]
    result_evidence: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path_evidence", immutable_mapping(self.path_evidence))
        object.__setattr__(self, "error_evidence", immutable_mapping(self.error_evidence))
        if self.result_evidence is not None:
            object.__setattr__(self, "result_evidence", immutable_mapping(self.result_evidence))
        RuntimeError.__init__(self, self.reason)

    def as_dict(self) -> dict[str, object]:
        evidence = {
            "queue_listdir_failed": True,
            "scheduler_filesystem_unavailable": True,
            "reason": self.reason,
            "path_evidence": materialize_scheduler_mapping(self.path_evidence),
            "error_evidence": materialize_scheduler_mapping(self.error_evidence),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
        if self.result_evidence is not None:
            materialized_result = materialize_scheduler_mapping(self.result_evidence)
            evidence["result_evidence"] = materialized_result
            if type(materialized_result) is dict:
                for key in tuple(dict.keys(materialized_result)):
                    if key not in evidence:
                        evidence[key] = materialized_result[key]
        return evidence


def queue_listdir_failure(
    path: object,
    *,
    reason: str,
    error: BaseException | None = None,
    result: object | None = None,
) -> QueueListdirFailure:
    reason_text = reason if type(reason) is str else "queue_listdir_failed"
    if error is None:
        error_evidence: dict[str, object] = {
            "error_available": False,
            "error_type": "",
            "error_detail": reason_text,
        }
    else:
        error_evidence = {
            "error_available": True,
            "error_type": no_hook_type_name(error),
            "error_detail": scheduler_error_detail(error, max_length=500),
        }
    path_text, path_reason = scheduler_path_text(path)
    path_evidence: dict[str, object] = {
        "path_available": path_reason == "",
        "path_text": path_text if path_reason == "" else "",
        "path_reason": path_reason,
    }
    if path_reason != "":
        path_evidence["path_rejected"] = unsupported_scheduler_value_evidence(
            path,
            field_name="queue_listdir_path",
        )
    return QueueListdirFailure(
        reason=reason_text,
        path_evidence=path_evidence,
        error_evidence=error_evidence,
        result_evidence=(
            unsupported_scheduler_value_evidence(result, field_name="queue_listdir_result")
            if result is not None
            else None
        ),
    )


def queue_listdir_names(listed: object, *, context: object) -> tuple[object, ...]:
    """Return an exact built-in listing snapshot or raise explicit failure evidence."""
    if type(listed) is QueueListdirFailure:
        raise listed
    if type(listed) is list:
        return tuple(listed)
    if type(listed) is tuple:
        return tuple(listed)
    if type(listed) is set:
        return tuple(listed)
    if type(listed) is frozenset:
        return tuple(listed)
    raise queue_listdir_failure(
        context,
        reason="queue_listdir_result_unsupported",
        result=listed,
    )


__all__ = ("QueueListdirFailure", "queue_listdir_failure", "queue_listdir_names")
