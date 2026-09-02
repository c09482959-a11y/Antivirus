"""Canonical scheduler trace writer ownership."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.records import collect_scheduler_evidence
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_process_queue_json_durable
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text


@dataclass(frozen=True, slots=True)
class SchedulerTraceWriteResult:
    trace_path: str
    status: str
    evidence: tuple[SchedulerEvidenceRecord, ...] = ()
    error: str = ""
    fatal: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "trace_path": self.trace_path,
            "status": self.status,
            "evidence": [record.as_dict() for record in self.evidence],
            "error": self.error,
            "fatal": self.fatal,
        }



def build_scheduler_trace_payload(records: Iterable[SchedulerEvidenceRecord | Mapping[str, object]]) -> dict[str, object]:
    evidence = collect_scheduler_evidence(records)
    return {"scheduler_trace": [record.as_dict() for record in evidence]}


def write_scheduler_trace(
    trace_path: str | Path,
    records: Iterable[SchedulerEvidenceRecord | Mapping[str, object]],
    *,
    write_json: Callable[..., bool] = write_process_queue_json_durable,
) -> SchedulerTraceWriteResult:
    path_text, path_reason = scheduler_path_text(trace_path)
    if path_reason != "" or not path_text:
        evidence = SchedulerEvidenceRecord(
            stage="trace_writer",
            state="failure",
            error_category="trace_path_rejected",
            error_source="scheduler.evidence.trace_writer",
            message="scheduler trace path was rejected before path-hook materialization",
            context={"trace_path_type": no_hook_type_name(trace_path)},
            checkpoint_must_record=True,
            final_json_must_record=True,
            replay_must_record=True,
            fatal=True,
        )
        return SchedulerTraceWriteResult("", "failed", evidence=(evidence,), error=evidence.message, fatal=True)
    final = Path(path_text)
    tmp = Path(str.__add__(path_text, ".tmp"))
    payload = build_scheduler_trace_payload(records)
    ok = write_json(tmp, final, payload, log_context="scheduler_trace")
    if ok:
        return SchedulerTraceWriteResult(path_text, "written")
    evidence = SchedulerEvidenceRecord(
        stage="trace_writer",
        state="failure",
        error_category="trace_write_failed",
        error_source="scheduler.evidence.trace_writer",
        message="scheduler trace JSON publication failed",
        context={"trace_path": path_text},
        checkpoint_must_record=True,
        final_json_must_record=True,
        replay_must_record=True,
        fatal=False,
    )
    return SchedulerTraceWriteResult(path_text, "failed", evidence=(evidence,), error=evidence.message)


__all__ = ("SchedulerTraceWriteResult", "build_scheduler_trace_payload", "write_scheduler_trace")
