"""Canonical scheduler checkpoint writer ownership.

This evidence owner writes scheduler checkpoint payloads through the canonical
scheduler JSON durable writer.  It returns immutable write results and evidence
records instead of mutating queue, worker, timeout, retry, replay, or runtime
state directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.evidence.records import SchedulerEvidenceBundle, build_scheduler_evidence_bundle
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_process_queue_json_durable
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

_CHECKPOINT_PAYLOAD_UNSUPPORTED = "scheduler checkpoint payload requires SchedulerResult, SchedulerEvidenceBundle, or mapping"


@dataclass(frozen=True, slots=True)
class SchedulerCheckpointWriteResult:
    checkpoint_path: str
    status: str
    evidence: tuple[SchedulerEvidenceRecord, ...] = ()
    error: str = ""
    fatal: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "checkpoint_path": self.checkpoint_path,
            "status": self.status,
            "evidence": [record.as_dict() for record in self.evidence],
            "error": self.error,
            "fatal": self.fatal,
        }



def build_scheduler_checkpoint_payload(result: SchedulerResult | SchedulerEvidenceBundle | Mapping[str, object]) -> dict[str, object]:
    if type(result) is SchedulerResult:
        bundle = build_scheduler_evidence_bundle(result.evidence)
        return {"scheduler_result": result.as_dict(), "scheduler": bundle.as_dict()}
    if type(result) is SchedulerEvidenceBundle:
        return {"scheduler": result.as_dict()}
    if isinstance(result, Mapping):
        return materialize_scheduler_mapping(result)
    raise TypeError(_CHECKPOINT_PAYLOAD_UNSUPPORTED)


def write_scheduler_checkpoint(
    checkpoint_path: str | Path,
    result: SchedulerResult | SchedulerEvidenceBundle | Mapping[str, object],
    *,
    write_json: Callable[..., bool] = write_process_queue_json_durable,
) -> SchedulerCheckpointWriteResult:
    path_text, path_reason = scheduler_path_text(checkpoint_path)
    if path_reason != "" or not path_text:
        evidence = SchedulerEvidenceRecord(
            stage="checkpoint_writer",
            state="failure",
            error_category="checkpoint_path_rejected",
            error_source="scheduler.evidence.checkpoint_writer",
            message="scheduler checkpoint path was rejected before path-hook materialization",
            context={"checkpoint_path_type": no_hook_type_name(checkpoint_path)},
            checkpoint_must_record=True,
            final_json_must_record=True,
            replay_must_record=True,
            fatal=True,
        )
        return SchedulerCheckpointWriteResult("", "failed", evidence=(evidence,), error=evidence.message, fatal=True)
    final = Path(path_text)
    tmp = Path(str.__add__(path_text, ".tmp"))
    payload = build_scheduler_checkpoint_payload(result)
    ok = write_json(tmp, final, payload, log_context="scheduler_checkpoint")
    if ok:
        return SchedulerCheckpointWriteResult(path_text, "written")
    evidence = SchedulerEvidenceRecord(
        stage="checkpoint_writer",
        state="failure",
        error_category="checkpoint_write_failed",
        error_source="scheduler.evidence.checkpoint_writer",
        message="scheduler checkpoint JSON publication failed",
        context={"checkpoint_path": path_text},
        checkpoint_must_record=True,
        final_json_must_record=True,
        replay_must_record=True,
        fatal=True,
    )
    return SchedulerCheckpointWriteResult(path_text, "failed", evidence=(evidence,), error=evidence.message, fatal=True)


__all__ = ("SchedulerCheckpointWriteResult", "build_scheduler_checkpoint_payload", "write_scheduler_checkpoint")
