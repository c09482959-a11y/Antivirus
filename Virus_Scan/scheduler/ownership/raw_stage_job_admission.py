"""Raw-stage job admission cap and identity helpers."""
from __future__ import annotations

from dataclasses import dataclass, field

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_path_text, scheduler_text


@dataclass
class RawStageJobAdmissionState:
    path: object
    file_id: str
    deps: object
    jobs: list[dict[str, object]]
    seq: int = 0
    collector_counts: dict[str, int] = field(default_factory=dict)

    def add(self, collector: object, start: object = 0, size_arg: object = 0) -> bool:
        try:
            cap_raw = self.deps.runtime_value("RAW_PER_FILE_ACTIVE_CAP", 128)
        except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
            self.deps.record_suppressed("raw_build_jobs_deep_scan_cap_failed", exc)
            cap_raw = 128
        per_file_cap, cap_limit_reason = scheduler_int(
            cap_raw,
            default=128,
            minimum=1,
            reason="raw_per_file_active_cap_rejected",
        )
        if cap_limit_reason:
            self.deps.record_suppressed(cap_limit_reason, ValueError(cap_limit_reason))
        if len(self.jobs) >= per_file_cap:
            self.deps.record_suppressed("raw_stage_job_per_file_cap_reached", RuntimeError("raw stage job per-file cap reached"))
            return False
        collector_text, collector_reason = scheduler_text(collector, unsupported_reason="raw_stage_collector_rejected")
        if collector_reason:
            self.deps.record_suppressed(collector_reason, ValueError(collector_reason))
            collector_text = ""
        collector_cap = self._collector_cap(collector_text)
        current_count, count_reason = scheduler_int(
            self.collector_counts.get(collector_text, 0),
            default=0,
            minimum=0,
            reason="raw_stage_collector_count_rejected",
        )
        if count_reason:
            self.deps.record_suppressed(count_reason, ValueError(count_reason))
        if current_count >= collector_cap:
            self.deps.record_suppressed("raw_stage_job_collector_cap_reached", RuntimeError("raw stage job collector cap reached"))
            return False
        file_text = self._file_text()
        start_i, start_reason = scheduler_int(start, default=0, minimum=0, reason="raw_stage_job_start_rejected")
        if start_reason:
            self.deps.record_suppressed(start_reason, ValueError(start_reason))
        size_source = (
            self.deps.raw_chunk_bytes()
            if size_arg is None
            or (type(size_arg) is int and type(size_arg) is not bool and size_arg == 0)
            else size_arg
        )
        size_i, size_reason = scheduler_int(size_source, default=0, minimum=0, reason="raw_stage_job_size_rejected")
        if size_reason:
            self.deps.record_suppressed(size_reason, ValueError(size_reason))
        self.jobs.append({
            "job_type": "raw_stage",
            "file_id": self.file_id,
            "file": file_text,
            "collector": collector_text,
            "seq": self.seq,
            "start": start_i,
            "size": size_i,
            "attempt": 0,
            "max_retries": self.deps.retry_max("raw"),
        })
        self.collector_counts[collector_text] = current_count + 1
        self.seq += 1
        return True

    def _collector_cap(self, collector_text: str) -> int:
        try:
            collector_cap_raw = self.deps.raw_collector_cap(collector_text)
        except (TypeError, ValueError, RuntimeError) as cap_exc:
            self.deps.record_suppressed("raw_stage_collector_cap_failed", cap_exc)
            collector_cap_raw = 128
        cap, cap_reason = scheduler_int(collector_cap_raw, default=128, minimum=1, reason="raw_stage_collector_cap_rejected")
        if cap_reason:
            self.deps.record_suppressed(cap_reason, ValueError(cap_reason))
        return cap

    def _file_text(self) -> str:
        file_text, file_reason = scheduler_path_text(self.path)
        if file_reason:
            self.deps.record_suppressed(file_reason, ValueError(file_reason))
            return ""
        return file_text


__all__ = ("RawStageJobAdmissionState",)
