"""Immutable contracts for process-queue result merging."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, TYPE_CHECKING


from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool

if TYPE_CHECKING:
    from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure


@dataclass(frozen=True)
class ProcessQueueResultMergeRequest:
    queue_dir: object
    outputs: tuple[object, ...]
    all_files: tuple[object, ...]
    partial_output_path: object | None
    strict_had_error: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", immutable_tuple(self.outputs))
        object.__setattr__(self, "all_files", immutable_tuple(self.all_files))
        object.__setattr__(self, "strict_had_error", scheduler_bool(self.strict_had_error, default=False, reason="result_merge_strict_had_error_rejected")[0])


@dataclass(frozen=True)
class ProcessQueueResultMergeDependencies:
    read_json_file: Callable[..., object]
    load_queue_file_results: Callable[..., dict[str, object]]
    queue_job_dirs: Callable[..., tuple[object, object, object, object]]
    is_job_json_name: Callable[[object], bool]
    done_jobs_missing_results: Callable[..., list[object]]
    repair_failed_queue_job_diagnostics: Callable[[object], object]
    cleanup_diagnostic_tmp_files: Callable[..., object]
    collect_failed_queue_report: Callable[..., list[object]]
    summarize_failed_queue_report: Callable[..., list[object]]
    safe_queue_listdir: Callable[[object], list[str] | QueueListdirFailure]
    record_issue: Callable[..., None]
    log_error: Callable[[str], None]
    log_info: Callable[[str], None]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ProcessQueueResultMergeOutput:
    merged: Mapping[str, object]
    had_error: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "merged", immutable_mapping(self.merged))


__all__ = (
    "ProcessQueueResultMergeDependencies",
    "ProcessQueueResultMergeOutput",
    "ProcessQueueResultMergeRequest",
)
