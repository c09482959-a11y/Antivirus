"""Scheduler serial-mode orchestration."""
from dataclasses import dataclass
from typing import Callable, Mapping, Tuple

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths


@dataclass(frozen=True)
class SchedulerSerialModeRequest:
    files: Tuple[str, ...]
    total_files: int
    started_at: float
    progress_every: int
    throttle_sec: float
    results: dict[object, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "files", freeze_live_scheduler_paths(self.files))


@dataclass(frozen=True)
class SchedulerSerialModeDependencies:
    worker: Callable[[str, str, bool], tuple]
    prepare_result: Callable[[object, object], object]
    write_derived_cache: Callable[[object], object]
    write_partial: Callable[..., None]
    bulk_scan_maintenance: Callable[[int], None]
    log_bulk_progress: Callable[..., None]
    sleep: Callable[[float], None]

    def run_worker(self, path: str, previous_stage: str, *, strict: bool) -> tuple:
        return self.worker(path, previous_stage, strict)

    def publish_partial(self, *, force: bool) -> None:
        self.write_partial(force)


@dataclass(frozen=True)
class SchedulerSerialModeResult:
    results: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", immutable_mapping(self.results))


def run_scheduler_serial_mode(
    request: SchedulerSerialModeRequest,
    deps: SchedulerSerialModeDependencies,
) -> SchedulerSerialModeResult:
    results = request.results if type(request.results) is dict else {}
    for idx, path in enumerate(request.files):
        completed_path, result = deps.run_worker(path, "unknown", strict=True)
        prepared_result = deps.prepare_result(completed_path, result)
        results[completed_path] = prepared_result
        deps.publish_partial(force=False)
        deps.write_derived_cache(result)
        deps.bulk_scan_maintenance(idx + 1)
        deps.log_bulk_progress(
            idx + 1,
            request.total_files,
            file_path=completed_path,
            started_at=request.started_at,
            progress_every=request.progress_every,
        )
        if request.throttle_sec:
            deps.sleep(max(0.0, float(request.throttle_sec)))
    return SchedulerSerialModeResult(results=results)
