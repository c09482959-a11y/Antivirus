"""Session-owned bounded executors for intrastage raw evidence collection."""
from __future__ import annotations

from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from contextvars import copy_context
from dataclasses import dataclass
import json
from multiprocessing.util import Finalize
import os
import pickle
from threading import BoundedSemaphore, RLock
import time
from typing import Callable

from Virus_Scan.contracts.intrastage_execution import IntrastageExecutionPlan
from Virus_Scan.contracts.no_hook_materialization import (
    materialize_json_no_hook,
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.contracts.scan_session_snapshot import (
    ScanSessionSnapshot,
    scan_session_snapshot_from_record,
)
from Virus_Scan.core.logging import _safe_stage_collect
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.orchestration.scan_session import validate_scan_session_runtime
from Virus_Scan.runtime.api import (
    RuntimeEnvironmentOwner,
    log_error,
    record_suppressed_failure,
    release_mitre_runtime,
    release_yara_runtime,
    scheduler_runtime_state,
)
from Virus_Scan.routing.intrastage_execution_plan import (
    intrastage_default_backend,
    intrastage_enabled,
    stage_parallel_enabled,
    stage_parallel_workers,
)
from Virus_Scan.orchestration.worker_runtime_descriptors import (
    WorkerMitreRuntimeDescriptor,
    WorkerYaraRuntimeDescriptor,
    build_worker_mitre_runtime_descriptor,
    build_worker_yara_runtime_descriptor,
)
from Virus_Scan.scheduler.api.runtime import (
    acquire_weighted_stage_budget,
    get_scheduler_multiprocessing_context,
    release_weighted_stage_budget,
)

_PROCESS_BACKEND_ERRORS = RECOVERABLE_RUNTIME_ERRORS + (AssertionError, BrokenProcessPool, pickle.PicklingError)


class _ProcessBackendUnavailable(RuntimeError):
    """The selected process backend cannot execute the requested batch."""


class _ProcessTaskNotSerializable(RuntimeError):
    """One process task cannot cross the canonical IPC boundary."""


class _ProcessTaskPayloadTooLarge(RuntimeError):
    """One process task exceeds the canonical IPC byte limit."""


@dataclass(frozen=True, slots=True)
class IntrastageProcessWorkerBootstrap:
    """Exact immutable/live carriers required by one spawned intrastage worker."""

    scan_session_record_json: str
    yara_runtime_descriptor: WorkerYaraRuntimeDescriptor
    mitre_runtime_descriptor: WorkerMitreRuntimeDescriptor
    stage_limit_items: tuple[tuple[str, object], ...]
    stage_semaphore_items: tuple[tuple[str, object], ...]
    stage_failure_evidence_json: str

    def __post_init__(self) -> None:
        if type(self.scan_session_record_json) is not str or self.scan_session_record_json == "":
            raise ValueError("intrastage_process_scan_session_record_invalid")
        if type(self.yara_runtime_descriptor) is not WorkerYaraRuntimeDescriptor:
            raise TypeError("intrastage_process_yara_descriptor_invalid")
        if type(self.mitre_runtime_descriptor) is not WorkerMitreRuntimeDescriptor:
            raise TypeError("intrastage_process_mitre_descriptor_invalid")
        for items, reason in (
            (self.stage_limit_items, "intrastage_process_stage_limits_invalid"),
            (self.stage_semaphore_items, "intrastage_process_stage_semaphores_invalid"),
        ):
            if type(items) is not tuple:
                raise TypeError(reason)
            if any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or item[0] == ""
                for item in items
            ):
                raise ValueError(reason)
        if type(self.stage_failure_evidence_json) is not str:
            raise TypeError("intrastage_process_stage_evidence_invalid")


def _exact_stage_table_items(value: object, *, reason: str) -> tuple[tuple[str, object], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise TypeError(reason)
    materialized: list[tuple[str, object]] = []
    for key, item in items:
        if type(key) is not str or key == "":
            raise ValueError(reason)
        materialized.append((str.__str__(key), item))
    materialized.sort(key=lambda pair: pair[0])
    return tuple(materialized)


def _build_intrastage_process_worker_bootstrap(
    snapshot: ScanSessionSnapshot,
    *,
    stage_tables: object,
) -> IntrastageProcessWorkerBootstrap:
    if type(snapshot) is not ScanSessionSnapshot:
        raise TypeError("intrastage_scan_session_snapshot_required")
    stage_table_items = no_hook_mapping_items(stage_tables)
    if stage_table_items is None:
        raise TypeError("intrastage_process_stage_tables_invalid")
    stage_table_map = dict(stage_table_items)
    failure_evidence = dict.get(stage_table_map, "stage_table_evidence", ())
    if type(failure_evidence) is not tuple:
        raise TypeError("intrastage_process_stage_evidence_invalid")
    return IntrastageProcessWorkerBootstrap(
        scan_session_record_json=json.dumps(
            snapshot.to_record(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
        yara_runtime_descriptor=build_worker_yara_runtime_descriptor(snapshot),
        mitre_runtime_descriptor=build_worker_mitre_runtime_descriptor(snapshot),
        stage_limit_items=_exact_stage_table_items(
            dict.get(stage_table_map, "stage_limits"),
            reason="intrastage_process_stage_limits_invalid",
        ),
        stage_semaphore_items=_exact_stage_table_items(
            dict.get(stage_table_map, "stage_semaphores"),
            reason="intrastage_process_stage_semaphores_invalid",
        ),
        stage_failure_evidence_json=json.dumps(
            materialize_json_no_hook(
                failure_evidence,
                context="intrastage_process_stage_evidence",
            ),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
    )


def _finalize_intrastage_process_worker(generation_id: str) -> None:
    session = _INTRASTAGE_EXECUTOR_RUNTIME.current()
    if session is not None and session.snapshot.generation_id == generation_id:
        _INTRASTAGE_EXECUTOR_RUNTIME.close(session.snapshot)
    release_mitre_runtime()
    release_yara_runtime()


def _initialize_intrastage_process_worker(
    bootstrap: IntrastageProcessWorkerBootstrap,
) -> None:
    if type(bootstrap) is not IntrastageProcessWorkerBootstrap:
        raise TypeError("intrastage_process_worker_bootstrap_invalid")
    record = json.loads(bootstrap.scan_session_record_json)
    snapshot = scan_session_snapshot_from_record(record)
    RuntimeEnvironmentOwner().publish(
        {
            "UMIGE_INTRASTAGE_PROCESS_WORKER": "1",
            "UMIGE_PROCESS_SHARD": "1",
        }
    )
    runtime_state = scheduler_runtime_state()
    runtime_state.configure_profile_policy(
        defer_profile_writes=True,
        profile_flush_every=25,
        bulk_profile_flush_every=1_000_000_000,
    )
    runtime_state.configure_worker_stage_tables(
        stage_limits=dict(bootstrap.stage_limit_items),
        stage_semaphores=dict(bootstrap.stage_semaphore_items),
        failure_evidence=json.loads(bootstrap.stage_failure_evidence_json),
    )
    yara_descriptor = bootstrap.yara_runtime_descriptor
    yara_descriptor.initializer(
        root=yara_descriptor.root,
        enabled=yara_descriptor.enabled,
        available=yara_descriptor.available,
        scan_mode=yara_descriptor.scan_mode,
        package_kind=yara_descriptor.package_kind,
        source_path=yara_descriptor.source_path,
        expected_source_digest=yara_descriptor.source_digest,
        expected_compiled_cache_digest=yara_descriptor.compiled_cache_digest,
        expected_rule_catalog_digest=yara_descriptor.rule_catalog_digest,
        unavailable_reason=yara_descriptor.unavailable_reason,
    )
    mitre_descriptor = bootstrap.mitre_runtime_descriptor
    mitre_descriptor.initializer(
        root=mitre_descriptor.root,
        enabled=mitre_descriptor.enabled,
        available=mitre_descriptor.available,
        expected_repository_digest=mitre_descriptor.repository_digest,
        expected_dataset_version=mitre_descriptor.dataset_version,
        unavailable_reason=mitre_descriptor.unavailable_reason,
    )
    validate_scan_session_runtime(snapshot)
    _INTRASTAGE_EXECUTOR_RUNTIME.start(snapshot, process_backend_allowed=False)
    Finalize(
        None,
        _finalize_intrastage_process_worker,
        args=(snapshot.generation_id,),
        exitpriority=10,
    )


def _raw_task_error(name: object, exc: BaseException) -> dict[str, object]:
    return {
        "name": str.__str__(name) if type(name) is str else "stage_task",
        "tags": [],
        "meta": {},
        "suspicious": False,
        "error": no_hook_type_name(exc),
    }


def _execute_raw_task(
    submitted_ns: int,
    name: object,
    fn: Callable[..., object],
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> tuple[object, int, int]:
    started_ns = time.monotonic_ns()
    budget_tokens = ()
    try:
        budget_tokens = acquire_weighted_stage_budget(
            stage_name=name,
            cost={"weight": 1, "stage": "generic"},
        )
        result = _safe_stage_collect(name, fn, *args, **kwargs)
        return result, max(0, started_ns - submitted_ns), time.monotonic_ns() - started_ns
    finally:
        release_weighted_stage_budget(budget_tokens)


def _record_process_backend_failure(exc: BaseException) -> None:
    try:
        log_error(
            "raw task process backend unavailable: " + no_hook_type_name(exc)
        )
    except RECOVERABLE_RUNTIME_ERRORS as suppressed_exc:
        try:
            record_suppressed_failure(
                "suppressed_exception",
                suppressed_exc,
                domain="runtime",
            )
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc


def _pickle_size(value: object) -> tuple[int, bool]:
    try:
        return len(pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)), True
    except _PROCESS_BACKEND_ERRORS:
        return 0, False


@dataclass(frozen=True, slots=True)
class IntrastageExecutorMetrics:
    generation_id: str
    owner_pid: int
    session_start_count: int
    session_reuse_count: int
    thread_executor_start_count: int
    process_executor_start_count: int
    process_backend_failure_count: int
    process_payload_rejection_count: int
    batch_count: int
    serial_batch_count: int
    thread_batch_count: int
    process_batch_count: int
    task_submission_count: int
    task_completion_count: int
    task_failure_count: int
    executor_reuse_count: int
    max_inflight_tasks: int
    backpressure_wait_ns: int
    queue_wait_ns: int
    execution_ns: int
    process_request_bytes: int
    process_result_bytes: int
    serialization_measurement_failures: int
    closed: bool

    def to_record(self) -> dict[str, object]:
        return {
            "backpressure_wait_ns": self.backpressure_wait_ns,
            "batch_count": self.batch_count,
            "closed": self.closed,
            "execution_ns": self.execution_ns,
            "executor_reuse_count": self.executor_reuse_count,
            "generation_id": self.generation_id,
            "max_inflight_tasks": self.max_inflight_tasks,
            "owner_pid": self.owner_pid,
            "process_backend_failure_count": self.process_backend_failure_count,
            "process_payload_rejection_count": self.process_payload_rejection_count,
            "process_batch_count": self.process_batch_count,
            "process_executor_start_count": self.process_executor_start_count,
            "process_request_bytes": self.process_request_bytes,
            "process_result_bytes": self.process_result_bytes,
            "queue_wait_ns": self.queue_wait_ns,
            "serialization_measurement_failures": self.serialization_measurement_failures,
            "serial_batch_count": self.serial_batch_count,
            "session_reuse_count": self.session_reuse_count,
            "session_start_count": self.session_start_count,
            "task_completion_count": self.task_completion_count,
            "task_failure_count": self.task_failure_count,
            "task_submission_count": self.task_submission_count,
            "thread_batch_count": self.thread_batch_count,
            "thread_executor_start_count": self.thread_executor_start_count,
        }


class IntrastageExecutorSession:
    """One process-local executor lifecycle bound to one scan generation."""

    def __init__(
        self,
        snapshot: ScanSessionSnapshot,
        *,
        process_backend_allowed: bool,
    ) -> None:
        if type(snapshot) is not ScanSessionSnapshot:
            raise TypeError("intrastage_scan_session_snapshot_required")
        if type(process_backend_allowed) is not bool:
            raise TypeError("intrastage_process_backend_policy_invalid")
        plan = snapshot.concurrency_plan
        if plan.digest != snapshot.concurrency_digest:
            raise ValueError("intrastage_concurrency_identity_mismatch")
        self.snapshot = snapshot
        self.plan = plan
        self.process_backend_allowed = process_backend_allowed
        self.owner_pid = os.getpid()
        self._lock = RLock()
        self._pending_slots = BoundedSemaphore(plan.max_pending_tasks)
        self._thread_executor: ThreadPoolExecutor | None = None
        self._process_executor: ProcessPoolExecutor | None = None
        self._process_backend_unavailable = not process_backend_allowed
        self._process_stage_tables = (
            scheduler_runtime_state().stage_tables_snapshot()
            if process_backend_allowed
            else None
        )
        self._process_worker_bootstrap: IntrastageProcessWorkerBootstrap | None = None
        self._closed = False
        self._session_reuse_count = 0
        self._thread_executor_start_count = 0
        self._process_executor_start_count = 0
        self._process_backend_failure_count = 0
        self._process_payload_rejection_count = 0
        self._batch_count = 0
        self._serial_batch_count = 0
        self._thread_batch_count = 0
        self._process_batch_count = 0
        self._task_submission_count = 0
        self._task_completion_count = 0
        self._task_failure_count = 0
        self._executor_reuse_count = 0
        self._inflight_tasks = 0
        self._max_inflight_tasks = 0
        self._backpressure_wait_ns = 0
        self._queue_wait_ns = 0
        self._execution_ns = 0
        self._process_request_bytes = 0
        self._process_result_bytes = 0
        self._serialization_measurement_failures = 0

    def mark_reused(self) -> None:
        with self._lock:
            self._session_reuse_count += 1

    def _require_open(self) -> None:
        if self.owner_pid != os.getpid():
            raise RuntimeError("intrastage_executor_process_identity_mismatch")
        if self._closed:
            raise RuntimeError("intrastage_executor_session_closed")

    def _thread_pool(self) -> ThreadPoolExecutor:
        with self._lock:
            self._require_open()
            if self._thread_executor is None:
                self._thread_executor = ThreadPoolExecutor(
                    max_workers=self.plan.intrastage_workers,
                    thread_name_prefix=("umige-intrastage-" + self.snapshot.generation_id[:8]),
                )
                self._thread_executor_start_count += 1
            else:
                self._executor_reuse_count += 1
            return self._thread_executor

    def _process_pool(self) -> ProcessPoolExecutor:
        with self._lock:
            self._require_open()
            if self._process_backend_unavailable:
                raise RuntimeError("intrastage_process_backend_unavailable")
            if self._process_executor is None:
                bootstrap = self._process_worker_bootstrap
                if bootstrap is None:
                    stage_tables = self._process_stage_tables
                    if stage_tables is None:
                        raise RuntimeError("intrastage_process_stage_tables_missing")
                    bootstrap = _build_intrastage_process_worker_bootstrap(
                        self.snapshot,
                        stage_tables=stage_tables,
                    )
                    self._process_worker_bootstrap = bootstrap
                if type(bootstrap) is not IntrastageProcessWorkerBootstrap:
                    raise RuntimeError("intrastage_process_worker_bootstrap_missing")
                self._process_executor = ProcessPoolExecutor(
                    max_workers=self.plan.intrastage_workers,
                    mp_context=get_scheduler_multiprocessing_context(),
                    initializer=_initialize_intrastage_process_worker,
                    initargs=(bootstrap,),
                )
                self._process_executor_start_count += 1
            else:
                self._executor_reuse_count += 1
            return self._process_executor

    def _record_submit(self, *, process_bytes: int = 0, measured: bool = True) -> None:
        with self._lock:
            self._task_submission_count += 1
            self._inflight_tasks += 1
            self._max_inflight_tasks = max(self._max_inflight_tasks, self._inflight_tasks)
            self._process_request_bytes += process_bytes
            if not measured:
                self._serialization_measurement_failures += 1

    def _record_done(
        self,
        *,
        queue_wait_ns: int,
        execution_ns: int,
        failed: bool,
        process_result: object = None,
        process_backend: bool = False,
    ) -> None:
        result_bytes = 0
        measured = True
        if process_backend:
            result_bytes, measured = _pickle_size(process_result)
        with self._lock:
            self._inflight_tasks = max(0, self._inflight_tasks - 1)
            self._task_completion_count += 1
            self._task_failure_count += int(failed)
            self._queue_wait_ns += max(0, queue_wait_ns)
            self._execution_ns += max(0, execution_ns)
            self._process_result_bytes += result_bytes
            if process_backend and not measured:
                self._serialization_measurement_failures += 1

    def _submit(
        self,
        *,
        executor: object,
        task: tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]],
        process_backend: bool,
        process_request_bytes: int = 0,
    ) -> Future:
        name, fn, args, kwargs = task
        wait_started = time.monotonic_ns()
        self._pending_slots.acquire()
        acquired_ns = time.monotonic_ns()
        with self._lock:
            self._backpressure_wait_ns += max(0, acquired_ns - wait_started)
        self._record_submit(process_bytes=process_request_bytes, measured=True)
        submitted_ns = time.monotonic_ns()
        try:
            if process_backend:
                future = executor.submit(_execute_raw_task, submitted_ns, name, fn, args, kwargs)
            else:
                context = copy_context()
                future = executor.submit(context.run, _execute_raw_task, submitted_ns, name, fn, args, kwargs)
        except _PROCESS_BACKEND_ERRORS:
            self._record_done(
                queue_wait_ns=0,
                execution_ns=0,
                failed=True,
                process_result=None,
                process_backend=False,
            )
            self._pending_slots.release()
            raise
        future.add_done_callback(lambda _future: self._pending_slots.release())
        return future

    def _execute_wave(
        self,
        tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]],
        *,
        executor: object,
        process_backend: bool,
        process_request_sizes: tuple[int, ...] = (),
    ) -> tuple[list[object], BaseException | None]:
        results: list[object | None] = [None] * len(tasks)
        future_map: dict[Future, int] = {}
        backend_error: BaseException | None = None
        for idx, task in enumerate(tasks):
            request_bytes = process_request_sizes[idx] if process_backend else 0
            try:
                future = self._submit(
                    executor=executor,
                    task=task,
                    process_backend=process_backend,
                    process_request_bytes=request_bytes,
                )
            except _PROCESS_BACKEND_ERRORS as exc:
                if process_backend:
                    backend_error = backend_error or exc
                    results[idx] = _raw_task_error(task[0], exc)
                    for pending_idx in range(idx + 1, len(tasks)):
                        results[pending_idx] = self._record_rejected_task(
                            tasks[pending_idx],
                            exc,
                        )
                    break
                results[idx] = _raw_task_error(task[0], exc)
            else:
                future_map[future] = idx
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                result, queue_wait_ns, execution_ns = future.result()
            except _PROCESS_BACKEND_ERRORS as exc:
                result = _raw_task_error(tasks[idx][0], exc)
                self._record_done(
                    queue_wait_ns=0,
                    execution_ns=0,
                    failed=True,
                    process_result=result,
                    process_backend=process_backend,
                )
                if process_backend:
                    backend_error = backend_error or exc
            else:
                failed = type(result) is dict and dict.get(result, "error") is not None
                self._record_done(
                    queue_wait_ns=queue_wait_ns,
                    execution_ns=execution_ns,
                    failed=failed,
                    process_result=result,
                    process_backend=process_backend,
                )
            results[idx] = result
        completed = [
            item if item is not None else _raw_task_error(tasks[idx][0], RuntimeError("intrastage_task_missing_result"))
            for idx, item in enumerate(results)
        ]
        return completed, backend_error

    def _execute_parallel(
        self,
        tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]],
        *,
        backend: str,
        requested_workers: int,
        process_request_sizes: tuple[int, ...] = (),
    ) -> tuple[list[object], BaseException | None]:
        process_backend = backend == "process"
        try:
            executor = self._process_pool() if process_backend else self._thread_pool()
        except _PROCESS_BACKEND_ERRORS as exc:
            if process_backend:
                raise _ProcessBackendUnavailable(no_hook_type_name(exc)) from exc
            raise
        results: list[object] = []
        backend_error: BaseException | None = None
        for offset in range(0, len(tasks), requested_workers):
            wave_tasks = tasks[offset:offset + requested_workers]
            wave_sizes = (
                process_request_sizes[offset:offset + requested_workers]
                if process_backend
                else ()
            )
            wave_results, wave_error = self._execute_wave(
                wave_tasks,
                executor=executor,
                process_backend=process_backend,
                process_request_sizes=wave_sizes,
            )
            results.extend(wave_results)
            if wave_error is not None:
                backend_error = backend_error or wave_error
                break
        if backend_error is not None and len(results) < len(tasks):
            for task in tasks[len(results):]:
                results.append(self._record_rejected_task(task, backend_error))
        return results, backend_error

    def _execute_serial(
        self,
        tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]],
    ) -> list[object]:
        results: list[object] = []
        for name, fn, args, kwargs in tasks:
            started_ns = time.monotonic_ns()
            self._record_submit()
            result = _execute_raw_task(started_ns, name, fn, args, kwargs)
            value, queue_wait_ns, execution_ns = result
            failed = type(value) is dict and dict.get(value, "error") is not None
            self._record_done(
                queue_wait_ns=queue_wait_ns,
                execution_ns=execution_ns,
                failed=failed,
            )
            results.append(value)
        return results

    def _record_rejected_task(
        self,
        task: tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]],
        exc: BaseException,
    ) -> dict[str, object]:
        self._record_submit()
        result = _raw_task_error(task[0], exc)
        self._record_done(
            queue_wait_ns=0,
            execution_ns=0,
            failed=True,
        )
        return result

    def _reject_process_batch(
        self,
        tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]],
        exc: BaseException,
    ) -> list[object]:
        return [self._record_rejected_task(task, exc) for task in tasks]

    def execute(
        self,
        tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]],
        *,
        backend: str,
        requested_workers: int,
    ) -> list[object]:
        self._require_open()
        with self._lock:
            self._batch_count += 1
        use_serial = (
            not self.plan.parallel_enabled
            or requested_workers <= 1
            or len(tasks) <= self.plan.serial_task_threshold
        )
        if use_serial:
            with self._lock:
                self._serial_batch_count += 1
            return self._execute_serial(tasks)
        safe_backend = backend if backend in {"thread", "process"} else self.plan.default_backend
        if safe_backend != "process":
            with self._lock:
                self._thread_batch_count += 1
            results, _backend_error = self._execute_parallel(
                tasks,
                backend="thread",
                requested_workers=min(requested_workers, self.plan.intrastage_workers),
            )
            return results

        with self._lock:
            self._process_batch_count += 1
        if self._process_backend_unavailable:
            exc = _ProcessBackendUnavailable("intrastage_process_backend_unavailable")
            _record_process_backend_failure(exc)
            with self._lock:
                self._process_backend_failure_count += 1
            return self._reject_process_batch(tasks, exc)

        accepted_tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]] = []
        accepted_sizes: list[int] = []
        accepted_indices: list[int] = []
        merged: list[object | None] = [None] * len(tasks)
        for index, task in enumerate(tasks):
            request_bytes, measured = _pickle_size(task)
            if not measured:
                with self._lock:
                    self._serialization_measurement_failures += 1
                merged[index] = self._record_rejected_task(
                    task,
                    _ProcessTaskNotSerializable("intrastage_process_task_not_serializable"),
                )
                continue
            if request_bytes > self.plan.max_process_task_bytes:
                with self._lock:
                    self._process_payload_rejection_count += 1
                merged[index] = self._record_rejected_task(
                    task,
                    _ProcessTaskPayloadTooLarge("intrastage_process_task_payload_too_large"),
                )
                continue
            accepted_tasks.append(task)
            accepted_sizes.append(request_bytes)
            accepted_indices.append(index)

        if accepted_tasks:
            try:
                accepted_results, backend_error = self._execute_parallel(
                    accepted_tasks,
                    backend="process",
                    requested_workers=min(requested_workers, self.plan.intrastage_workers),
                    process_request_sizes=tuple(accepted_sizes),
                )
            except _ProcessBackendUnavailable as exc:
                _record_process_backend_failure(exc)
                with self._lock:
                    self._process_backend_failure_count += 1
                    self._process_backend_unavailable = True
                    pool = self._process_executor
                    self._process_executor = None
                if pool is not None:
                    pool.shutdown(wait=True, cancel_futures=True)
                accepted_results = self._reject_process_batch(accepted_tasks, exc)
                backend_error = None
            if backend_error is not None:
                _record_process_backend_failure(backend_error)
                with self._lock:
                    self._process_backend_failure_count += 1
                    self._process_backend_unavailable = True
                    pool = self._process_executor
                    self._process_executor = None
                if pool is not None:
                    pool.shutdown(wait=True, cancel_futures=True)
            for index, result in zip(accepted_indices, accepted_results, strict=True):
                merged[index] = result

        return [
            item
            if item is not None
            else self._record_rejected_task(
                tasks[index],
                _ProcessBackendUnavailable("intrastage_process_task_missing_result"),
            )
            for index, item in enumerate(merged)
        ]

    def metrics(self, *, closed: bool | None = None) -> IntrastageExecutorMetrics:
        with self._lock:
            return IntrastageExecutorMetrics(
                generation_id=self.snapshot.generation_id,
                owner_pid=self.owner_pid,
                session_start_count=1,
                session_reuse_count=self._session_reuse_count,
                thread_executor_start_count=self._thread_executor_start_count,
                process_executor_start_count=self._process_executor_start_count,
                process_backend_failure_count=self._process_backend_failure_count,
                process_payload_rejection_count=self._process_payload_rejection_count,
                batch_count=self._batch_count,
                serial_batch_count=self._serial_batch_count,
                thread_batch_count=self._thread_batch_count,
                process_batch_count=self._process_batch_count,
                task_submission_count=self._task_submission_count,
                task_completion_count=self._task_completion_count,
                task_failure_count=self._task_failure_count,
                executor_reuse_count=self._executor_reuse_count,
                max_inflight_tasks=self._max_inflight_tasks,
                backpressure_wait_ns=self._backpressure_wait_ns,
                queue_wait_ns=self._queue_wait_ns,
                execution_ns=self._execution_ns,
                process_request_bytes=self._process_request_bytes,
                process_result_bytes=self._process_result_bytes,
                serialization_measurement_failures=self._serialization_measurement_failures,
                closed=self._closed if closed is None else closed,
            )

    def close(self) -> IntrastageExecutorMetrics:
        with self._lock:
            if self._closed:
                return self.metrics(closed=True)
            self._closed = True
            thread_pool = self._thread_executor
            process_pool = self._process_executor
            self._thread_executor = None
            self._process_executor = None
        if thread_pool is not None:
            thread_pool.shutdown(wait=True, cancel_futures=True)
        if process_pool is not None:
            process_pool.shutdown(wait=True, cancel_futures=True)
        return self.metrics(closed=True)


class IntrastageExecutorRuntime:
    """Single process-local owner for the active scan generation's executors."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._session: IntrastageExecutorSession | None = None
        self._last_metrics: IntrastageExecutorMetrics | None = None

    def start(
        self,
        snapshot: ScanSessionSnapshot,
        *,
        process_backend_allowed: bool = True,
    ) -> IntrastageExecutorMetrics:
        if type(snapshot) is not ScanSessionSnapshot:
            raise TypeError("intrastage_scan_session_snapshot_required")
        if type(process_backend_allowed) is not bool:
            raise TypeError("intrastage_process_backend_policy_invalid")
        current_pid = os.getpid()
        with self._lock:
            session = self._session
            if session is not None and session.owner_pid != current_pid:
                self._session = None
                session = None
            if session is not None:
                if session.snapshot.generation_id != snapshot.generation_id:
                    raise RuntimeError("intrastage_executor_generation_already_active")
                if session.process_backend_allowed != process_backend_allowed:
                    raise RuntimeError("intrastage_executor_process_policy_mismatch")
                session.mark_reused()
                return session.metrics()
            session = IntrastageExecutorSession(
                snapshot,
                process_backend_allowed=process_backend_allowed,
            )
            self._session = session
            return session.metrics()

    def current(self) -> IntrastageExecutorSession | None:
        with self._lock:
            session = self._session
            if session is None or session.owner_pid != os.getpid():
                return None
            return session

    def close(self, snapshot: ScanSessionSnapshot | None = None) -> IntrastageExecutorMetrics | None:
        with self._lock:
            session = self._session
            if session is None or session.owner_pid != os.getpid():
                return self._last_metrics
            if snapshot is not None and session.snapshot.generation_id != snapshot.generation_id:
                raise RuntimeError("intrastage_executor_generation_mismatch")
            self._session = None
        metrics = session.close()
        with self._lock:
            self._last_metrics = metrics
        return metrics

    def metrics(self) -> IntrastageExecutorMetrics | None:
        with self._lock:
            session = self._session
            if session is not None and session.owner_pid == os.getpid():
                return session.metrics()
            return self._last_metrics


_INTRASTAGE_EXECUTOR_RUNTIME = IntrastageExecutorRuntime()


def start_intrastage_executor_session(snapshot: object) -> IntrastageExecutorMetrics:
    if type(snapshot) is not ScanSessionSnapshot:
        raise TypeError("intrastage_scan_session_snapshot_required")
    return _INTRASTAGE_EXECUTOR_RUNTIME.start(snapshot, process_backend_allowed=True)


def close_intrastage_executor_session(snapshot: object = None) -> IntrastageExecutorMetrics | None:
    if snapshot is not None and type(snapshot) is not ScanSessionSnapshot:
        raise TypeError("intrastage_scan_session_snapshot_required")
    return _INTRASTAGE_EXECUTOR_RUNTIME.close(snapshot)


def intrastage_executor_metrics() -> IntrastageExecutorMetrics | None:
    return _INTRASTAGE_EXECUTOR_RUNTIME.metrics()


def active_intrastage_execution_plan() -> IntrastageExecutionPlan | None:
    session = _INTRASTAGE_EXECUTOR_RUNTIME.current()
    return None if session is None else session.plan


def effective_intrastage_enabled() -> bool:
    plan = active_intrastage_execution_plan()
    if plan is not None:
        return plan.intrastage_enabled and plan.stage_parallel_enabled
    return intrastage_enabled() and stage_parallel_enabled()


def effective_stage_parallel_workers() -> int:
    plan = active_intrastage_execution_plan()
    if plan is not None:
        return plan.intrastage_workers
    return stage_parallel_workers()


def effective_intrastage_backend() -> str:
    session = _INTRASTAGE_EXECUTOR_RUNTIME.current()
    if session is not None:
        if not session.process_backend_allowed:
            return "thread"
        return session.plan.default_backend
    return intrastage_default_backend()


def execute_intrastage_tasks(
    tasks: list[tuple[object, Callable[..., object], tuple[object, ...], dict[str, object]]],
    *,
    backend: str,
    requested_workers: int,
) -> list[object]:
    session = _INTRASTAGE_EXECUTOR_RUNTIME.current()
    if session is None:
        # Direct API calls without a scan-session generation remain deterministic
        # and never create a file-scoped executor owner.
        results: list[object] = []
        for name, fn, args, kwargs in tasks:
            result, _queue_wait_ns, _execution_ns = _execute_raw_task(
                time.monotonic_ns(), name, fn, args, kwargs,
            )
            results.append(result)
        return results
    return session.execute(tasks, backend=backend, requested_workers=requested_workers)


__all__ = (
    "IntrastageExecutorMetrics",
    "IntrastageExecutorRuntime",
    "IntrastageExecutorSession",
    "active_intrastage_execution_plan",
    "close_intrastage_executor_session",
    "effective_intrastage_backend",
    "effective_intrastage_enabled",
    "effective_stage_parallel_workers",
    "execute_intrastage_tasks",
    "intrastage_executor_metrics",
    "start_intrastage_executor_session",
)
