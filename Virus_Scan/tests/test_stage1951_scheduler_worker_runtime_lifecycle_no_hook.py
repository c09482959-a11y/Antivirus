"""Stage1951 scheduler worker runtime/lifecycle no-hook closure."""
from __future__ import annotations

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from Virus_Scan.scheduler.workers.inmemory_runtime_config import build_inmemory_runtime_config_snapshot
from Virus_Scan.scheduler.workers.inmemory_scan_progress import InMemoryScanProgressEmitter
from Virus_Scan.scheduler.workers.inmemory_shared_heartbeat_row import parse_shared_heartbeat_row
from Virus_Scan.scheduler.workers.inmemory_worker_completion import collect_done_inmemory_worker_futures
from Virus_Scan.scheduler.workers.inmemory_worker_death import snapshot_inmemory_worker_liveness


from Virus_Scan.orchestration.yara_initialization import initialize_yara_worker_runtime
from Virus_Scan.orchestration.worker_runtime_descriptors import (
    WorkerYaraRuntimeDescriptor,
)

def _disabled_yara_descriptor() -> WorkerYaraRuntimeDescriptor:
    return WorkerYaraRuntimeDescriptor(
        initializer=initialize_yara_worker_runtime,
        root="/tmp/yara",
        enabled=False,
        available=False,
        scan_mode="auto",
        package_kind="",
        source_path="",
        source_digest="",
        compiled_cache_digest="",
        rule_catalog_digest="",
        unavailable_reason="yara_disabled",
    )


class HostileValue:
    touched = 0

    def __str__(self):
        HostileValue.touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        HostileValue.touched += 1
        raise RuntimeError("format hook executed")

    def __int__(self):
        HostileValue.touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):
        HostileValue.touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("bool hook executed")

    def __iter__(self):
        HostileValue.touched += 1
        raise RuntimeError("iter hook executed")


class HostileMapping(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        HostileMapping.touched += 1
        raise RuntimeError("mapping get hook executed")

    def keys(self):
        HostileMapping.touched += 1
        raise RuntimeError("mapping keys hook executed")

    def items(self):
        HostileMapping.touched += 1
        raise RuntimeError("mapping items hook executed")

    def __bool__(self):
        HostileMapping.touched += 1
        raise RuntimeError("mapping bool hook executed")


class HostileProc:
    touched = 0

    def __getattribute__(self, name):
        if name == "touched":
            return object.__getattribute__(self, name)
        HostileProc.touched += 1
        raise RuntimeError("process attribute hook executed")

    def __repr__(self):
        HostileProc.touched += 1
        raise RuntimeError("process repr hook executed")


class DummyCtx:
    def Array(self, _typecode, count, lock=False):
        return [0] * count

    def BoundedSemaphore(self, value):
        return {"semaphore": value}


class DummyCtypes:
    c_ulonglong = "Q"


def test_stage1951_scan_progress_rejects_hostile_stage_and_counts_without_hooks():
    HostileValue.touched = 0
    calls: list[tuple[str, int, int]] = []
    emitter = InMemoryScanProgressEmitter(
        progress_callback=lambda stage, inc, bytes_delta: calls.append((stage, inc, bytes_delta)) or True,
        cancel_error_type=KeyboardInterrupt,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda *_args: None,
    )

    assert emitter(HostileValue(), HostileValue(), HostileValue()) is True
    assert calls == [("scan", 1, 0)]
    assert HostileValue.touched == 0


def test_stage1951_runtime_config_rejects_hostile_scalars_and_environment_without_hooks():
    HostileValue.touched = 0
    HostileMapping.touched = 0

    snapshot = build_inmemory_runtime_config_snapshot(
        ctx=DummyCtx(),
        ctypes_module=DummyCtypes(),
        environ=HostileMapping({"UMIGE_DEEP_SCAN_MODE": HostileValue()}),
        recoverable_exceptions=(RuntimeError, ValueError, TypeError),
        get_init_value=lambda _name: None,
        file_count=2,
        workers=HostileValue(),
        logical_slots=HostileValue(),
        strict=HostileValue(),
        yara_enabled=False,
        scan_cache_enabled=False,
        yara_runtime_descriptor=_disabled_yara_descriptor(),
        per_file_timeout_sec=HostileValue(),
        slow_file_warn_sec=HostileValue(),
        worker_threads=HostileValue(),
        worker_threads_base=HostileValue(),
        worker_threads_max=HostileValue(),
        timeout_budget_factory=None,
        timeout_result_annotator=None,
        timeout_error_type=RuntimeError,
        mitre_initializer=lambda **_kwargs: None,
        mitre_root="/tmp/mitre",
        mitre_enabled=False,
        mitre_available=False,
        mitre_repository_digest="",
        mitre_dataset_version="",
        mitre_unavailable_reason="mitre_disabled",

        scan_session_snapshot=scan_session_snapshot_fixture(),
        routing_evidence_context=RoutingEvidenceContext.build("/tmp"),
    )

    assert snapshot.strict is False
    assert snapshot.per_file_timeout_sec == 0
    assert snapshot.slow_file_warn_sec == 0.0
    assert snapshot.deep_scan_mode == "auto"
    assert HostileValue.touched == 0
    assert HostileMapping.touched == 0


def test_stage1951_shared_heartbeat_row_uses_scheduler_mapping_without_record_get_hooks():
    HostileMapping.touched = 0
    row = {
        "monotonic_ns": 1_000_000_000,
        "pid": 11,
        "progress_counter": 3,
        "stage": "scan",
        "bytes_processed": 7,
        "last_progress_ns": 8,
        "flags": 0,
        "rss_mb": 1.5,
        "completed_jobs": 2,
    }

    parsed = parse_shared_heartbeat_row(
        row=row,
        record=HostileMapping({"pid": 22, "state": "running"}),
        heartbeat_flags=type("Flags", (), {"poisoned_or_retire_mask": 0})(),
        monotonic_ns=lambda: 2_000_000_000,
        wall_time=lambda: 10.0,
    )

    assert parsed.pid == 11
    assert parsed.state == "unknown"
    assert HostileMapping.touched == 0


def test_stage1951_completion_and_liveness_reject_hostile_containers_without_hooks():
    HostileMapping.touched = 0
    HostileProc.touched = 0

    assert collect_done_inmemory_worker_futures(HostileMapping()) == ()
    snapshot = snapshot_inmemory_worker_liveness(procs=(HostileProc(),))

    assert snapshot.live_count == 0
    assert snapshot.dead_pids == ()
    assert HostileMapping.touched == 0
    assert HostileProc.touched == 0
