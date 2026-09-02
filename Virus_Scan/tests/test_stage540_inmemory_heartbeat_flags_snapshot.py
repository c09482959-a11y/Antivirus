from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from dataclasses import FrozenInstanceError
import ctypes
from Virus_Scan.scheduler.runtime.multiprocessing_context import get_scheduler_multiprocessing_context

import pytest

from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import build_inmemory_heartbeat_flags
from Virus_Scan.scheduler.workers.inmemory_runtime_config import build_inmemory_runtime_config_snapshot


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


def _timeout_budget_factory(*args, **kwargs):
    return {}


def _timeout_result_annotator(result, *args, **kwargs):
    return result


def test_inmemory_heartbeat_flags_are_immutable_and_context_owned():
    values = {
        "HB_RUNNING": 8,
        "HB_CANCEL_REQUEST": 16,
        "HB_POISONED": 32,
        "HB_STALLED": 64,
        "HB_FORCE_RETIRE": 128,
    }
    flags = build_inmemory_heartbeat_flags(values.get)

    assert flags.running == 8
    assert flags.cancel_stall_poison_mask == (16 | 64 | 32)
    assert flags.poisoned_or_retire_mask == (32 | 128)

    with pytest.raises(FrozenInstanceError):
        flags.running = 1


def test_inmemory_runtime_snapshot_carries_heartbeat_flags_to_worker_payload():
    ctx = get_scheduler_multiprocessing_context()
    snapshot = build_inmemory_runtime_config_snapshot(
        ctx=ctx,
        ctypes_module=ctypes,
        environ={},
        recoverable_exceptions=(OSError, ValueError, TypeError, RuntimeError),
        get_init_value=lambda name: {
            "HB_RUNNING": 1,
            "HB_CANCEL_REQUEST": 2,
            "HB_POISONED": 4,
            "HB_STALLED": 8,
            "HB_FORCE_RETIRE": 16,
        }.get(name),
        file_count=1,
        workers=1,
        logical_slots=1,
        strict=False,
        yara_enabled=False,
        scan_cache_enabled=False,
        yara_runtime_descriptor=_disabled_yara_descriptor(),
        per_file_timeout_sec=10,
        slow_file_warn_sec=1.0,
        worker_threads=1,
        worker_threads_base=1,
        worker_threads_max=1,
        timeout_budget_factory=_timeout_budget_factory,
        timeout_result_annotator=_timeout_result_annotator,
        timeout_error_type=TimeoutError,
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

    payload = snapshot.as_worker_config()
    assert payload["heartbeat_flags"] is snapshot.heartbeat_flags
    assert payload["heartbeat_flags"].cancel_stall_poison_mask == (2 | 8 | 4)
