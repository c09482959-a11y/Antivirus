from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from dataclasses import FrozenInstanceError
from Virus_Scan.scheduler.runtime.multiprocessing_context import get_scheduler_multiprocessing_context

import pytest

from Virus_Scan.scheduler.workers.inmemory_runtime_config import build_inmemory_runtime_config_snapshot
import ctypes


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


def test_inmemory_runtime_config_snapshot_is_immutable_and_explicit():
    ctx = get_scheduler_multiprocessing_context()
    snapshot = build_inmemory_runtime_config_snapshot(
        ctx=ctx,
        ctypes_module=ctypes,
        environ={
            'UMIGE_DEEP_SCAN_MODE': 'auto',
            'UMIGE_INMEMORY_HEARTBEAT_INTERVAL_SEC': '0.25',
            'UMIGE_INMEMORY_MAX_JOBS_PER_WORKER': '11',
            'UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB': '512',
        },
        recoverable_exceptions=(OSError, ValueError, TypeError, RuntimeError),
        file_count=2,
        workers=1,
        logical_slots=2,
        strict=True,
        yara_enabled=False,
        scan_cache_enabled=False,
        yara_runtime_descriptor=_disabled_yara_descriptor(),
        per_file_timeout_sec=7,
        slow_file_warn_sec=1.5,
        worker_threads=2,
        worker_threads_base=1,
        worker_threads_max=4,
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

    with pytest.raises(FrozenInstanceError):
        snapshot.strict = False

    payload = snapshot.as_worker_config()
    assert payload['strict'] is True
    assert payload['scan_cache_enabled'] is False
    assert payload['per_file_timeout_sec'] == 7
    assert payload['heartbeat_interval_sec'] == 0.25
    assert payload['max_jobs_per_worker'] == 11
    assert payload['worker_rss_limit_mb'] == 512.0
    assert set(payload['stage_limits']) == {'yara', 'image', 'archive', 'dotnet', 'raw', 'generic'}
    assert payload['cancel_table'] is not None
    assert payload['heartbeat_table'] is not None
