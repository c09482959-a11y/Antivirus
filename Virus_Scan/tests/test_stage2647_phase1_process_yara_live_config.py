"""Phase-1 regression for process-local YARA carrier preservation."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.runtime.yara_rules_state import YaraLightSnapshot
from Virus_Scan.scheduler.internal.live_worker_config import freeze_inmemory_worker_config
from Virus_Scan.scheduler.workers.inmemory_worker_job import InMemoryWorkerJobExecutionRequest


def test_live_worker_config_preserves_compiled_rules_identity_across_repeated_freeze() -> None:
    rules = object()
    snapshot = YaraLightSnapshot(rules=rules, ok=True, loaded_count=1)
    first = freeze_inmemory_worker_config({"compiled_rules": snapshot, "yara_enabled": True})
    assert dict(first)["compiled_rules"] is snapshot

    local = dict(first)
    local["progress_callback"] = lambda _stage: True
    second = freeze_inmemory_worker_config(local)
    assert dict(second)["compiled_rules"] is snapshot
    assert dict(second)["compiled_rules"].rules is rules


def test_worker_job_request_preserves_process_local_compiled_rules_identity(tmp_path: Path) -> None:
    rules = object()
    snapshot = YaraLightSnapshot(rules=rules, ok=True, loaded_count=1)
    request = InMemoryWorkerJobExecutionRequest.build(
        job_id=1,
        path=str(tmp_path / "sample.bin"),
        attempt=0,
        worker_config={"compiled_rules": snapshot, "yara_enabled": True},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags={},
        completed_jobs=0,
        task_meta=None,
    )
    retained = dict(request.worker_config)["compiled_rules"]
    assert retained is snapshot
    assert retained.rules is rules
