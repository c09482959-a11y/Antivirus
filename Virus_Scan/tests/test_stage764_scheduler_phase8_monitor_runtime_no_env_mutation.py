from __future__ import annotations

import os

from Virus_Scan.scheduler.orchestration.process_queue_monitor_runtime import build_process_queue_monitor_runtime_state


def test_stage764_monitor_runtime_uses_explicit_timeout_policy_without_env_mutation():
    sentinel = os.environ.get("UMIGE_PER_FILE_TIMEOUT_SEC")
    had_sentinel = "UMIGE_PER_FILE_TIMEOUT_SEC" in os.environ
    os.environ["UMIGE_PER_FILE_TIMEOUT_SEC"] = "77"
    try:
        state = build_process_queue_monitor_runtime_state(configured_per_file_timeout_sec=12)
        assert state.per_file_timeout_sec == 30.0
        assert state.timeout_config_evidence
        assert os.environ["UMIGE_PER_FILE_TIMEOUT_SEC"] == "77"
    finally:
        if had_sentinel:
            os.environ["UMIGE_PER_FILE_TIMEOUT_SEC"] = str(sentinel)
        else:
            os.environ.pop("UMIGE_PER_FILE_TIMEOUT_SEC", None)
