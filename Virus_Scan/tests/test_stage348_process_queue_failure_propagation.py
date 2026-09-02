from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.authority import queue_path_mtime_age
from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_float


def test_process_queue_mtime_failure_is_attributable(tmp_path):
    seen = []

    def record(where, exc, *, extra=None, fatal=False):
        seen.append((where, type(exc).__name__, dict(extra or {}), bool(fatal)))
        return True

    missing = tmp_path / "missing-active-job.json"

    assert queue_path_mtime_age(missing, now=100.0, record_suppressed=record) is None
    assert seen
    assert seen[0][0] == "process_queue_active_claim_mtime_unavailable"
    assert seen[0][2]["path"] == str(missing)
    assert seen[0][3] is False


def test_process_queue_claim_grace_uses_typed_env_parser():
    seen = []

    def record(where, exc, *, extra=None, fatal=False):
        seen.append((where, type(exc).__name__, dict(extra or {}), bool(fatal)))
        return True

    assert process_queue_env_float(
        "UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC",
        60.0,
        minimum=15.0,
        record_suppressed=record,
        env_get=lambda name, default=None: "not-a-number" if name == "UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC" else default,
    ) == pytest.approx(60.0)
    assert seen
    assert seen[0][0] == "process_queue_env_float_invalid"
    assert seen[0][2]["name"] == "UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC"
