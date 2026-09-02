from __future__ import annotations

from pathlib import Path

import Virus_Scan.scheduler.queue.process_queue_finalization as finalization
from Virus_Scan.scheduler.queue.process_queue_finalization_decisions import (
    idle_optional_float_decision,
    queue_finish_claim_path_decision,
    queue_finish_job_attempt_decision,
)
from Virus_Scan.scheduler.queue.process_queue_idle_finalization import (
    ProcessQueueIdleFinalizationOutput,
    ProcessQueueIdleFinalizationRequest,
)


class HostileMapping(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise AssertionError("caller-owned get hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook executed")


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook executed")

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned str hook executed")

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned float hook executed")



def test_stage2179_queue_finish_attempt_decision_rejects_hostile_mapping_subclass_without_hooks() -> None:
    HostileMapping.reset()
    decision = queue_finish_job_attempt_decision(HostileMapping(attempt=5))

    assert decision.accepted is False
    assert decision.reason == "queue_finish_job_attempt_unavailable"
    assert decision.as_value() is None
    assert HostileMapping.touched == 0



def test_stage2179_queue_finish_attempt_decision_preserves_exact_dict_attempt() -> None:
    decision = queue_finish_job_attempt_decision({"attempt": 7})

    assert decision.accepted is True
    assert decision.reason == ""
    assert decision.as_value() == 7
    assert finalization._queue_finish_job_attempt({"attempt": 9}) == 9



def test_stage2179_claim_path_decision_replays_missing_and_blank_without_bool_hooks() -> None:
    HostileScalar.reset()

    missing = queue_finish_claim_path_decision(None)
    blank = queue_finish_claim_path_decision("")
    hostile = queue_finish_claim_path_decision(HostileScalar())

    assert missing.as_bool() is False
    assert missing.reason == "queue_finish_claim_path_missing"
    assert blank.as_bool() is False
    assert blank.reason == "queue_finish_claim_path_blank"
    assert hostile.as_bool() is True
    assert hostile.reason == ""
    assert HostileScalar.touched == 0



def test_stage2179_finish_process_queue_rejects_missing_claim_path_through_decision(tmp_path: Path) -> None:
    seen: list[tuple[str, object]] = []

    ok = finalization._finish_process_queue_job(
        tmp_path / "queue",
        None,
        record_suppressed=lambda where, exc, **kw: seen.append((where, kw)),
    )

    assert ok is False
    assert seen == []



def test_stage2179_idle_optional_float_decision_records_missing_and_rejected_values_without_hooks() -> None:
    HostileScalar.reset()

    missing = idle_optional_float_decision(None, reason="idle_done_since_rejected")
    rejected = idle_optional_float_decision(HostileScalar(), reason="idle_done_since_rejected")
    accepted = idle_optional_float_decision("2.5", reason="idle_done_since_rejected")

    assert missing.as_value() is None
    assert missing.reason == "idle_optional_float_missing"
    assert rejected.as_value() == 0.0
    assert rejected.reason == "idle_done_since_rejected"
    assert accepted.as_value() == 2.5
    assert accepted.accepted is True
    assert HostileScalar.touched == 0



def test_stage2179_idle_finalization_dataclasses_use_replayable_optional_float_decision() -> None:
    output = ProcessQueueIdleFinalizationOutput(
        idle_done_since=None,
        idle_notice_sec="3.0",
        had_error=False,
        should_stop=True,
    )
    request = ProcessQueueIdleFinalizationRequest(
        feed_complete=True,
        no_live_queue_work=True,
        accounted_files=1,
        total_files=2,
        idle_done_since=None,
        now="4.0",
        idle_grace_sec="5.0",
        idle_notice_sec="6.0",
        all_files=(),
        queue_dir="queue",
        outputs_dir="outputs",
        procs=(),
        live_workers=0,
    )

    assert output.idle_done_since is None
    assert output.idle_notice_sec == 3.0
    assert request.idle_done_since is None
    assert request.now == 4.0



def test_stage2179_sources_route_hidden_defaults_through_decisions() -> None:
    finalization_source = Path(finalization.__file__).read_text(encoding="utf-8")
    idle_source = Path(finalization.__file__).with_name("process_queue_idle_finalization.py").read_text(encoding="utf-8")

    assert "queue_finish_claim_path_decision(claim_path)" in finalization_source
    assert "queue_finish_job_attempt_decision(job).as_value()" in finalization_source
    assert "return None\n" not in finalization_source.split("def _queue_finish_job_attempt", 1)[1].split("def _finish_process_queue_job", 1)[0]
    assert "idle_optional_float_decision(value, reason=reason).as_value()" in idle_source
