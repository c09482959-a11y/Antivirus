from pathlib import Path

import Virus_Scan.scheduler.queue.process_queue_finalization as pqf
from Virus_Scan.scheduler.queue.process_queue_idle_finalization import ProcessQueueIdleFinalizationOutput, ProcessQueueIdleFinalizationRequest


class HostileClaimPath:
    def __bool__(self):
        raise AssertionError("claim path bool hook executed")

    def __str__(self):
        raise AssertionError("claim path str hook executed")

    def __format__(self, spec):
        raise AssertionError("claim path format hook executed")


class HostileException(RuntimeError):
    def __str__(self):
        raise AssertionError("exception str hook executed")

    def __format__(self, spec):
        raise AssertionError("exception format hook executed")


def test_finish_process_queue_failure_logging_rejects_hostile_claim_path_without_hooks(tmp_path):
    messages = []
    suppressed = []
    ok = pqf._finish_process_queue_job(
        tmp_path / "queue",
        HostileClaimPath(),
        ok=True,
        record_suppressed=lambda where, exc, **kw: suppressed.append((where, kw)) or True,
        log_error=lambda message: messages.append(message) or True,
    )

    assert ok is False
    assert suppressed and suppressed[-1][0] == "queue_finish_failed"
    assert suppressed[-1][1]["fatal"] is True
    extra = suppressed[-1][1]["extra"]
    assert extra["claim_path"].startswith("<HostileClaimPath unsupported_queue_finish_claim_path")
    assert extra["ok"] is True
    assert messages
    assert messages[-1].startswith("process queue job finalization failed for " + extra["claim_path"] + ": ")


def test_finish_process_queue_failure_logging_rejects_hostile_exception_text_without_hooks(tmp_path):
    queue_dir = tmp_path / "queue"
    active = queue_dir / "active"
    active.mkdir(parents=True)
    claim = active / "worker_1_job.json"
    claim.write_text('{"file":"x"}', encoding="utf-8")
    messages = []
    suppressed_calls = 0

    def record_suppressed(*_args, **_kwargs):
        nonlocal suppressed_calls
        suppressed_calls += 1
        if suppressed_calls == 1:
            raise HostileException("boom")

    ok = pqf._finish_process_queue_job(
        queue_dir,
        claim,
        ok=True,
        remove_claim_meta=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup failed")),
        record_suppressed=record_suppressed,
        log_error=lambda message: messages.append(message) or True,
    )

    assert ok is False
    assert messages
    assert messages[-1].startswith("process queue job finalization failed for ")
    assert "scheduler diagnostic detail unavailable without caller hooks" in messages[-1]


class HostileScalar:
    def __bool__(self):
        raise AssertionError("scalar bool hook executed")

    def __str__(self):
        raise AssertionError("scalar str hook executed")

    def __int__(self):
        raise AssertionError("scalar int hook executed")

    def __float__(self):
        raise AssertionError("scalar float hook executed")


def test_idle_finalization_contract_rejects_hostile_scalar_defaults_without_hooks():
    hostile = HostileScalar()
    request = ProcessQueueIdleFinalizationRequest(
        feed_complete=hostile,
        no_live_queue_work=hostile,
        accounted_files=hostile,
        total_files=hostile,
        idle_done_since=hostile,
        now=hostile,
        idle_grace_sec=hostile,
        idle_notice_sec=hostile,
        all_files=(),
        queue_dir="queue",
        outputs_dir="outputs",
        procs=(),
        live_workers=hostile,
    )

    assert request.feed_complete is False
    assert request.no_live_queue_work is False
    assert request.accounted_files == 0
    assert request.total_files == 0
    assert request.idle_done_since == 0.0
    assert request.now == 0.0
    assert request.idle_grace_sec == 0.0
    assert request.idle_notice_sec == 0.0
    assert request.live_workers == 0

    output = ProcessQueueIdleFinalizationOutput(
        idle_done_since=hostile,
        idle_notice_sec=hostile,
        had_error=hostile,
        should_stop=hostile,
    )
    assert output.idle_done_since == 0.0
    assert output.idle_notice_sec == 0.0
    assert output.had_error is True
    assert output.should_stop is False
