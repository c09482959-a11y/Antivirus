import random
from Virus_Scan.scheduler.queue.inmemory_lifecycle import make_transition, replay_lifecycle, canonical_transition_key


def _stream():
    return [
        make_transition(epoch=7, sequence=1, job_id=2, attempt=0, transition="queued").to_dict(),
        make_transition(epoch=7, sequence=2, job_id=2, attempt=0, transition="assigned", worker_pid=99).to_dict(),
        make_transition(epoch=7, sequence=3, job_id=2, attempt=0, transition="running", worker_pid=99).to_dict(),
        make_transition(epoch=7, sequence=4, job_id=2, attempt=1, transition="retry_pending", worker_pid=99, reason="worker_died").to_dict(),
        make_transition(epoch=7, sequence=5, job_id=2, attempt=1, transition="queued").to_dict(),
        make_transition(epoch=7, sequence=6, job_id=2, attempt=1, transition="running", worker_pid=100).to_dict(),
        make_transition(epoch=7, sequence=7, job_id=2, attempt=1, transition="done", worker_pid=100).to_dict(),
        # stale old-generation completion arrives after retry generation exists; replay must ignore it
        make_transition(epoch=7, sequence=8, job_id=2, attempt=0, transition="failed", worker_pid=99).to_dict(),
    ]


def test_stage_x_replay_canonicalizes_arrival_order():
    base = _stream()
    expected = replay_lifecycle(base)
    for seed in range(100):
        shuffled = list(base)
        random.Random(seed).shuffle(shuffled)
        assert replay_lifecycle(shuffled) == expected
    assert expected[2]["attempt"] == 1
    assert expected[2]["state"] == "done"
    assert expected[2]["retry_pending_active"] is False


def test_stage_x_transition_key_ignores_wall_clock_arrival():
    a = make_transition(epoch=1, sequence=10, job_id=1, attempt=0, transition="done", timestamp=999.0).to_dict()
    b = make_transition(epoch=1, sequence=2, job_id=1, attempt=0, transition="queued", timestamp=1.0).to_dict()
    ordered = sorted([a, b], key=canonical_transition_key)
    assert [x["transition"] for x in ordered] == ["queued", "done"]


def test_stage_x_retry_exhaustion_terminal_failure_is_replay_visible():
    stream = [
        make_transition(epoch=9, sequence=1, job_id=4, attempt=0, transition="running", worker_pid=10).to_dict(),
        make_transition(epoch=9, sequence=2, job_id=4, attempt=1, transition="retry_pending", worker_pid=10, reason="worker_died").to_dict(),
        make_transition(epoch=9, sequence=3, job_id=4, attempt=1, transition="queued").to_dict(),
        make_transition(epoch=9, sequence=4, job_id=4, attempt=1, transition="running", worker_pid=11).to_dict(),
        make_transition(epoch=9, sequence=5, job_id=4, attempt=1, transition="failed", worker_pid=11, reason="worker_heartbeat_lost").to_dict(),
    ]
    replayed = replay_lifecycle(list(reversed(stream)))
    assert replayed[4]["attempt"] == 1
    assert replayed[4]["state"] == "failed"
    assert replayed[4]["retry_pending_active"] is False
    assert replayed[4]["terminal"] is True
