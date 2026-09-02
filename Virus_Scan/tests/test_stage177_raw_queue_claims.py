from Virus_Scan.scheduler.queue.claim_sidecar_policy import active_claim_grace_sec, build_claim_sidecar_meta


def test_stage177_active_claim_grace_reports_invalid_value():
    events = []
    value = active_claim_grace_sec({'UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC': 'bad'}, report=lambda *a, **k: events.append((a, k)))
    assert value == 60.0
    assert events and events[0][0][0] == 'queue_active_claim_grace_invalid'


def test_stage177_claim_sidecar_meta_is_deterministic_and_non_mutating():
    job = {'file': 'game.rpy', 'attempt': 2, 'queue_info': {'existing': True}}
    meta, qi = build_claim_sidecar_meta('/tmp/active/job.json', job, now=100.0, pid=1234, worker_id='w1', progress_marker='claimed')
    assert job['queue_info'] == {'existing': True}
    assert meta['claim_job'] == 'job.json'
    assert meta['file'] == 'game.rpy'
    assert meta['attempt'] == 2
    assert qi['existing'] is True
    assert qi['worker_pid'] == 1234
    assert qi['claimed_time'] == 100.0
    assert qi['progress_marker'] == 'claimed'
