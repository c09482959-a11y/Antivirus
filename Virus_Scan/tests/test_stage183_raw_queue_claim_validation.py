from Virus_Scan.scheduler.ownership.raw_queue_claim_validation import repair_and_validate_claim_job


class Accum:
    def __init__(self, data):
        self.data = data
    def load(self):
        return dict(self.data)


def failure_info(**kwargs):
    return dict(kwargs)


def test_raw_claim_repairs_file_from_accumulator_before_validation():
    reported = []
    job, err = repair_and_validate_claim_job(
        'q',
        {'file_id': 'abc', 'collector': 'strings', 'seq': 4},
        failure_info=failure_info,
        file_id_for_path=lambda p: 'from-path',
        accumulator_factory=lambda q, fid: Accum({'file': '/tmp/game.bin'}),
        report=lambda *a, **k: reported.append((a, k)),
        worker_pid=123,
    )
    assert err is None
    assert job['job_type'] == 'raw_stage'
    assert job['file'] == '/tmp/game.bin'
    assert job['queue_info']['repaired_file_from_accumulator'] is True
    assert reported == []


def test_raw_claim_returns_typed_failure_for_missing_required_fields():
    job, err = repair_and_validate_claim_job(
        'q',
        {'raw_file_id': 'abc', 'seq': None},
        failure_info=failure_info,
        file_id_for_path=lambda p: 'from-path',
        accumulator_factory=lambda q, fid: Accum({}),
        report=lambda *a, **k: None,
        worker_pid=321,
    )
    assert job['job_type'] == 'raw_stage'
    assert err['exception_type'] == 'InvalidRawStageQueueJob'
    assert 'collector' in err['error']
    assert 'seq' in err['error']
    assert 'file' in err['error']


def test_missing_file_normal_job_is_queue_artifact_not_scan_failure():
    job, err = repair_and_validate_claim_job(
        'q',
        {'job_type': 'file'},
        failure_info=failure_info,
        file_id_for_path=lambda p: 'from-path',
        accumulator_factory=lambda q, fid: Accum({}),
        report=lambda *a, **k: None,
        worker_pid=1,
    )
    assert err['exception_type'] == 'InvalidFileQueueJob'
    assert err['extra']['queue_artifact'] is True
