import json
from pathlib import Path

from Virus_Scan.core.paths import queue_result_record_name, _queue_job_dirs
from Virus_Scan.runtime.determinism import canonicalize_result_mapping
from Virus_Scan.publication.json_writer import finalize_scan_results


def testqueue_result_record_name_ignores_claim_pid_and_retry_prefix():
    a = queue_result_record_name('/q/active/worker_111_00000001_00000001.json', 'C:/Game/A.dll')
    b = queue_result_record_name('/q/active/reclaim02_worker_999_00000001_00000001.json', 'C:/Game/A.dll')
    assert a == b
    assert '111' not in a and '999' not in a and 'reclaim' not in a.lower()
    assert a.endswith('_A.dll.result.json')


def test_canonical_result_mapping_drops_concurrency_volatile_fields():
    left = {
        'b': {'tags': ['z', 'a'], 'worker_pid': 101, 'time': 'later', 'claim': 'worker_101_job.json'},
        'A': {'score': 1, 'updated_at': 999},
    }
    right = {
        'A': {'updated_at': 1, 'score': 1},
        'b': {'claim': 'worker_202_job.json', 'time': 'earlier', 'worker_pid': 202, 'tags': ['a', 'z']},
    }
    assert canonicalize_result_mapping(left) == canonicalize_result_mapping(right)


def test_finalizer_output_order_is_stable_across_insertion_order(tmp_path):
    p1 = tmp_path / 'one.json'
    p2 = tmp_path / 'two.json'
    r1 = {'b': {'file': 'b', 'tags': ['z', 'a'], 'score': 1}, 'A': {'file': 'A', 'tags': ['clean'], 'score': 0}}
    r2 = {'A': {'file': 'A', 'tags': ['clean'], 'score': 0}, 'b': {'file': 'b', 'tags': ['a', 'z'], 'score': 1}}
    assert finalize_scan_results(str(p1), r1, deterministic_mode=True)
    assert finalize_scan_results(str(p2), r2, deterministic_mode=True)
    assert json.loads(p1.read_text()) == json.loads(p2.read_text())


def test_raw_stage_queue_name_formula_is_deterministic_static_guard():
    src = Path(__file__).parents[1] / 'scheduler' / 'ownership' / 'raw_queue_publish.py'
    locked = Path(__file__).parents[1] / 'scheduler' / 'ownership' / 'raw_queue_publish_locked.py'
    boundary = Path(__file__).parents[1] / 'scheduler' / 'ownership' / 'raw_queue_publish_boundary.py'
    text = src.read_text(encoding='utf-8') + locked.read_text(encoding='utf-8')
    boundary_text = boundary.read_text(encoding='utf-8')
    assert "raw_publish_pending_name(fid, seq, attempt, collector)" in text
    assert 'int.__format__(seq, "06d")' in boundary_text
    assert 'int.__format__(attempt, "02d")' in boundary_text
    assert "raw_publish_collector_name" in text
    assert 'raw_{fid}_{seq:06d}_{os.getpid()}_{time.time_ns()}.json' not in text
