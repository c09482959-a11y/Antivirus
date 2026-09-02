import ast
from pathlib import Path

import Virus_Scan.scheduler.queue.claim as process_queue_engine
from Virus_Scan.scheduler.queue.authority import process_queue_merge_claim_meta_into_job as _queue_merge_claim_meta_into_job


def test_process_queue_engine_has_no_duplicate_top_level_definitions():
    source = Path(process_queue_engine.__file__).read_text(encoding='utf-8')
    tree = ast.parse(source)
    seen = {}
    duplicates = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            previous = seen.setdefault(node.name, node.lineno)
            if previous != node.lineno:
                duplicates.append((node.name, previous, node.lineno))
    assert duplicates == []


def test_claim_meta_merge_helper_preserves_job_without_shadow_dispatch():
    job = {'file': 'sample.bin', 'queue_file_id': 'abc'}
    merged = _queue_merge_claim_meta_into_job('sample.claim', job)
    assert merged == job
    assert merged is not job
