from Virus_Scan.scheduler.queue import results as queue_results


def test_stage1071_queue_results_exports_public_result_readback_contracts_only():
    assert "load_queue_file_results" in queue_results.__all__
    assert "queue_done_jobs_missing_results" in queue_results.__all__
    assert "_load_queue_file_results" not in queue_results.__all__
    assert "_queue_done_jobs_missing_results" not in queue_results.__all__
    assert hasattr(queue_results, "load_queue_file_results")
    assert hasattr(queue_results, "queue_done_jobs_missing_results")
    assert not hasattr(queue_results, "_load_queue_file_results")
    assert not hasattr(queue_results, "_queue_done_jobs_missing_results")
