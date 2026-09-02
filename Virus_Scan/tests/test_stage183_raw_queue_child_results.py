from Virus_Scan.scheduler.workers import child_result_publication as child


def test_child_safe_exception_info_falls_back_with_metadata_error():
    seen = []
    def bad_builder(*args, **kwargs):
        raise RuntimeError('meta boom')
    def report(where, exc):
        seen.append((where, type(exc).__name__))
    info = child.safe_exception_info(
        ValueError('root'),
        stage='queue_child_outer',
        job={'attempt': 3},
        exception_info_builder=bad_builder,
        report=report,
        recoverable_exceptions=(RuntimeError,),
    )
    assert info['stage'] == 'queue_child_outer'
    assert info['exception_type'] == 'ValueError'
    assert info['attempt'] == 3
    assert info['exception_info_builder_unavailable_reason'] == 'caller_owned_exception_info_builder_rejected'
    assert seen == []


def test_child_result_persistence_reports_rejection_and_exception():
    seen = []
    def report(where, exc):
        seen.append(where)
    assert child.persist_child_result(
        child.ChildResultPersistRequest(
            queue_dir='q',
            claim_path='c',
            file_path='f',
            result={},
            context='ctx',
            write_result=lambda *a: False,
            report=report,
        )
    ) is False
    assert 'ctx.result_persist_rejected' in seen
    def boom(*args):
        raise OSError('disk')
    assert child.persist_child_result(
        child.ChildResultPersistRequest(
            queue_dir='q',
            claim_path='c',
            file_path='f',
            result={},
            context='ctx2',
            write_result=boom,
            report=report,
            recoverable_exceptions=(OSError,),
        )
    ) is False
    assert 'ctx2.result_persist_exception' in seen


def test_worker_output_update_reports_rejection_without_completion_side_effect(tmp_path):
    seen = []
    def report(where, exc):
        seen.append(where)
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    assert child.update_worker_output(
        child.WorkerOutputUpdateRequest(
            worker_output_path=blocked_parent / 'out.json',
            file_path='f',
            result={},
            child_results={},
            report=report,
        )
    ) is False
    assert seen == ['worker_output.aggregate_write_rejected']
