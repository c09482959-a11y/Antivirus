import inspect

from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as factory
from Virus_Scan.scheduler.context import inmemory_raw_policy_dependencies as policy


def test_inmemory_raw_suppression_is_policy_owned_not_factory_duplicate():
    source = inspect.getsource(factory)
    assert "def _record_process_queue_suppressed" not in source
    assert factory._record_process_queue_suppressed is policy.record_process_queue_suppressed
