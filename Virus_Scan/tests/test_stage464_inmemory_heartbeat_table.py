from Virus_Scan.scheduler.orchestration import inmemory_parent_maintenance

import ctypes
import inspect
from Virus_Scan.scheduler.runtime.multiprocessing_context import get_scheduler_multiprocessing_context
import os

from Virus_Scan.scheduler.workers import heartbeat
from Virus_Scan.scheduler.orchestration import inmemory_parent_loop as inmemory


def _heartbeat_table(size=2):
    ctx = get_scheduler_multiprocessing_context()
    return {
        'monotonic_ns': ctx.Array(ctypes.c_ulonglong, size, lock=False),
        'pid': ctx.Array('i', size, lock=False),
        'thread_id': ctx.Array('i', size, lock=False),
        'generation': ctx.Array('i', size, lock=False),
        'stage': ctx.Array('i', size, lock=False),
        'progress_counter': ctx.Array('i', size, lock=False),
        'bytes_processed': ctx.Array(ctypes.c_ulonglong, size, lock=False),
        'last_progress_ns': ctx.Array(ctypes.c_ulonglong, size, lock=False),
        'flags': ctx.Array('i', size, lock=False),
        'rss_mb': ctx.Array('d', size, lock=False),
        'completed_jobs': ctx.Array('i', size, lock=False),
    }


def test_stage464_parent_uses_shared_heartbeat_table_reader():
    source = inspect.getsource(inmemory_parent_maintenance.run_inmemory_parent_maintenance)
    assert 'read_heartbeat=read_shared_heartbeat' in source
    assert 'hbrow = None\n                    if hbrow:' not in source


def test_stage464_shared_heartbeat_reader_preserves_progress_fields():
    table = _heartbeat_table()
    heartbeat.update_shared_heartbeat(
        table,
        1,
        2,
        pid=1234,
        thread_id=77,
        stage='archive',
        progress_counter=9,
        bytes_processed=4096,
        last_progress_ns=555,
        flags=heartbeat.HB_RUNNING,
        rss_mb=12.5,
        completed_jobs=3,
    )
    row = heartbeat.read_shared_heartbeat(table, 1, 2)
    assert row is not None
    assert row['pid'] == 1234
    assert row['thread_id'] == 77
    assert row['stage'] == 'archive'
    assert row['progress_counter'] == 9
    assert row['bytes_processed'] == 4096
    assert row['last_progress_ns'] == 555
    assert row['flags'] & heartbeat.HB_RUNNING
    assert row['completed_jobs'] == 3
