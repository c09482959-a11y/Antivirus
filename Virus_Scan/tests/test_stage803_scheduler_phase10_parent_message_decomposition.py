from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import pytest
from Virus_Scan.scheduler.orchestration.inmemory_parent_message import InMemoryParentMessageResult

from pathlib import Path


def test_stage803_parent_message_orchestration_is_thin_worker_dispatcher():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_message.py"))

    assert "from dataclasses import dataclass" not in source
    assert "complete_inmemory_result_message" not in source
    assert "mark_worker_assigned_from_message" not in source
    assert "ingest_worker_heartbeat_message" not in source
    assert "reconcile_inmemory_worker_exit" not in source
    assert "handle_inmemory_result_worker_message" in source
    assert "handle_inmemory_assigned_worker_message" in source
    assert "record_unknown_inmemory_worker_message" in source


def test_stage803_parent_message_contracts_remain_import_compatible_and_immutable():

    result = InMemoryParentMessageResult(handled=True, should_continue=False)
    with pytest.raises(AttributeError):
        result.handled = False


def test_stage803_worker_handlers_are_owned_by_workers_package():
    source = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_parent_worker_messages.py"))

    assert "mark_worker_assigned_from_message" in source
    assert "mark_worker_running_from_message" in source
    assert "ingest_worker_heartbeat_message" in source
    assert "reconcile_inmemory_worker_exit" in source
    assert "complete_inmemory_result_message" not in source
