"""Parent-side in-memory worker message orchestration."""
from __future__ import annotations


import Virus_Scan.scheduler.workers.inmemory_parent_state as _worker_parent_state_module
import Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message as _worker_heartbeat_message_module

from Virus_Scan.scheduler.orchestration.inmemory_parent_message_contracts import (
    InMemoryParentMessageRequest,
    InMemoryParentMessageResult,
)
from Virus_Scan.scheduler.orchestration.inmemory_parent_result_message import (
    handle_inmemory_result_worker_message,
)
from Virus_Scan.scheduler.workers.inmemory_parent_worker_messages import (
    handle_inmemory_assigned_worker_message,
    handle_inmemory_heartbeat_worker_message,
    handle_inmemory_running_worker_message,
    handle_inmemory_worker_exit_message,
    record_unknown_inmemory_worker_message,
)

_WORKER_MESSAGE_OWNERSHIP_MODULE_NAMES = tuple(
    sorted(
        (
            _worker_parent_state_module.__name__,
            _worker_heartbeat_message_module.__name__,
        )
    )
)


def handle_inmemory_parent_message(request: InMemoryParentMessageRequest) -> InMemoryParentMessageResult:
    msg = request.message
    result = InMemoryParentMessageResult(handled=False, should_continue=False)
    if msg:
        kind = msg[0]
        if kind in {"assigned", "started"}:
            result = handle_inmemory_assigned_worker_message(request)
        elif kind == "running":
            result = handle_inmemory_running_worker_message(request)
        elif kind == "heartbeat":
            result = handle_inmemory_heartbeat_worker_message(request)
        elif kind == "result":
            result = handle_inmemory_result_worker_message(request)
        elif kind == "worker_exit":
            result = handle_inmemory_worker_exit_message(request)
        else:
            result = record_unknown_inmemory_worker_message(msg)
    return result
