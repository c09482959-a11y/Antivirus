"""Stage2197 recovery contract strict-typing closure."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

from Virus_Scan.scheduler.queue.recovery_contract import (
    RecoveryHistoryTransitionRequest,
    build_inmemory_retry_transition,
    build_recovery_history_transition,
    cancel_payload,
    reset_queue_retry_runtime_metadata,
)

SOURCE = Path("Virus_Scan/scheduler/queue/recovery_contract.py")


class Stage2197HostileText:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __format__(self, _spec: str) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")


class Stage2197HostileInteger:
    touched = 0

    def __int__(self) -> int:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ executed")

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")


class Stage2197HostileMapping:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iteration executed")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items executed")



def test_stage2197_recovery_contract_exports_no_any_annotations() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    any_names = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "Any"]

    assert any_names == []
    assert "typing import Any" not in source
    assert "Any" not in source
    assert "SchedulerRecord" in source
    assert "object" in source



def test_stage2197_recovery_contract_keeps_no_hook_retry_evidence() -> None:
    Stage2197HostileText.touched = 0
    Stage2197HostileInteger.touched = 0
    Stage2197HostileMapping.touched = 0

    retry = build_inmemory_retry_transition(
        {"attempt": Stage2197HostileInteger(), "state": "running"},
        Stage2197HostileText(),
        pid=Stage2197HostileInteger(),
        now=30.0,
    ).as_record()
    history = build_recovery_history_transition(RecoveryHistoryTransitionRequest(
        cast(Any, Stage2197HostileMapping()),
        Stage2197HostileText(),
        attempt=Stage2197HostileInteger(),
        now=31.0,
    )).as_record()
    payload = cancel_payload(Stage2197HostileText(), Stage2197HostileInteger(), now=32.0)
    reset = reset_queue_retry_runtime_metadata(
        {"queue_info": {"retry_generation": Stage2197HostileInteger()}},
        now=33.0,
        reason=Stage2197HostileText(),
    )

    assert retry["attempt"] == 1
    retry_attempt_issue = cast(dict[str, Any], retry["attempt_issue"])
    assert retry_attempt_issue["error_category"] == "retry_attempt_rejected"
    assert retry_attempt_issue["value_type"] == "dict"
    assert "unsupported_retry_reason" in cast(str, retry["retry_pending_reason"])
    assert history["scheduler_mapping_unavailable"] is True
    assert payload["generation"] == 0
    assert cast(dict[str, Any], payload["generation_issue"])["value_type"] == "Stage2197HostileInteger"
    assert "unsupported_recovery_reason" in cast(str, payload["reason"])
    reset_queue_info = cast(dict[str, Any], reset["queue_info"])
    assert reset_queue_info["retry_generation"] == 1
    assert cast(dict[str, Any], reset_queue_info["retry_generation_issue"])["error_category"] == "retry_generation_rejected"
    assert "unsupported_recovery_reason" in cast(str, reset_queue_info["retry_pending_reason"])
    assert Stage2197HostileText.touched == 0
    assert Stage2197HostileInteger.touched == 0
    assert Stage2197HostileMapping.touched == 0
