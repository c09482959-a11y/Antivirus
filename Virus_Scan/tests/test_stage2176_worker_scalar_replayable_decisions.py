import ast
import inspect

from Virus_Scan.scheduler.workers import inmemory_job_dispatch as dispatch
from Virus_Scan.scheduler.workers import inmemory_worker_death as death
from Virus_Scan.scheduler.workers.inmemory_runtime_env import InMemoryRuntimeEnvValueDecision, env_value, env_value_decision
from Virus_Scan.scheduler.workers.inmemory_worker_assignment import InMemoryAssignedTask, InMemoryWorkerTaskDecision, parse_inmemory_worker_task, parse_inmemory_worker_task_decision
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import WorkerSharedHeartbeatGenerationDecision, _coerce_generation, _coerce_generation_decision


class HostileValue:
    touched = 0
    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("iteration hook touched")
    def __len__(self):
        type(self).touched += 1
        raise AssertionError("len hook touched")
    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("bool hook touched")
    def __getitem__(self, _key):
        type(self).touched += 1
        raise AssertionError("getitem hook touched")
    def __str__(self):
        type(self).touched += 1
        raise AssertionError("str hook touched")
    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("repr hook touched")


def test_stage2176_worker_scalar_absence_and_rejection_are_replayable_without_hooks() -> None:
    HostileValue.touched = 0
    hostile = HostileValue()
    proc_type = type("Proc", (), {})
    pid_rejected_proc = proc_type()
    pid_rejected_proc.pid = hostile

    assert env_value_decision(hostile, "UMIGE_WORKERS") == InMemoryRuntimeEnvValueDecision(None, "inmemory_runtime_env_source_rejected", False, False)
    assert env_value_decision({}, "UMIGE_WORKERS") == InMemoryRuntimeEnvValueDecision(None, "inmemory_runtime_env_value_missing", False, True)
    assert death._process_pid_decision(object()) == death.InMemoryWorkerProcessPidDecision(None, "inmemory_worker_process_state_unavailable", False, False)
    assert death._process_pid_decision(pid_rejected_proc) == death.InMemoryWorkerProcessPidDecision(None, "inmemory_worker_pid_rejected", False, True)
    assert _coerce_generation_decision(None) == WorkerSharedHeartbeatGenerationDecision(None, "worker_shared_heartbeat_generation_missing", False)
    assert _coerce_generation_decision(hostile) == WorkerSharedHeartbeatGenerationDecision(None, "worker_shared_heartbeat_generation_rejected", False)
    assert parse_inmemory_worker_task_decision(hostile, recoverable_exceptions=(RuntimeError, TypeError, ValueError), invalid_item_reporter=lambda _item, _exc: None) == InMemoryWorkerTaskDecision(None, "invalid worker assignment shape", False)
    assert dispatch._record_attempt_decision(hostile) == dispatch.InMemoryDispatchRecordAttemptDecision(0, "inmemory_dispatch_record_missing", False)
    assert dispatch._record_cost_decision(hostile) == dispatch.InMemoryDispatchRecordCostDecision(None, "inmemory_dispatch_record_missing", False)
    assert HostileValue.touched == 0


def test_stage2176_worker_projections_are_preserved() -> None:
    assert env_value({}, "UMIGE_WORKERS") is None
    assert env_value({"UMIGE_WORKERS": "4"}, "UMIGE_WORKERS") == "4"
    assert death._process_pid(object()) is None
    assert _coerce_generation(None) is None
    assert parse_inmemory_worker_task(object(), recoverable_exceptions=(Exception,)) is None
    parsed = parse_inmemory_worker_task(("job", "file.bin", 3), recoverable_exceptions=(Exception,))
    assert isinstance(parsed, InMemoryAssignedTask)
    assert parsed.attempt == 3
    assert dispatch._record_attempt(object()) == 0
    assert dispatch._record_cost(object()) is None


def _single_return_expression(function: object) -> str:
    tree = ast.parse(inspect.getsource(function))
    returns = [node for node in ast.walk(tree) if isinstance(node, ast.Return)]
    assert len(returns) == 1
    return ast.unparse(returns[0].value)


def test_stage2176_worker_projections_project_decision_fields_not_literal_defaults() -> None:
    assert _single_return_expression(env_value) == "env_value_decision(environ, name).as_value()"
    assert _single_return_expression(death._process_pid) == "_process_pid_decision(proc).as_pid()"
    assert _single_return_expression(_coerce_generation) == "_coerce_generation_decision(generation).as_generation()"
    assert _single_return_expression(parse_inmemory_worker_task).endswith(".as_task()")
    assert _single_return_expression(dispatch._record_attempt) == "_record_attempt_decision(record).as_attempt()"
    assert _single_return_expression(dispatch._record_cost) == "_record_cost_decision(record).as_cost()"
