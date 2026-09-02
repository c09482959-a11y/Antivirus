from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config
from Virus_Scan.scheduler.timeout.inmemory_timeout_numeric_policy import (
    safe_timeout_policy_number,
    safe_timeout_result_count,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import (
    record_timeout_recovery_failure,
    timeout_recovery_failure_evidence,
    timeout_retry_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_config_values import (
    MinimumConfigEvidenceRequest,
    coerce_float_config,
    coerce_int_config,
    minimum_config_evidence,
    record_minimum_if_needed,
    timeout_config_evidence,
)


class HostileValue:
    def __bool__(self):  # pragma: no cover - hook execution proves the defect
        raise AssertionError("timeout config called __bool__")

    def __float__(self):  # pragma: no cover
        raise AssertionError("timeout config called __float__")

    def __int__(self):  # pragma: no cover
        raise AssertionError("timeout config called __int__")

    def __str__(self):  # pragma: no cover
        raise AssertionError("timeout config called __str__")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("timeout config called __repr__")


class HostileEnv:
    def get(self, _name, _default=None):  # pragma: no cover
        raise AssertionError("timeout config called env get")

    def items(self):  # pragma: no cover
        raise AssertionError("timeout config called env items")

    def __iter__(self):  # pragma: no cover
        raise AssertionError("timeout config called env iter")

    def __bool__(self):  # pragma: no cover
        raise AssertionError("timeout config called env bool")


class HostileError(RuntimeError):
    def __str__(self):  # pragma: no cover
        raise AssertionError("timeout config called error __str__")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("timeout config called error __repr__")


def test_stage1941_timeout_config_coercion_rejects_hostile_values_without_hooks():
    raw = HostileValue()
    setting = HostileValue()

    int_value, int_evidence = coerce_int_config(setting=setting, raw_value=raw, default=HostileValue())
    float_value, float_evidence = coerce_float_config(setting=setting, raw_value=raw, default=HostileValue())

    assert int_value == 0
    assert float_value == 0.0
    assert int_evidence[0]["setting"].startswith("<HostileValue")
    assert int_evidence[0]["raw_value"]["unsupported_scheduler_value"] is True
    assert int_evidence[0]["default_value"] == 0
    assert float_evidence[0]["raw_value"]["unsupported_scheduler_value"] is True
    assert "fallback_value" not in int_evidence[0]
    assert "fallback_value" not in float_evidence[0]


def test_stage1941_timeout_config_direct_evidence_and_minimum_errors_are_no_hook():
    direct = timeout_config_evidence(
        setting=HostileValue(),
        raw_value=HostileValue(),
        default_value=HostileValue(),
        error=HostileError("hidden"),
    )
    assert direct["setting"].startswith("<HostileValue")
    assert direct["raw_value"]["unsupported_scheduler_value"] is True
    assert direct["default_value"]["unsupported_scheduler_value"] is True
    assert direct["error_category"] == "HostileError"
    assert "hidden" not in direct["detail"]
    assert "fallback_value" not in direct

    minimum = minimum_config_evidence(
        setting=HostileValue(),
        raw_value=HostileValue(),
        minimum_value=HostileValue(),
        default_value=HostileValue(),
    )
    assert minimum["setting"].startswith("<HostileValue")
    assert "below minimum" in minimum["detail"]


def test_stage1941_timeout_config_minimum_and_env_rejection_paths_are_explicit():
    evidence = record_minimum_if_needed(
        MinimumConfigEvidenceRequest(
            evidence=(),
            setting="UMIGE_INMEMORY_PROGRESS_STALE_SEC",
            raw_value="1",
            parsed_value=1.0,
            minimum_value=120.0,
            default_value=240.0,
        )
    )
    assert evidence[0]["setting"] == "UMIGE_INMEMORY_PROGRESS_STALE_SEC"
    assert evidence[0]["default_value"] == 240.0

    config = build_inmemory_timeout_config(HostileEnv(), per_file_timeout_sec=HostileValue())
    assert config.base_file_timeout_seconds == 20
    assert config.max_job_retries == 5
    assert config.config_evidence
    assert {record["stage"] for record in config.config_evidence} == {"inmemory_timeout_config"}



def test_stage1941_timeout_retry_evidence_rejects_hostile_identity_and_text_fields():
    record = timeout_retry_evidence(
        job_id=HostileValue(),
        reason=HostileValue(),
        pid=HostileValue(),
        action=HostileValue(),
        attempt=HostileValue(),
        timeout_budget=HostileValue(),
        error_category=HostileValue(),
        error_source=HostileValue(),
        detail=HostileValue(),
    )
    assert record["job_id"]["unsupported_scheduler_value"] is True
    assert record["pid"]["unsupported_scheduler_value"] is True
    assert record["attempt"]["unsupported_scheduler_value"] is True
    assert record["reason"].startswith("<HostileValue")
    assert record["action"].startswith("<HostileValue")
    assert record["timeout_budget"]["unsupported_scheduler_value"] is True


def test_stage1941_timeout_recovery_failure_suppression_uses_projected_exception_text():
    failures = []

    def record_suppressed(_kind, _error):
        raise HostileError("suppressed secret")

    record_timeout_recovery_failure(
        failures=failures,
        job_id=HostileValue(),
        reason=HostileValue(),
        pid=HostileValue(),
        action=HostileValue(),
        attempt=HostileValue(),
        timeout_budget=HostileValue(),
        error=HostileError("primary secret"),
        source=HostileValue(),
        record_scheduler_suppressed=record_suppressed,
        recoverable_exceptions=(HostileError,),
    )
    assert len(failures) == 1
    failure = failures[0]
    assert failure["job_id"]["unsupported_scheduler_value"] is True
    assert "primary secret" not in failure["detail"]
    assert "suppressed secret" not in failure["detail"]
    assert "suppression_record_failed" in failure["detail"]

    direct = timeout_recovery_failure_evidence(
        job_id=HostileValue(),
        reason="unit",
        pid=HostileValue(),
        action="recover",
        attempt=HostileValue(),
        timeout_budget=HostileValue(),
        error=HostileError("direct secret"),
        source=HostileValue(),
    )
    assert direct["error_category"] == "HostileError"
    assert "direct secret" not in direct["detail"]


def test_stage1941_timeout_numeric_policy_rejects_hostile_field_and_values_without_hooks():
    failures = []
    value = safe_timeout_policy_number(
        value=HostileValue(),
        default=HostileValue(),
        field=HostileValue(),
        job_id=HostileValue(),
        record={},
        pid=HostileValue(),
        failures=failures,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
    )
    assert value == 0.0
    assert failures
    assert failures[0]["error_source"].startswith("inmemory_timeout_sweep.<HostileValue")
    assert failures[0]["reason"].startswith("<HostileValue")

    reporting_failures = []
    count = safe_timeout_result_count(value=HostileValue(), field=HostileValue(), reporting_failures=reporting_failures)
    assert count == 0
    assert reporting_failures
    assert reporting_failures[0]["reason"].startswith("<HostileValue")

def test_stage1941_timeout_config_values_source_guards_block_regression():
    sources = (
        read_python_file(Path("Virus_Scan/scheduler/timeout/inmemory_timeout_config_values.py")),
        read_python_file(Path("Virus_Scan/scheduler/timeout/inmemory_timeout_evidence.py")),
        read_python_file(Path("Virus_Scan/scheduler/timeout/inmemory_timeout_numeric_policy.py")),
    )
    forbidden = (
        "def env_value(",
        "fallback_value",
        "fallback=",
        'field_name=f"',
        'reason=f"',
        "ValueError(f",
        "return fallback",
        "scheduler_text(value, fallback=default",
        'reason=f"unsafe_',
        'f"{scheduler_exception_text',
        'f"suppression_record_failed=',
        "fallbacks or clean defaults",
        "fallback,",
        "fallback_reason",
        'source=f"inmemory_timeout_sweep',
        'reason=f"{field}',
        'non_finite_reason=f"{field}',
    )
    for source in sources:
        for snippet in forbidden:
            assert snippet not in source
