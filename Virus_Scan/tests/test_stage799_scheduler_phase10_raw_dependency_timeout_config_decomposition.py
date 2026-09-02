from pathlib import Path

from Virus_Scan.scheduler.context.inmemory_raw_dependency_factory import inmemory_raw_scan_dependencies
from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config


def _line_count(path: str) -> int:
    return len(Path(path).read_text(encoding="utf-8").splitlines())


def test_stage799_raw_dependency_factory_is_thin_context_entrypoint():
    factory = Path("Virus_Scan/scheduler/context/inmemory_raw_dependency_factory.py")
    policy = Path("Virus_Scan/scheduler/context/inmemory_raw_policy_dependencies.py")
    stage = Path("Virus_Scan/scheduler/context/inmemory_raw_stage_dependencies.py")
    assert factory.exists() and policy.exists() and stage.exists()
    assert _line_count(str(factory)) < 200
    assert _line_count(str(policy)) < 200
    assert _line_count(str(stage)) < 200
    text = factory.read_text(encoding="utf-8")
    assert "raw_stage_execution_dependencies" in text
    assert "InMemoryRawDependencyInputs" in text
    assert "from Virus_Scan.scheduler.context.inmemory_raw_stage_dependencies" in text


def test_stage799_raw_dependencies_still_preserve_explicit_boundaries():
    deps = inmemory_raw_scan_dependencies()
    assert callable(deps.global_raw_eligible)
    assert callable(deps.execute_stage_job)
    assert callable(deps.record_issue)
    assert callable(deps.apply_integrity_tags)


def test_stage799_timeout_config_value_coercion_is_bounded_and_evidence_backed():
    config = build_inmemory_timeout_config(
        {
            "UMIGE_INMEMORY_MAX_JOB_RETRIES": "bad",
            "UMIGE_INMEMORY_QUEUED_START_TIMEOUT_SEC": "1",
            "UMIGE_INMEMORY_HEARTBEAT_STALE_SEC": "nan",
        },
        per_file_timeout_sec="bad",
    )
    assert config.base_file_timeout_seconds == 20
    assert config.max_job_retries == 5
    assert config.queued_start_timeout_seconds == 300.0
    assert config.heartbeat_stale_seconds == 120.0
    assert config.config_evidence
    assert all(record.get("final_json_must_record") for record in config.config_evidence)
