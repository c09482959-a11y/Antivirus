from __future__ import annotations

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.raw_queue_failure import default_failure_info
from Virus_Scan.scheduler.execution.raw_stage_executor import RawStageExecutionDependencies, execute_global_raw_stage_job
from Virus_Scan.scanners.raw_chunk_collectors import BytecodeChunkRequest, ContextualRawChunkRequest
from Virus_Scan.scheduler.execution.raw_stage_failure import raw_stage_failure_result
from Virus_Scan.scheduler.execution.raw_work_executor import envelope_from_raw_result
from Virus_Scan.scheduler.execution.scan_job_executor import RawQueueJobExecutionDependencies, process_one_raw_stage_job
from Virus_Scan.scheduler.context.inmemory_raw_stage_dependencies import raw_stage_failure_result as context_raw_stage_failure_result
from Virus_Scan.scheduler.workers.child_result_publication import build_safe_exception_info


class HostileSchedulerValue:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __str__(self):
        HostileSchedulerValue.touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        HostileSchedulerValue.touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec):
        HostileSchedulerValue.touched += 1
        raise RuntimeError("do not format")

    def __int__(self):
        HostileSchedulerValue.touched += 1
        raise RuntimeError("do not int")

    def __bool__(self):
        HostileSchedulerValue.touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):
        HostileSchedulerValue.touched += 1
        raise RuntimeError("do not iterate")


class RawCacheState:
    def raw_stage_cache_get(self, key):
        return None

    def configure_raw_stage_cache(self, max_entries=2048):
        return None

    def raw_stage_cache_put(self, key, value):
        return None


def _raw_stage_deps(recorded=None):
    if recorded is None:
        recorded = []
    return RawStageExecutionDependencies(
        raw_chunk_bytes=lambda: 64,
        raw_stage_cache_key=lambda job: None,
        raw_stage_cache_allowed=lambda job: False,
        scheduler_runtime_state=lambda: RawCacheState(),
        make_json_safe=lambda value: value,
        record_suppressed=lambda where, exc: recorded.append((where, type(exc).__name__)),
        micro_stage_collect=lambda stage, path: ["identity_tag"],
        read_range_text=lambda path, start=0, size=0: "text",
        contextual_chunk_raw=lambda text, **kwargs: ["context_tag"],
        should_context_scan=lambda text: False,
        decoded_chunk_tags=lambda text, **kwargs: ["decode_tag"],
        should_decode_scan=lambda text: False,
        explicit_missed_family_tag_scan=lambda text, **kwargs: ["payload_tag"],
        pe_api_header=lambda path: {"tags": ["pe_api"]},
        pe_api_chunk=lambda *args, **kwargs: {"tags": ["pe_api_chunk"], "strings_blob": ""},
        pure_pe_header=lambda path: {"tags": ["pure_pe"], "suspicious": False},
        contextual_tag_scan=lambda *args, **kwargs: [],
        context_failure=lambda *args, **kwargs: {},
        dotnet_header=lambda *args, **kwargs: {"tags": ["dotnet"]},
        scan_dotnet_file=lambda *args, **kwargs: [],
        unity_dotnet_header=lambda *args, **kwargs: {"tags": ["unity_dotnet"]},
        scan_unity_dotnet_layered_file=lambda *args, **kwargs: [],
        unity_dotnet_chunk=lambda *args, **kwargs: {"tags": ["unity_dotnet_chunk"], "strings_blob": ""},
        extract_il_patterns=lambda *args, **kwargs: [],
        analyze_il_pipeline=lambda *args, **kwargs: {},
        record_issue=lambda *args, **kwargs: None,
        il2cpp_header=lambda *args, **kwargs: {"tags": ["il2cpp"]},
        read_file_bytes=lambda *args, **kwargs: b"",
        il2cpp_chunk=lambda *args, **kwargs: {"tags": ["il2cpp_chunk"], "strings_blob": ""},
        runtime_value=lambda key, default=None: default,
        detect_unity_runtime_behavior=lambda *args, **kwargs: {},
        byte_entropy=lambda *args, **kwargs: 0.0,
        bytecode_header=lambda *args, **kwargs: {"tags": ["bytecode"]},
        get_scan_extension=lambda path: ".bin",
        detect_pickle_exec=lambda *args, **kwargs: {},
        renpy_header=lambda *args, **kwargs: {"tags": ["renpy"]},
        renpy_chunk=lambda *args, **kwargs: {"tags": ["renpy_chunk"], "strings_blob": ""},
        scan_rpgm_file=lambda *args, **kwargs: ["rpgm"],
        rpgm_js_ast_header=lambda *args, **kwargs: {"tags": ["rpgm_js_ast"]},
        rpgm_js_ast_chunk=lambda *args, **kwargs: {"tags": ["rpgm_js_ast_chunk"], "strings_blob": ""},
        js_execution_model_tags=lambda *args, **kwargs: ["js_exec"],
        yara_rules_state=lambda: None,
        normalize_yara_hits=lambda value: value,
        yara_scan=lambda *args, **kwargs: [],
        yara_scan_with_optional_zip=lambda *args, **kwargs: [],
        raw_stage_failure_result=context_raw_stage_failure_result,
        normalize_raw_collector_value=lambda value: {"tags": list(value[0]) if value else []},
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        bytecode_chunk_request_factory=BytecodeChunkRequest,
        bytecode_chunk_request_owner=lambda request: {"tags": ["bytecode_chunk"], "strings_blob": ""},
        contextual_chunk_request_factory=ContextualRawChunkRequest,
        dotnet_chunk_request_owner=lambda request: {"tags": ["dotnet_chunk"], "strings_blob": ""},
        pure_pe_chunk_request_owner=lambda request: {"tags": ["pure_pe_chunk"], "strings_blob": ""},
    )


def test_stage1615_raw_stage_executor_rejects_hostile_job_fields_without_hooks():
    HostileSchedulerValue.reset()
    hostile = HostileSchedulerValue()
    job = {
        "file": hostile,
        "collector": hostile,
        "start": hostile,
        "size": hostile,
        "attempt": hostile,
        "retried": hostile,
        "group_index": hostile,
        "group_count": hostile,
        "yara_source": hostile,
    }

    out = execute_global_raw_stage_job(job, deps=_raw_stage_deps())

    assert HostileSchedulerValue.touched == 0
    assert out["raw_stage_failed"] is True
    assert out["failure_stage"] == "raw_stage_input_rejected"
    evidence = out["raw_stage_boundary_evidence"]
    assert "file_unavailable" in evidence
    assert "collector_unavailable" in evidence
    assert "start_unavailable" in evidence
    assert "size_unavailable" in evidence
    assert "attempt_unavailable" in evidence
    assert "retried_unavailable" in evidence


def test_stage1615_raw_stage_executor_preserves_valid_identity_job(tmp_path):
    HostileSchedulerValue.reset()
    job = {
        "file": str(tmp_path / "sample.bin"),
        "collector": "identity",
        "file_id": "fid-stage1615",
        "seq": 7,
        "attempt": 2,
        "retried": True,
    }

    out = execute_global_raw_stage_job(job, deps=_raw_stage_deps())

    assert HostileSchedulerValue.touched == 0
    assert out["tags"] == ["identity_tag"]
    assert out["collector"] == "identity"
    assert out["attempt"] == 2
    assert out["retried"] is True


def test_stage1615_raw_stage_failure_result_does_not_materialize_hostile_fields():
    HostileSchedulerValue.reset()
    hostile = HostileSchedulerValue()

    out = raw_stage_failure_result(
        {"collector": hostile, "tags": hostile, "file_id": hostile, "file": hostile, "errors": hostile},
        hostile,
        RuntimeError(hostile),
        stage="raw_stage_execute",
        scanner_degraded_tags=lambda tags: [*tags, "scanner_failure", "scanner_degraded", "scan_incomplete"],
    )

    assert HostileSchedulerValue.touched == 0
    assert out["raw_stage_failed"] is True
    assert out["scheduler_failure_evidence"]
    assert "scheduler diagnostic detail unavailable" in out["error"]


def test_stage1615_scan_job_executor_rejects_hostile_job_and_result_fields_without_hooks(tmp_path):
    HostileSchedulerValue.reset()
    hostile = HostileSchedulerValue()
    claim = tmp_path / "active" / "claim.json"
    claim.parent.mkdir()
    claim.write_text("{}", encoding="utf-8")
    finish_calls = []
    suppressed = []
    appended = []
    job = {
        "job_type": "raw_stage",
        "file": hostile,
        "collector": hostile,
        "file_id": "fid-stage1615-scan-job",
        "seq": hostile,
        "attempt": hostile,
    }

    class Accumulator:
        def append(self, payload):
            appended.append(payload)

    deps = RawQueueJobExecutionDependencies(
        claim_matching=lambda *args, **kwargs: (job, claim),
        execute_stage_job=lambda _job: {"error": hostile, "collector": hostile, "tags": ["scanner_failure"]},
        envelope_from_raw_result=envelope_from_raw_result,
        result_has_infra_error=lambda result: True,
        classify_recovery=lambda *args, **kwargs: type("Decision", (), {})(),
        default_failure_info=default_failure_info,
        prepare_raw_retry=lambda *args, **kwargs: False,
        accumulator_store=lambda *args, **kwargs: Accumulator(),
        record_suppressed=lambda where, exc: suppressed.append((where, type(exc).__name__)),
        safe_exception_info=build_safe_exception_info,
        finish_job=lambda q, c, ok=True, error_info=None, job=None: finish_calls.append((ok, error_info, job)),
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )

    assert process_one_raw_stage_job(tmp_path, deps=deps) is True

    assert HostileSchedulerValue.touched == 0
    assert finish_calls and finish_calls[0][0] is True
    assert appended
    assert appended[0]["raw_execution_boundary_evidence"]["collector_unavailable"]
    assert finish_calls[0][1]["collector"]["unsupported_scheduler_value"] is True
    assert finish_calls[0][2]["collector"]["unsupported_scheduler_value"] is True
