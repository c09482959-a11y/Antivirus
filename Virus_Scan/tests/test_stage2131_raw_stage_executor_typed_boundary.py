from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.execution.raw_stage_executor import RawStageExecutionDependencies, execute_global_raw_stage_job
from Virus_Scan.scanners.raw_chunk_collectors import BytecodeChunkRequest, ContextualRawChunkRequest
from Virus_Scan.scheduler.context.inmemory_raw_stage_dependencies import raw_stage_failure_result as context_raw_stage_failure_result
from Virus_Scan.tests.support.static_inventory import read_python_file


class RawCacheState:
    def __init__(self, cached: object = None) -> None:
        self.cached = cached
        self.stored: list[tuple[object, object]] = []

    def raw_stage_cache_get(self, key: object) -> object:
        return self.cached

    def configure_raw_stage_cache(self, max_entries: int = 2048) -> object:
        return max_entries

    def raw_stage_cache_put(self, key: object, value: object) -> object:
        self.stored.append((key, value))
        return None


def _deps(cache_state: RawCacheState | None = None) -> RawStageExecutionDependencies:
    state = cache_state if cache_state is not None else RawCacheState()
    return RawStageExecutionDependencies(
        raw_chunk_bytes=lambda: 64,
        raw_stage_cache_key=lambda job: (job.get("collector"), job.get("file")),
        raw_stage_cache_allowed=lambda job: True,
        scheduler_runtime_state=lambda: state,
        make_json_safe=lambda value: value,
        record_suppressed=lambda _where, _exc: None,
        micro_stage_collect=lambda _stage, _path: ["identity_tag"],
        read_range_text=lambda _path, start=0, size=0: "text",
        contextual_chunk_raw=lambda _text, **_kwargs: ["context_tag"],
        should_context_scan=lambda _text: False,
        decoded_chunk_tags=lambda _text, **_kwargs: ["decode_tag"],
        should_decode_scan=lambda _text: False,
        explicit_missed_family_tag_scan=lambda _text, **_kwargs: ["payload_tag"],
        pe_api_header=lambda _path: {"tags": ["pe_api"]},
        pe_api_chunk=lambda *_args, **_kwargs: {"tags": ["pe_api_chunk"], "strings_blob": ""},
        pure_pe_header=lambda _path: {"tags": ["pure_pe"], "suspicious": False},
        contextual_tag_scan=lambda *_args, **_kwargs: [],
        context_failure=lambda *_args, **_kwargs: {},
        dotnet_header=lambda *_args, **_kwargs: {"tags": ["dotnet"]},
        scan_dotnet_file=lambda *_args, **_kwargs: [],
        unity_dotnet_header=lambda *_args, **_kwargs: {"tags": ["unity_dotnet"]},
        scan_unity_dotnet_layered_file=lambda *_args, **_kwargs: [],
        unity_dotnet_chunk=lambda *_args, **_kwargs: {"tags": ["unity_dotnet_chunk"], "strings_blob": ""},
        extract_il_patterns=lambda *_args, **_kwargs: [],
        analyze_il_pipeline=lambda *_args, **_kwargs: {},
        record_issue=lambda *_args, **_kwargs: None,
        il2cpp_header=lambda *_args, **_kwargs: {"tags": ["il2cpp"]},
        read_file_bytes=lambda *_args, **_kwargs: b"",
        il2cpp_chunk=lambda *_args, **_kwargs: {"tags": ["il2cpp_chunk"], "strings_blob": ""},
        runtime_value=lambda _key, default=None: default,
        detect_unity_runtime_behavior=lambda *_args, **_kwargs: {},
        byte_entropy=lambda *_args, **_kwargs: 0.0,
        bytecode_header=lambda *_args, **_kwargs: {"tags": ["bytecode"]},
        get_scan_extension=lambda _path: ".bin",
        detect_pickle_exec=lambda *_args, **_kwargs: {},
        renpy_header=lambda *_args, **_kwargs: {"tags": ["renpy"]},
        renpy_chunk=lambda *_args, **_kwargs: {"tags": ["renpy_chunk"], "strings_blob": ""},
        scan_rpgm_file=lambda *_args, **_kwargs: ["rpgm"],
        rpgm_js_ast_header=lambda *_args, **_kwargs: {"tags": ["rpgm_js_ast"]},
        rpgm_js_ast_chunk=lambda *_args, **_kwargs: {"tags": ["rpgm_js_ast_chunk"], "strings_blob": ""},
        js_execution_model_tags=lambda *_args, **_kwargs: ["js_exec"],
        yara_rules_state=lambda: None,
        normalize_yara_hits=lambda value: value,
        yara_scan=lambda *_args, **_kwargs: [],
        yara_scan_with_optional_zip=lambda *_args, **_kwargs: [],
        raw_stage_failure_result=context_raw_stage_failure_result,
        normalize_raw_collector_value=lambda value: {"tags": list(value[0]) if value else []},
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        bytecode_chunk_request_factory=BytecodeChunkRequest,
        bytecode_chunk_request_owner=lambda request: {"tags": ["bytecode_chunk"], "strings_blob": ""},
        contextual_chunk_request_factory=ContextualRawChunkRequest,
        dotnet_chunk_request_owner=lambda request: {"tags": ["dotnet_chunk"], "strings_blob": ""},
        pure_pe_chunk_request_owner=lambda request: {"tags": ["pure_pe_chunk"], "strings_blob": ""},
    )


def test_stage2131_raw_stage_executor_source_uses_typed_dependency_aliases() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/execution/raw_stage_executor.py")

    assert "from typing import Any" not in source
    assert "dict[str, Any]" not in source
    assert "Callable[..., Any]" not in source
    assert "RawStageRuntimeCacheState" in source
    assert "RawStageJob: TypeAlias" in source
    assert "RawStageResult: TypeAlias" in source


def test_stage2131_raw_stage_executor_cache_hit_uses_typed_runtime_protocol(tmp_path: Path) -> None:
    state = RawCacheState({"tags": ["cached"], "file": str(tmp_path / "sample.bin")})

    out = execute_global_raw_stage_job(
        {"file": str(tmp_path / "sample.bin"), "collector": "identity"},
        deps=_deps(state),
    )

    assert out["tags"] == ["cached"]
    assert out["raw_stage_cache_hit"] is True
    assert state.stored == []


def test_stage2131_raw_stage_executor_cache_store_uses_typed_runtime_protocol(tmp_path: Path) -> None:
    state = RawCacheState()

    out = execute_global_raw_stage_job(
        {"file": str(tmp_path / "sample.bin"), "collector": "identity"},
        deps=_deps(state),
    )

    assert out["tags"] == ["identity_tag"]
    assert state.stored
    assert state.stored[0][0] == ("identity", str(tmp_path / "sample.bin"))
