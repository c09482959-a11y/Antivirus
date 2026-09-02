"""Scanner-owned public-export smoke case domain matrix.

This module owns the callable matrix by scanner domain.  The public smoke gate
and the case-context/helper construction stay in separate bounded CI modules.
"""
from __future__ import annotations

from pathlib import Path
from functools import partial
import zlib
from typing import Callable

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot

from Virus_Scan.scanners import archives, binary, dotnet, dotnet_identity, entropy, il_pipeline, ilspy, image, payload_decode, pickle_scan, pipeline, raw_chunk_collectors, raw_chunk_core, raw_chunk_engine_collectors, raw_chunk_headers, raw_queue_scan_result, renpy, rpgm, strings, text, unity
from Virus_Scan.scanners.strings import (
    _append_intrastage_string_tasks as _strings_append_intrastage_string_tasks,
    _intrastage_contextual_chunk_raw as _strings_intrastage_contextual_chunk_raw,
    _intrastage_decoded_chunk_raw as _strings_intrastage_decoded_chunk_raw,
    _raw_stage_scan_strings as _strings_raw_stage_scan_strings,
    _raw_stage_scan_strings_parallel as _strings_raw_stage_scan_strings_parallel,
    _split_text_for_intrastage as _strings_split_text_for_intrastage,
    _umige_ast_enriched_strings as _strings_umige_ast_enriched_strings,
)

_ARCHIVES_MODULE = "Virus_Scan.scanners.archives"
_BINARY_MODULE = "Virus_Scan.scanners.binary"
_DOTNET_MODULE = "Virus_Scan.scanners.dotnet"
_DOTNET_IDENTITY_MODULE = "Virus_Scan.scanners.dotnet_identity"
_ENTROPY_MODULE = "Virus_Scan.scanners.entropy"
_IL_PIPELINE_MODULE = "Virus_Scan.scanners.il_pipeline"
_ILSPY_MODULE = "Virus_Scan.scanners.ilspy"
_IMAGE_MODULE = "Virus_Scan.scanners.image"
_PAYLOAD_DECODE_MODULE = "Virus_Scan.scanners.payload_decode"
_PICKLE_SCAN_MODULE = "Virus_Scan.scanners." + "pickle_scan"
_PIPELINE_MODULE = "Virus_Scan.scanners.pipeline"
_RAW_CHUNK_COLLECTORS_MODULE = "Virus_Scan.scanners.raw_chunk_collectors"
_RAW_CHUNK_CORE_MODULE = "Virus_Scan.scanners.raw_chunk_core"
_RAW_CHUNK_ENGINE_COLLECTORS_MODULE = "Virus_Scan.scanners.raw_chunk_engine_collectors"
_RAW_CHUNK_HEADERS_MODULE = "Virus_Scan.scanners.raw_chunk_headers"
_RAW_QUEUE_SCAN_RESULT_MODULE = "Virus_Scan.scanners.raw_queue_scan_result"
_RENPY_MODULE = "Virus_Scan.scanners.renpy"
_RPGM_MODULE = "Virus_Scan.scanners.rpgm"
_STRINGS_MODULE = "Virus_Scan.scanners.strings"
_TEXT_MODULE = "Virus_Scan.scanners.text"
_UNITY_MODULE = "Virus_Scan.scanners.unity"


def archive_and_binary_cases(ctx: object) -> dict[tuple[str, str], Callable[[], object]]:
    return {
        (_ARCHIVES_MODULE, "extract_methods"): lambda: archives.extract_methods("class A { void Foo() {} }"),
        (_ARCHIVES_MODULE, "rarity_multiplier_for_probability"): lambda: archives.rarity_multiplier_for_probability(0.1),
        (_ARCHIVES_MODULE, "scan_extracted_archive_member"): lambda: archives.scan_extracted_archive_member(ctx.text_path),
        (_ARCHIVES_MODULE, "scan_archive_file"): partial(archives.scan_archive_file, ctx.zip_path),
        (_ARCHIVES_MODULE, "scan_rpa_file"): lambda: archives.scan_rpa_file(ctx.rpa_path),
        (_BINARY_MODULE, "engine_extension_key"): lambda: binary.engine_extension_key("unity", ctx.binary_path),
        (_BINARY_MODULE, "call_detector"): lambda: binary.call_detector(lambda: (0.0, [])),
        (_BINARY_MODULE, "detect_attack_chain"): lambda: binary.detect_attack_chain(["network_download", "process_exec"]),
        (_BINARY_MODULE, "detect_env_var_abuse"): lambda: binary.detect_env_var_abuse(["registry_mod", "process_exec"]),
        (_BINARY_MODULE, "detect_evasion_signals"): lambda: binary.detect_evasion_signals(["process_exec"]),
        (_BINARY_MODULE, "detect_ransomware_file_rename_heuristic"): lambda: binary.detect_ransomware_file_rename_heuristic(ctx.text_blob),
        (_BINARY_MODULE, "detect_staged_execution"): lambda: binary.detect_staged_execution(["network_download", "file_write", "process_exec"]),
        (_BINARY_MODULE, "engine_flow_contract_report"): lambda: binary.engine_flow_contract_report(),
        (_BINARY_MODULE, "is_dotnet_pe"): lambda: binary.is_dotnet_pe(ctx.bytes_blob),
        (_BINARY_MODULE, "extract_dotnet_metadata"): lambda: binary.extract_dotnet_metadata(ctx.binary_path),
        (_BINARY_MODULE, "filetype_validation_context"): lambda: binary.filetype_validation_context("unity", ctx.binary_path),
        (_BINARY_MODULE, "get_engine_filetype_info"): lambda: binary.get_engine_filetype_info("unity", ctx.binary_path),
        (_BINARY_MODULE, "get_global_filetype_info"): lambda: binary.get_global_filetype_info(ctx.binary_path),
        (_BINARY_MODULE, "scan_pure_python_pe_file"): lambda: binary.scan_pure_python_pe_file(ctx.binary_path),
        (_BINARY_MODULE, "should_binary_failover"): lambda: binary.should_binary_failover("unknown", "unknown", {"magic_stage": "unknown", "magic_type": "unknown", "ext": ".bin"}, [], []),
        (_BINARY_MODULE, "update_filetype"): lambda: binary.update_filetype("dll", []),
        (_BINARY_MODULE, "global_raw_pure_pe_header"): lambda: binary.global_raw_pure_pe_header(ctx.binary_path),
    }


def dotnet_entropy_image_cases(ctx: object) -> dict[tuple[str, str], Callable[[], object]]:
    return {
        (_DOTNET_MODULE, "scan_unity_dotnet_layered_file"): lambda: dotnet.scan_unity_dotnet_layered_file(ctx.binary_path),
        (_DOTNET_MODULE, "scan_unity_ilspy_file"): lambda: dotnet.scan_unity_ilspy_file(ctx.binary_path),
        (_DOTNET_MODULE, "unity_ilspy_should_run"): lambda: dotnet.unity_ilspy_should_run(ctx.binary_path),
        (_DOTNET_IDENTITY_MODULE, "dotnet_metadata_present"): lambda: dotnet_identity.dotnet_metadata_present(ctx.text_blob + " BSJB"),
        (_DOTNET_IDENTITY_MODULE, "dotnet_behavior_tags"): lambda: dotnet_identity.dotnet_behavior_tags(ctx.text_blob),
        (_DOTNET_IDENTITY_MODULE, "dotnet_extension_tags"): lambda: dotnet_identity.dotnet_extension_tags(".dll"),
        (_ENTROPY_MODULE, "tag_entropy"): lambda: entropy.tag_entropy(["a", "b", "a"]),
        (_ENTROPY_MODULE, "byte_entropy"): lambda: entropy.byte_entropy(b"abc"),
        (_ENTROPY_MODULE, "entropy_bytes"): lambda: entropy.entropy_bytes(b"abc"),
        (_ENTROPY_MODULE, "detect_packer_entropy_anomaly"): lambda: entropy.detect_packer_entropy_anomaly(ctx.binary_path),
        (_IL_PIPELINE_MODULE, "extract_il_patterns"): lambda: il_pipeline.extract_il_patterns(ctx.text_blob),
        (_IL_PIPELINE_MODULE, "analyze_il_pipeline"): lambda: il_pipeline.analyze_il_pipeline(ctx.binary_path, ["dotnet"], strings_blob=ctx.text_blob),
        (_ILSPY_MODULE, "scan_unity_ilspy_file"): lambda: ilspy.scan_unity_ilspy_file(ctx.binary_path),
        (_ILSPY_MODULE, "unity_ilspy_should_run"): lambda: ilspy.unity_ilspy_should_run(ctx.binary_path),
        (_IMAGE_MODULE, "rewrite_stego_tags"): lambda: image.rewrite_stego_tags(["stego"], b"abc", ctx.image_path),
        (_IMAGE_MODULE, "scan_image_file"): lambda: image.scan_image_file(
            ctx.image_path, artifact_read_snapshot=build_artifact_read_snapshot(ctx.image_path),
        ),
        (_IMAGE_MODULE, "scan_image_stego"): lambda: image.scan_image_stego(ctx.image_path),
    }


def payload_pickle_pipeline_cases(ctx: object) -> dict[tuple[str, str], Callable[[], object]]:
    return {
        (_PAYLOAD_DECODE_MODULE, "decoded_payload_behavior_tags"): lambda: payload_decode.decoded_payload_behavior_tags({"text": "exec powershell", "decode_chain": ["base64"]}, []),
        (_PAYLOAD_DECODE_MODULE, "decoded_payload_records_from_bytes"): lambda: payload_decode.decoded_payload_records_from_bytes(b"powershell cmd.exe", encoding_hint="smoke"),
        (_PAYLOAD_DECODE_MODULE, "decoded_payload_tags"): lambda: payload_decode.decoded_payload_tags("QUJD", finalize=False),
        (_PAYLOAD_DECODE_MODULE, "embedded_payload_records_from_bytes"): lambda: payload_decode.embedded_payload_records_from_bytes(b"prefix" + zlib.compress(b"powershell cmd.exe"), encoding_hint="smoke"),
        (_PAYLOAD_DECODE_MODULE, "expand_payload_decoder_chain"): lambda: payload_decode.expand_payload_decoder_chain(b"abc", encoding_hint="smoke"),
        (_PAYLOAD_DECODE_MODULE, "safe_decode_payloads"): lambda: payload_decode.safe_decode_payloads("QUJD"),
        (_PICKLE_SCAN_MODULE, "analyze_pickle_opcode_graph"): lambda: pickle_scan.analyze_pickle_opcode_graph(b"not pickle"),
        (_PICKLE_SCAN_MODULE, "unify_pickle_detection_tags"): lambda: pickle_scan.unify_pickle_detection_tags(["pickle_protocol_4"], ctx.text_path),
        (_PICKLE_SCAN_MODULE, "pickle_opcode_graph_tags"): lambda: pickle_scan.pickle_opcode_graph_tags(b"not pickle", path=ctx.text_path),
        (_PICKLE_SCAN_MODULE, "renpy_source_pickle_injection_tags"): lambda: pickle_scan.renpy_source_pickle_injection_tags("pickle.loads(data)", path=ctx.text_path),
        (_PICKLE_SCAN_MODULE, "pickle_embedded_payload_tags"): lambda: pickle_scan.pickle_embedded_payload_tags(b"pickle loads exec", path=ctx.text_path),
        (_PICKLE_SCAN_MODULE, "pickle_fragment_decode_records_from_analysis"): lambda: pickle_scan.pickle_fragment_decode_records_from_analysis(pickle_scan.analyze_pickle_opcode_graph(b"not pickle")),
        (_PICKLE_SCAN_MODULE, "detect_python_pickle_opcode_exec"): lambda: pickle_scan.detect_python_pickle_opcode_exec("pickle.loads(data)", ".py"),
        (_PICKLE_SCAN_MODULE, "pickle_fast_escalation_prefilter"): lambda: pickle_scan.pickle_fast_escalation_prefilter(ctx.text_path),
        (_PIPELINE_MODULE, "compute_flow_coherence"): lambda: pipeline.compute_flow_coherence(["network_download", "process_exec"]),
        (_PIPELINE_MODULE, "compute_similarity"): lambda: pipeline.compute_similarity(["a"], ["a", "b"]),
        (_PIPELINE_MODULE, "increment_counter"): lambda: pipeline.increment_counter({}, "smoke"),
    }


def raw_chunk_queue_cases(ctx: object, *, scanner_degraded_tags: Callable[[object], list[str]], report_failure: Callable[..., None], raw_queue_deps: Callable[[], object]) -> dict[tuple[str, str], Callable[[], object]]:
    return {
        (_RAW_CHUNK_COLLECTORS_MODULE, "BytecodeChunkRequest"): lambda: raw_chunk_collectors.BytecodeChunkRequest(
            ctx.text_path, 0, None, raw_chunk_core.read_range_text,
            lambda _path: ".rpy", lambda *_args, **_kwargs: [],
            raw_chunk_core.should_context_scan, lambda *_args, **_kwargs: [],
            lambda tags, *_args, **_kwargs: tags, report_failure, (Exception,),
        ),
        (_RAW_CHUNK_COLLECTORS_MODULE, "ContextualRawChunkRequest"): lambda: raw_chunk_collectors.ContextualRawChunkRequest(
            ctx.binary_path, 0, None, raw_chunk_core.read_range_text,
            raw_chunk_core.should_context_scan, lambda *_args, **_kwargs: [],
            lambda tags, *_args, **_kwargs: tags,
        ),
        (_RAW_CHUNK_CORE_MODULE, "context_anchor_status"): lambda: raw_chunk_core.context_anchor_status(),
        (_RAW_CHUNK_CORE_MODULE, "decode_anchor_status"): lambda: raw_chunk_core.decode_anchor_status(),
        (_RAW_CHUNK_CORE_MODULE, "raw_printable_ratio"): lambda: raw_chunk_core.raw_printable_ratio(ctx.text_blob),
        (_RAW_CHUNK_CORE_MODULE, "should_context_scan"): lambda: raw_chunk_core.should_context_scan(ctx.text_blob),
        (_RAW_CHUNK_CORE_MODULE, "should_decode_scan"): lambda: raw_chunk_core.should_decode_scan(ctx.text_blob),
        (_RAW_CHUNK_CORE_MODULE, "decoded_chunk_tags"): lambda: raw_chunk_core.decoded_chunk_tags("encodedcommand " + ("A" * 96), path=ctx.text_path, decoded_payload_tags=lambda *_args, **_kwargs: ["decoded_payload_smoke"], scanner_degraded_tags=scanner_degraded_tags, report=report_failure),
        (_RAW_CHUNK_CORE_MODULE, "read_range_text"): lambda: raw_chunk_core.read_range_text(ctx.text_path),
        (_RAW_CHUNK_COLLECTORS_MODULE, "bytecode_chunk"): lambda: raw_chunk_collectors.bytecode_chunk(
            raw_chunk_collectors.BytecodeChunkRequest(
                ctx.text_path,
                0,
                None,
                ctx.chunk_kwargs["read_range_text_func"],
                lambda path: ".rpy",
                lambda *_args, **_kwargs: [],
                ctx.chunk_kwargs["should_context_scan_func"],
                ctx.chunk_kwargs["contextual_scan"],
                ctx.chunk_kwargs["context_failure"],
                report_failure,
                (Exception,),
            )
        ),
        (_RAW_CHUNK_COLLECTORS_MODULE, "dotnet_chunk"): lambda: raw_chunk_collectors.dotnet_chunk(
            raw_chunk_collectors.ContextualRawChunkRequest(
                ctx.binary_path,
                0,
                None,
                ctx.chunk_kwargs["read_range_text_func"],
                ctx.chunk_kwargs["should_context_scan_func"],
                ctx.chunk_kwargs["contextual_scan"],
                ctx.chunk_kwargs["context_failure"],
            )
        ),
        (_RAW_CHUNK_COLLECTORS_MODULE, "pe_api_chunk"): lambda: raw_chunk_collectors.pe_api_chunk(ctx.text_path, read_range_text_func=raw_chunk_core.read_range_text),
        (_RAW_CHUNK_COLLECTORS_MODULE, "pure_pe_chunk"): lambda: raw_chunk_collectors.pure_pe_chunk(
            raw_chunk_collectors.ContextualRawChunkRequest(
                ctx.binary_path,
                0,
                None,
                ctx.chunk_kwargs["read_range_text_func"],
                ctx.chunk_kwargs["should_context_scan_func"],
                ctx.chunk_kwargs["contextual_scan"],
                ctx.chunk_kwargs["context_failure"],
            )
        ),
        (_RAW_CHUNK_ENGINE_COLLECTORS_MODULE, "il2cpp_chunk"): partial(raw_chunk_engine_collectors.il2cpp_chunk, ctx.binary_path, read_range_text_func=raw_chunk_core.read_range_text, runtime_value=lambda _key, default=None: dict(default or {}), detect_unity_runtime_behavior=unity.detect_unity_runtime_behavior, byte_entropy=entropy.byte_entropy, report=report_failure, recoverable_exceptions=(Exception,)),
        (_RAW_CHUNK_ENGINE_COLLECTORS_MODULE, "unity_dotnet_chunk"): lambda: raw_chunk_engine_collectors.unity_dotnet_chunk(ctx.binary_path, extract_il_patterns=il_pipeline.extract_il_patterns, analyze_il_pipeline=il_pipeline.analyze_il_pipeline, report_issue=report_failure, **ctx.chunk_kwargs),
        (_RAW_CHUNK_HEADERS_MODULE, "unity_dotnet_header"): lambda: raw_chunk_headers.unity_dotnet_header(ctx.binary_path, scan_unity_dotnet_layered_file=dotnet.scan_unity_dotnet_layered_file),
        (_RAW_CHUNK_HEADERS_MODULE, "dotnet_header"): lambda: raw_chunk_headers.dotnet_header(ctx.binary_path, scan_dotnet_file=dotnet.scan_unity_dotnet_layered_file),
        (_RAW_CHUNK_HEADERS_MODULE, "il2cpp_header"): lambda: raw_chunk_headers.il2cpp_header(ctx.binary_path, read_file_bytes=lambda path, max_size=None: Path(path).read_bytes()[: int(max_size or 1000000)]),
        (_RAW_QUEUE_SCAN_RESULT_MODULE, "RawQueueScanResultDependencies"): lambda: raw_queue_deps(),
        (_RAW_QUEUE_SCAN_RESULT_MODULE, "build_global_raw_scan_result"): lambda: raw_queue_scan_result.build_global_raw_scan_result(path=ctx.text_path, file_id="smoke", accum={"expected": 1, "completed": 1, "tags": ["raw"]}, identity={"tags": []}, effective_stage="raw", deps=raw_queue_deps()),
    }


def text_engine_cases(ctx: object) -> dict[tuple[str, str], Callable[[], object]]:
    return {
        (_STRINGS_MODULE, "ScanStringsRequest"): lambda: strings.ScanStringsRequest(
            ctx.text_blob, path=ctx.text_path
        ),
        (_RENPY_MODULE, "rpa_decoded_member_behavior_tags"): lambda: renpy.rpa_decoded_member_behavior_tags(b"pickle loads exec", path=ctx.rpa_path),
        (_RENPY_MODULE, "scan_renpy_file"): lambda: renpy.scan_renpy_file(ctx.text_path),
        (_RENPY_MODULE, "global_raw_renpy_header"): lambda: renpy.global_raw_renpy_header(ctx.text_path),
        (_RPGM_MODULE, "scan_rpgm_file"): lambda: rpgm.scan_rpgm_file(ctx.text_path),
        (_RPGM_MODULE, "global_raw_rpgm_js_ast_header"): partial(rpgm.global_raw_rpgm_js_ast_header, ctx.text_path),
        (_STRINGS_MODULE, "scan_strings"): lambda: strings.scan_strings(strings.ScanStringsRequest(ctx.text_blob, path=ctx.text_path)),
        (_STRINGS_MODULE, "iter_ordered_string_events"): lambda: list(strings.iter_ordered_string_events(ctx.text_blob)),
        (_STRINGS_MODULE, "intrastage_contextual_chunk_raw"): lambda: strings.intrastage_contextual_chunk_raw(ctx.text_blob, path=ctx.text_path, source="smoke", offset=0),
        (_STRINGS_MODULE, "_umige_ast_enriched_strings"): lambda: _strings_umige_ast_enriched_strings("x = 'abc'"),
        (_STRINGS_MODULE, "_split_text_for_intrastage"): lambda: list(_strings_split_text_for_intrastage(ctx.text_blob)),
        (_STRINGS_MODULE, "_intrastage_contextual_chunk_raw"): lambda: _strings_intrastage_contextual_chunk_raw(ctx.text_blob, path=ctx.text_path, source="smoke", offset=0),
        (_STRINGS_MODULE, "_intrastage_decoded_chunk_raw"): lambda: _strings_intrastage_decoded_chunk_raw("encodedcommand " + ("A" * 96), path=ctx.text_path, offset=0),
        (_STRINGS_MODULE, "_append_intrastage_string_tasks"): lambda: _strings_append_intrastage_string_tasks([], ctx.text_blob, path=ctx.text_path),
        (_STRINGS_MODULE, "_raw_stage_scan_strings"): lambda: _strings_raw_stage_scan_strings(ctx.text_blob, path=ctx.text_path),
        (_STRINGS_MODULE, "_raw_stage_scan_strings_parallel"): lambda: _strings_raw_stage_scan_strings_parallel(ctx.text_blob, path=ctx.text_path),
        (_UNITY_MODULE, "detect_unity_runtime_behavior"): lambda: unity.detect_unity_runtime_behavior(ctx.text_blob + " UnityEngine Application.persistentDataPath"),
        (_UNITY_MODULE, "scan_unity_file"): lambda: unity.scan_unity_file(ctx.binary_path),
    }


def text_policy_cases(ctx: object) -> dict[tuple[str, str], Callable[[], object]]:
    return {
        (_TEXT_MODULE, "TextGraphEnrichmentRequest"): lambda: text.TextGraphEnrichmentRequest(
            None, strings_blob=ctx.text_blob
        ),
        (_TEXT_MODULE, "api_ngrams"): lambda: text.api_ngrams(["CreateFileA", "WriteFile"], 2),
        (_TEXT_MODULE, "api_to_timeline_tag"): lambda: text.api_to_timeline_tag("CreateFileA"),
        (_TEXT_MODULE, "build_api_regex"): lambda: text.build_api_regex(),
        (_TEXT_MODULE, "build_api_sequence"): lambda: text.build_api_sequence(strings_blob=ctx.text_blob),
        (_TEXT_MODULE, "infer_tags_from_api"): lambda: text.infer_tags_from_api(["CreateFileA"], []),
        (_TEXT_MODULE, "primary_behavior_for_tag"): lambda: text.primary_behavior_for_tag("process_exec"),
        (_TEXT_MODULE, "build_behavior_timeline"): lambda: text.build_behavior_timeline(strings_blob=ctx.text_blob, tags=["process_exec"]),
        (_TEXT_MODULE, "enrich_with_api_and_graph"): lambda: text.enrich_with_api_and_graph(
            text.TextGraphEnrichmentRequest(None, strings_blob=ctx.text_blob)
        ),
        (_TEXT_MODULE, "extract_api_calls"): lambda: text.extract_api_calls(ctx.text_blob),
        (_TEXT_MODULE, "extract_api_sequence_from_blob"): lambda: text.extract_api_sequence_from_blob(ctx.text_blob),
        (_TEXT_MODULE, "gate_spyware_collection_chains"): lambda: text.gate_spyware_collection_chains(["process_exec"], path=ctx.text_path, strings_blob=ctx.text_blob),
        (_TEXT_MODULE, "infer_correlation_group"): lambda: text.infer_correlation_group("process_exec", ["process_exec"]),
        (_TEXT_MODULE, "library_baseline_hard_proof_status"): lambda: text.library_baseline_hard_proof_status(["process_exec"], ctx.text_blob),
        (_TEXT_MODULE, "library_baseline_has_hard_proof"): partial(text.library_baseline_has_hard_proof, ["process_exec"], ctx.text_blob),
        (_TEXT_MODULE, "map_api_to_group"): lambda: text.map_api_to_group("CreateFileA"),
        (_TEXT_MODULE, "reference_url_only_score_cap"): lambda: text.reference_url_only_score_cap(0.0, [], path=ctx.text_path, strings_blob=ctx.text_blob),
        (_TEXT_MODULE, "safe_decode_payloads"): lambda: text.safe_decode_payloads("QUJD"),
        (_TEXT_MODULE, "validate_high_risk_tag"): lambda: text.validate_high_risk_tag("process_exec", ctx.text_blob, ctx.text_path),
        (_TEXT_MODULE, "global_raw_pe_api_header"): lambda: text.global_raw_pe_api_header(ctx.binary_path),
        (_TEXT_MODULE, "global_raw_renpy_chunk"): lambda: text.global_raw_renpy_chunk(ctx.text_path),
        (_TEXT_MODULE, "global_raw_rpgm_js_ast_chunk"): lambda: text.global_raw_rpgm_js_ast_chunk(ctx.text_path),
    }


__all__ = (
    "archive_and_binary_cases",
    "dotnet_entropy_image_cases",
    "payload_pickle_pipeline_cases",
    "raw_chunk_queue_cases",
    "text_engine_cases",
    "text_policy_cases",
)
