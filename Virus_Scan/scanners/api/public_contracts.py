"""Canonical public scanner contracts for production callers.

This module is the bounded public surface that production code may import when
it needs scanner-owned functionality.  It performs only static module-level
imports and exposes scanner-owned callables/constants without duplicating
implementation logic.
"""
from __future__ import annotations

from Virus_Scan.scanners import initialize_scanners
from Virus_Scan.scanners import archives as _archives
from Virus_Scan.scanners import binary as _binary
from Virus_Scan.scanners import dotnet as _dotnet
from Virus_Scan.scanners import dotnet_identity as _dotnet_identity
from Virus_Scan.scanners import entropy as _entropy
from Virus_Scan.scanners import il_pipeline as _il_pipeline
from Virus_Scan.scanners import ilspy as _ilspy
from Virus_Scan.scanners import image as _image
from Virus_Scan.scanners import payload_decode as _payload_decode
from Virus_Scan.scanners.pickle import scanner as _pickle_scanner
from Virus_Scan.scanners import pipeline as _pipeline
from Virus_Scan.scanners import raw_chunk_collectors as _raw_chunk_collectors
from Virus_Scan.scanners import raw_chunk_core as _raw_chunk_core
from Virus_Scan.scanners import raw_chunk_engine_collectors as _raw_chunk_engine_collectors
from Virus_Scan.scanners import raw_chunk_headers as _raw_chunk_headers
from Virus_Scan.scanners import raw_queue_scan_result as _raw_queue_scan_result
from Virus_Scan.scanners import renpy as _renpy
from Virus_Scan.scanners import rpgm as _rpgm
from Virus_Scan.scanners import strings as _strings
from Virus_Scan.scanners import text as _text
from Virus_Scan.scanners import unity as _unity
from Virus_Scan.scanners.archives import scan_archive_file
from Virus_Scan.scanners.binary_failover import should_binary_failover
from Virus_Scan.scanners.binary_embedded_payloads import validated_embedded_payload_hits
from Virus_Scan.scanners.binary_pe import global_raw_pure_pe_header, scan_pure_python_pe_file
from Virus_Scan.scanners.dotnet import (
    scan_unity_dotnet_layered_file,
    scan_unity_ilspy_file,
    unity_ilspy_should_run,
)
from Virus_Scan.scanners.dotnet_identity import (
    DOTNET_BEHAVIOR_MARKERS,
    DOTNET_EXTENSIONS,
    DOTNET_METADATA_MARKERS,
    dotnet_behavior_tags,
    dotnet_extension_tags,
    dotnet_metadata_present,
)
from Virus_Scan.scanners.entropy import (
    _strict_fast_entropy as strict_fast_entropy,
    byte_entropy,
    detect_packer_entropy_anomaly,
    entropy_bytes,
    tag_entropy,
)
from Virus_Scan.scanners.il_pipeline import analyze_il_pipeline, extract_il_patterns
from Virus_Scan.scanners.image import scan_image_file, scan_image_stego
from Virus_Scan.scanners.payload_decode import decoded_payload_records_from_bytes, embedded_payload_records_from_bytes, safe_decode_payloads
from Virus_Scan.scanners.pickle.scanner import (
    detect_python_pickle_opcode_exec,
    pickle_embedded_payload_tags,
    pickle_fragment_decode_records_from_analysis,
)
from Virus_Scan.scanners.pipeline import _aw_float as adaptive_weight_float, _ctx_re as scanner_context_regex, increment_counter
from Virus_Scan.scanners.raw_chunk_collectors import (
    bytecode_chunk, dotnet_chunk, pe_api_chunk, pure_pe_chunk,
)
from Virus_Scan.scanners.raw_chunk_core import (
    DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS, DEFAULT_GLOBAL_RAW_DECODE_ANCHORS,
    decoded_chunk_tags, read_range_text, should_context_scan, should_decode_scan,
)
from Virus_Scan.scanners.raw_chunk_engine_collectors import il2cpp_chunk, unity_dotnet_chunk
from Virus_Scan.scanners.raw_chunk_headers import dotnet_header, il2cpp_header, unity_dotnet_header

from Virus_Scan.scanners.raw_queue_scan_result import RawQueueScanResultDependencies, build_global_raw_scan_result
from Virus_Scan.scanners.renpy import global_raw_renpy_header
from Virus_Scan.scanners.rpgm import global_raw_rpgm_js_ast_header, scan_rpgm_file
from Virus_Scan.scanners.strings import (
    _append_intrastage_string_tasks as append_intrastage_string_tasks,
    _raw_stage_scan_strings as raw_stage_scan_strings,
    intrastage_contextual_chunk_raw,
    iter_ordered_string_events,
    scan_strings,
    _scan_strings_provider as scan_strings_provider,
)
from Virus_Scan.scanners.text_raw_chunks import (
    global_raw_pe_api_header,
    global_raw_renpy_chunk,
    global_raw_rpgm_js_ast_chunk,
)
from Virus_Scan.scanners.text_validation_gates import library_baseline_has_hard_proof
from Virus_Scan.scanners.unity import scan_unity_file

SCANNER_BOOTSTRAP_MODULE_NAMES = tuple(
    sorted(
        (
            _archives.__name__,
            _binary.__name__,
            _dotnet.__name__,
            _dotnet_identity.__name__,
            _entropy.__name__,
            _il_pipeline.__name__,
            _ilspy.__name__,
            _image.__name__,
            _payload_decode.__name__,
            _pickle_scanner.__name__,
            _pipeline.__name__,
            _raw_chunk_collectors.__name__,
            _raw_chunk_core.__name__,
            _raw_chunk_engine_collectors.__name__,
            _raw_chunk_headers.__name__,
            _raw_queue_scan_result.__name__,
            _renpy.__name__,
            _rpgm.__name__,
            _strings.__name__,
            _text.__name__,
            _unity.__name__,
        )
    )
)

__all__ = (
    "DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS",
    "DEFAULT_GLOBAL_RAW_DECODE_ANCHORS",
    "DOTNET_BEHAVIOR_MARKERS",
    "DOTNET_EXTENSIONS",
    "DOTNET_METADATA_MARKERS",
    "SCANNER_BOOTSTRAP_MODULE_NAMES",
    "RawQueueScanResultDependencies",
    "adaptive_weight_float",
    "analyze_il_pipeline",
    "append_intrastage_string_tasks",
    "build_global_raw_scan_result",
    "byte_entropy",
    "bytecode_chunk",
    "decoded_chunk_tags",
    "decoded_payload_records_from_bytes",
    "detect_packer_entropy_anomaly",
    "detect_python_pickle_opcode_exec",
    "dotnet_behavior_tags",
    "dotnet_chunk",
    "dotnet_extension_tags",
    "dotnet_header",
    "dotnet_metadata_present",
    "embedded_payload_records_from_bytes",
    "entropy_bytes",
    "extract_il_patterns",
    "global_raw_pe_api_header",
    "global_raw_pure_pe_header",
    "global_raw_renpy_chunk",
    "global_raw_renpy_header",
    "global_raw_rpgm_js_ast_chunk",
    "global_raw_rpgm_js_ast_header",
    "il2cpp_chunk",
    "il2cpp_header",
    "increment_counter",
    "initialize_scanners",
    "intrastage_contextual_chunk_raw",
    "iter_ordered_string_events",
    "library_baseline_has_hard_proof",
    "pe_api_chunk",
    "pickle_embedded_payload_tags",
    "pickle_fragment_decode_records_from_analysis",
    "pure_pe_chunk",
    "raw_stage_scan_strings",
    "read_range_text",
    "safe_decode_payloads",
    "scan_archive_file",
    "scan_image_file",
    "scan_image_stego",
    "scan_pure_python_pe_file",
    "scan_rpgm_file",
    "scan_strings",
    "scan_strings_provider",
    "scan_unity_dotnet_layered_file",
    "scan_unity_file",
    "scan_unity_ilspy_file",
    "scanner_context_regex",
    "should_binary_failover",
    "should_context_scan",
    "should_decode_scan",
    "strict_fast_entropy",
    "tag_entropy",
    "unity_dotnet_chunk",
    "unity_dotnet_header",
    "unity_ilspy_should_run",
    "validated_embedded_payload_hits",
)
