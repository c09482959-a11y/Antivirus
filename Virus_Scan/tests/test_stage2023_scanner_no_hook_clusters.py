from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scanners import (
    pipeline,
    raw_chunk_core,
    raw_chunk_engine_collectors,
    rpgm,
    strings,
    strings_ast,
    strings_intrastage,
    text_api_policy,
    text_api_sequence,
    text_api_timeline,
    text_behavior,
    text_contextual_tags,
    text_extraction,
    text_raw_chunks,
    text_validation_gates,
    unity,
)
from Virus_Scan.scanners.payload import base64_policy, chain as payload_chain, decode as payload_decode, evidence as payload_evidence, records as payload_records, tags as payload_tags
from Virus_Scan.scanners.pickle import (
    embedded_payloads,
    embedded_projection,
    embedded_streams,
    escalation,
    escalation_base64,
    escalation_context,
    escalation_io,
    escalation_rpyc,
    fragment_tags,
    global_references,
    graph_base,
    graph_tags,
    opcode_analysis,
    opcode_reduce,
    opcode_summary,
    payload_literal_records,
    payload_opcode_records,
    payload_tags as pickle_payload_tags,
    protocol,
    rpa_member_payloads,
    rpyc_chunks,
    rpyc_compression,
    rpyc_views,
    source_detection,
    source_opcode_exec,
)
from Virus_Scan.scanners.pickle import literals as pickle_literals
from Virus_Scan.scanners.pickle import trigger_evidence
from Virus_Scan.scanners import renpy


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile scanner hook")

    def __str__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()

    def __format__(self, _spec):  # pragma: no cover
        return self._touch()

    def __bool__(self):  # pragma: no cover
        return self._touch()

    def __int__(self):  # pragma: no cover
        return self._touch()

    def __iter__(self):  # pragma: no cover
        return self._touch()

    def __fspath__(self):  # pragma: no cover
        return self._touch()


class HostileAttribute(HostileValue):
    def __getattribute__(self, name):  # pragma: no cover - failure proves getattr execution
        if name in {"_touch", "__class__"}:
            return object.__getattribute__(self, name)
        return self._touch()


def test_stage2023_raw_chunk_core_rejects_hostile_text_numbers_and_paths_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    reports: list[tuple[str, dict[str, object]]] = []

    assert raw_chunk_core.raw_printable_ratio(hostile, sample_limit=hostile) == -1.0
    assert raw_chunk_core.should_context_scan(hostile, report=lambda stage, exc: reports.append((stage, {}))) is True
    assert raw_chunk_core.should_decode_scan(hostile, report=lambda stage, exc: reports.append((stage, {}))) is False

    tags = raw_chunk_core.decoded_chunk_tags(
        "A" * 120,
        path=hostile,
        offset=hostile,
        decoded_payload_tags=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decode failed")),
        scanner_degraded_tags=lambda values: ["scanner_failure", *values],
        report=lambda stage, exc, **kwargs: reports.append((stage, kwargs)),
        decode_anchors=("A",),
    )

    assert "raw_decoded_chunk_failed" in tags
    assert reports[-1][1]["extra"] == {"path": "", "offset": 0}
    assert HostileValue.touched == 0


def test_stage2023_text_extraction_rejects_hostile_text_path_and_decode_views_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()

    assert text_extraction._safe_cli_text(hostile) == "<HostileValue>"
    assert text_extraction._umige_ast_enriched_strings(hostile) == []
    assert text_extraction._umige_normalize_obfuscated_text(hostile) == ""
    assert isinstance(text_extraction._umige_build_extraction_view(hostile, path=hostile), str)
    assert HostileValue.touched == 0


def test_stage2023_pickle_trigger_and_literal_helpers_reject_hostile_records_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    analysis = {
        "trigger_windows": [{"ops": [{"opcode": hostile, "arg": hostile, "op_position": hostile}]}],
        "reduce_chains": [{"callable": hostile, "opcode": hostile, "stream_offset": hostile, "op_position": hostile}],
        "dangerous_globals": [hostile],
        "literal_fragments": [hostile],
    }

    assert trigger_evidence.record_trigger_windows(analysis) == ["unknown:"]
    assert trigger_evidence.pickle_trigger_summaries(analysis) == ([], ["unknown:"])
    assert pickle_literals._pickle_arg_to_text_status(hostile)[0] == "decode_error"
    assert pickle_literals.pickle_fragment_decode_records_from_analysis(analysis) == []
    assert HostileValue.touched == 0


def test_stage2023_strings_intrastage_rejects_hostile_limits_and_prefix_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()

    assert strings_intrastage._split_text_for_intrastage(hostile, min_chars=hostile, chunk_chars=hostile, overlap=hostile, max_chunks=hostile) == []
    tasks: list[tuple[object, ...]] = []
    strings_intrastage._append_intrastage_string_tasks(
        tasks,
        "short text",
        prefix=hostile,
        include_context=True,
        include_decode=False,
    )

    assert tasks[0][0] == "intrastage_context_raw"
    assert HostileValue.touched == 0


def test_stage2023_text_validation_and_api_sequence_do_not_format_hostile_inputs() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    logs: list[str] = []

    status = text_validation_gates.library_baseline_hard_proof_status(
        tags=(),
        strings_blob="sample",
        validation_text=lambda _blob: hostile,
        logger=logs.append,
    )
    api_tags = text_api_sequence.extract_api_calls(hostile, logger=logs.append)
    sequence = text_api_sequence.build_api_sequence(log_lines=hostile, strings_blob="")

    assert status == ("probe_error", True)
    assert logs == ["library baseline hard-proof text validation failed: unsafe_scanner_validation_text_rejected"]
    assert "unsafe_api_extract_text_rejected" in api_tags
    assert sequence == []
    assert HostileValue.touched == 0


def test_stage2023_payload_decode_package_rejects_hostile_inputs_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    results: list[dict[str, object]] = []
    seen: set[str] = set()

    assert base64_policy._b64_alphabet_kind(hostile) == "invalid"
    assert base64_policy._likely_base64_candidate(hostile) == (False, "too_short")
    assert payload_decode.safe_decode_payloads(hostile, max_depth=hostile) == []
    failure = payload_evidence._payload_decode_failure_record(hostile, "bad", encoding=hostile, depth=hostile)
    record = payload_records._record_decoded_result(results, seen, b"powershell http://example.invalid", "raw", hostile, 1, hostile)

    assert failure["evidence_id"] == "payload_decode_failure:payload_decode"
    assert failure["depth"] == 0
    assert record is not None
    assert record["parent_sha256"] == ""
    assert record["raw_sample"] == ""
    assert payload_records.decoded_payload_records_from_bytes(hostile) == []
    assert payload_tags.decoded_payload_tags(hostile) == []
    assert payload_chain._try_decoder_chain(hostile, encoding_hint=hostile) == []
    assert HostileValue.touched == 0


def test_stage2023_pickle_global_payload_and_renpy_boundaries_reject_hostile_values_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    logged: list[str] = []

    assert global_references._pickle_is_safe_reconstruct_global(hostile) is False
    assert global_references._pickle_is_dangerous_callable_global(hostile) is False
    assert global_references.pickle_reference_global_status(hostile) == "probe_error"
    status, value = global_references._pickle_canonical_global_status(hostile)
    assert status == "parse_error"
    assert isinstance(value, TypeError)

    assert pickle_payload_tags._pickle_decoded_payload_tags(hostile) == []
    assert pickle_payload_tags._decoded_payload_is_official_renpy_runtime([hostile], hostile, hostile) is False
    assert pickle_payload_tags._decoded_payload_exec_tags([hostile], hostile, path=hostile) == []
    assert renpy._is_valid_renpy_bytecode_header(hostile, b"RENPY RPC2") is False

    renpy._global_raw_renpy_header(hostile)
    result = renpy.scan_renpy_file(
        hostile,
        read_bytes=lambda _path: (_ for _ in ()).throw(OSError("read failed")),
        engine_threat_evaluator=lambda *_args, **_kwargs: {},
    )
    assert "scanner_failure" in result
    assert HostileValue.touched == 0


def test_stage2023_pickle_embedded_escalation_protocol_and_rpyc_boundaries_reject_hostile_values_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    hostile_attr = HostileAttribute()

    assert "scanner_failure" in embedded_payloads.pickle_embedded_payload_tags(hostile, path=hostile)
    assert embedded_projection._record_payload_tags({"encoding": hostile, "binary_magic": hostile, "text": hostile}, path=hostile)

    stream_tags: list[str] = []
    embedded_streams._append_stream_context_tags(stream_tags, hostile, ["pickle_opcode_execution"])
    assert "rpyc_decoded_stream_inspected" in stream_tags

    assert escalation.pickle_fast_escalation_prefilter(hostile, data=hostile, text=hostile) == {"hits": [], "tags": [], "force_full": False, "meta": {}}
    assert escalation_base64._pickle_fast_base64_status(hostile) == (False, 0)
    assert escalation_context._pickle_fast_text_has_pickle_context(hostile) is False
    assert escalation_context._pickle_fast_text_has_exec_context(hostile) is False
    assert escalation_context._pickle_fast_source_escalation(".rpy", "", hostile) is False
    assert escalation_io._pickle_fast_path_info(hostile) == ("", "")
    assert escalation_rpyc._pickle_fast_rpyc_view_hints(hostile, hostile, ".rpyc") == (False, False, False, [], [])

    assert fragment_tags.pickle_fragment_tags({"binary_magic": hostile, "text": hostile})
    assert graph_base.unify_pickle_detection_tags([hostile], path=hostile) == []
    assert "pickle_opcode_graph_scan_error" in graph_tags.pickle_opcode_graph_tags(hostile, path=hostile)
    assert opcode_analysis._pickle_opcode_name(hostile_attr) == ""
    opcode_reduce.append_reduce_chain(opcode_reduce.PickleReduceRequest({"dangerous_globals": [hostile], "reduce_chains": []}, [], hostile, "REDUCE", 0, hostile, []))
    assert opcode_summary.dedupe_literal_fragments({"literal_fragments": [hostile]}) == {"literal_fragments": [""]}
    assert payload_literal_records._try_decode_pickle_literal(hostile)
    assert list(payload_opcode_records.iter_pickle_payload_records(hostile))

    with pytest.raises(ValueError, match="unsafe_pickle_protocol_input_rejected"):
        protocol.has_pickle_protocol_header(hostile, max_bytes=hostile)
    with pytest.raises(ValueError, match="unsafe_pickle_protocol_input_rejected"):
        protocol.pickle_protocol_offsets(hostile, max_offsets=hostile, max_bytes=hostile)

    assert rpa_member_payloads.prepare_rpa_blob(hostile) == b"pickle_rpa_member_prepare_failure"
    assert rpa_member_payloads.member_rank((hostile, ())) == (2, "")
    assert list(rpyc_chunks._iter_renpy_rpc_chunks(hostile)) == [("rpyc_rpc_parse_failure", b"pickle_rpc_parse_failure")]
    assert list(rpyc_compression._iter_pickle_compressed_views(hostile, kind_prefix=hostile))[0][0] == "rpyc+compressed_scan_failure"
    assert list(rpyc_views.iter_rpyc_pickle_byte_views(hostile, path=hostile))[0][0] == "rpyc_input_conversion_failure"
    assert source_detection.renpy_pickle_path_status(hostile) == "probe_error"
    assert source_detection.renpy_source_pickle_injection_tags(hostile, path=hostile) == []
    assert source_opcode_exec.detect_python_pickle_opcode_exec(hostile, ext=hostile) == []
    assert HostileValue.touched == 0
    assert HostileAttribute.touched == 0


def test_stage2023_remaining_scanner_pipeline_text_and_engine_boundaries_reject_hostile_values_without_hooks() -> None:
    HostileValue.reset()
    hostile = HostileValue()
    reports: list[tuple[str, object, dict[str, object]]] = []

    assert pipeline._ctx_any(hostile, [hostile]) is False
    assert pipeline._high_gate_calls([hostile]) == set()
    assert pipeline._stable_entity_id(hostile, hostile).startswith("entity:")

    assert raw_chunk_engine_collectors._raw_chunk_path_text(hostile) == "raw_chunk_path_probe_error"
    assert raw_chunk_engine_collectors._raw_chunk_start(hostile) == 0
    raw_chunk_engine_collectors.il2cpp_chunk(
        hostile,
        start=hostile,
        read_range_text_func=lambda *_args, **_kwargs: "il2cpp assembly-csharp",
        runtime_value=lambda _name, default: hostile,
        detect_unity_runtime_behavior=lambda _text: [],
        byte_entropy=lambda _data: 0.0,
        report=lambda label, exc: reports.append((label, exc, {})),
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
    )
    raw_chunk_engine_collectors.unity_dotnet_chunk(
        hostile,
        start=hostile,
        read_range_text_func=lambda *_args, **_kwargs: "assembly-csharp unityengine",
        extract_il_patterns=lambda _text: (_ for _ in ()).throw(ValueError("il failed")),
        analyze_il_pipeline=None,
        should_context_scan_func=lambda _text: False,
        contextual_scan=lambda *_args, **_kwargs: [],
        context_failure=lambda *_args, **_kwargs: [],
        report_issue=lambda label, exc, **kwargs: reports.append((label, exc, kwargs)),
    )

    assert "scanner_failure" in rpgm.scan_rpgm_file(
        hostile,
        read_bytes=lambda _path: (_ for _ in ()).throw(OSError("read failed")),
        engine_threat_evaluator=lambda *_args, **_kwargs: {},
    )
    assert strings.scan_strings(strings.ScanStringsRequest(
        hostile,
        finalize=False,
        contextual_scanner=lambda *_args, **_kwargs: [],
        payload_decoder=lambda *_args, **_kwargs: [],
        intrastage_enabled_fn=lambda: True,
    )) == []
    assert strings_ast._umige_ast_enriched_strings(hostile, max_items=hostile) == []
    assert dict(text_api_policy._freeze_api_groups(hostile)) == {}
    assert text_api_policy.map_api_to_group(hostile) == "unknown"
    assert text_api_timeline.build_behavior_timeline(strings_blob=hostile, api_sequence=[hostile]) == ([], [])

    old_debug = text_behavior.DECODE_LAYER_DEBUG
    try:
        text_behavior.DECODE_LAYER_DEBUG = True
        text_behavior._decode_debug(hostile)
    finally:
        text_behavior.DECODE_LAYER_DEBUG = old_debug
    assert text_behavior._has_confirmed_exfil_proof("", {"network_exfiltration"}) is True
    assert text_behavior._has_input_collection_behavior("getasynckeystate password") is True
    assert "unsafe_contextual_text_rejected" in text_contextual_tags.contextual_tag_scan(hostile, path=hostile)
    read_result = text_raw_chunks._global_raw_read_range_text_result(
        hostile,
        start=hostile,
        open_reader=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read failed")),
    )
    assert "failure_tags" in read_result
    assert unity.detect_unity_runtime_behavior(hostile) == set()
    assert "scanner_failure" in unity.scan_unity_file(
        hostile,
        read_bytes=lambda _path: (_ for _ in ()).throw(OSError("read failed")),
        engine_threat_evaluator=lambda *_args, **_kwargs: {},
    )
    assert HostileValue.touched == 0


def test_stage2023_scanner_cluster_source_removed_audited_hook_patterns() -> None:
    checks = {
        "Virus_Scan/scanners/pipeline.py": [
            "text = str(text or '').lower()",
            "raw = (str(kind or 'entity') + ':' + str(value or '')).encode('utf-8', errors='ignore')",
            "return f'{kind}:{hashlib.sha256(raw).hexdigest()[:16]}'",
            "return f'{kind}:unknown'",
        ],
        "Virus_Scan/scanners/raw_chunk_engine_collectors.py": [
            "for key, sig in il_sigs.items():",
            "extra={'path': os.fspath(path), 'start': int(start or 0), 'collector': 'unity_dotnet_chunk'},",
        ],
        "Virus_Scan/scanners/rpgm.py": [
            'log_error(f"scan_rpgm_file input read failed for {path}: {exc}")',
        ],
        "Virus_Scan/scanners/strings.py": [
            "if intrastage_enabled_fn() and (len(str(strings_blob or '')) >= INTRASTAGE_MIN_TEXT_CHARS):",
        ],
        "Virus_Scan/scanners/strings_ast.py": [
            "max_items = int(max_items or STRINGS_AST_MAX_ITEMS)",
            "tree = ast.parse(str(code or ''))",
            "for val in env.values():",
        ],
        "Virus_Scan/scanners/text.py": [
            "fallback implementation and no duplicate logic; names are imported statically at",
        ],
        "Virus_Scan/scanners/text_api_policy.py": [
            "return MappingProxyType({canonical_api_text(group): tuple(canonical_api_text(api) for api in apis) for group, apis in dict(api_groups or {}).items()})",
            "for apis in source.values():",
            "for group, apis in API_GROUPS.items():",
        ],
        "Virus_Scan/scanners/text_api_timeline.py": [
            "log_error(f'API timeline extraction failed: {e}')",
        ],
        "Virus_Scan/scanners/text_behavior.py": [
            "log_error(f'decode debug: {msg}')",
            "return bool(tagset & {'network_exfiltration', 'token_exfiltration', 'http_upload', 'dns_tunneling'}",
            "return bool(strong_input_api and (sensitive_target or exfil_target))",
        ],
        "Virus_Scan/scanners/text_contextual_tags.py": [
            "missing_reason=f'missing_{field}',",
            "unsupported_reason=f'unsafe_{field}_rejected',",
        ],
        "Virus_Scan/scanners/text_raw_chunks.py": [
            "start_i = max(0, int(start or 0))",
            "tags += ['nodejs_native_bridge', 'script_to_process_chain']",
            "log_error(f'intrastage contextual chunk failed for {path} @{offset}: {e}')",
        ],
        "Virus_Scan/scanners/unity.py": [
            "if f'void {hook}' in text or f'{hook}(' in text:",
            "log_error(f'scan_unity_file input read failed for {path}: {exc}')",
        ],
        "Virus_Scan/scanners/pickle/embedded_payloads.py": [
            "log_error(f'pickle_embedded_payload_tags failed: {exc}')",
        ],
        "Virus_Scan/scanners/pickle/embedded_projection.py": [
            "enc = str(encoding or 'pickle_literal')",
            "tags.extend(['decoded_binary_payload', f\"decoded_{rec.get('binary_magic')}_payload\"])",
        ],
        "Virus_Scan/scanners/pickle/embedded_streams.py": [
            "tags.append(f'{enc_kind}_pickle_stream')",
        ],
        "Virus_Scan/scanners/pickle/escalation.py": [
            "low = str(text or '').lower()",
        ],
        "Virus_Scan/scanners/pickle/escalation_base64.py": [
            "sample = str(text or '')[:PICKLE_FAST_B64_SAMPLE_MAX]",
        ],
        "Virus_Scan/scanners/pickle/escalation_context.py": [
            "return any((needle in str(text or '') for needle in pickle_context_needles))",
            "low = str(text or '')",
            "return bool(exec_text or any((needle in low_text for needle in source_escalation_needles)))",
        ],
        "Virus_Scan/scanners/pickle/escalation_io.py": [
            "path_obj = Path(str(path))",
            "log_error(f'pickle_fast_escalation_prefilter failed for {path}: {error}')",
        ],
        "Virus_Scan/scanners/pickle/escalation_rpyc.py": [
            "hits.append(f'{view_kind}_pickle_protocol_hint')",
            "hits.append(f'{view_kind}_pickle_text_hint')",
        ],
        "Virus_Scan/scanners/pickle/fragment_tags.py": [
            "tags.extend(['decoded_binary_payload', f\"decoded_{rec.get('binary_magic')}_payload\"])",
            "low_text = str(text or '').lower()",
        ],
        "Virus_Scan/scanners/pickle/graph_base.py": [
            "if ext in RENPY_PICKLE_EXTENSIONS or 'renpy' in str(path or '').lower():",
        ],
        "Virus_Scan/scanners/pickle/graph_tags.py": [
            "log_error(f'pickle_opcode_graph_tags failed: {exc}')",
        ],
        "Virus_Scan/scanners/pickle/opcode_analysis.py": [
            "name = str(getattr(op, 'name', '') or '').upper()",
        ],
        "Virus_Scan/scanners/pickle/opcode_reduce.py": [
            "c = str(cand or '').lower()",
        ],
        "Virus_Scan/scanners/pickle/opcode_summary.py": [
            "fs = str(frag or '')",
        ],
        "Virus_Scan/scanners/pickle/payload_literal_records.py": [
            "records.extend(safe_decoder(text_view, max_depth=2))",
        ],
        "Virus_Scan/scanners/pickle/payload_opcode_records.py": [
            "name = getattr(op, 'name', '')",
        ],
        "Virus_Scan/scanners/pickle/protocol.py": [
            "return bytes(source)[: max(0, int(max_bytes or 0))]",
            "limit = max(1, int(max_offsets or 1))",
        ],
        "Virus_Scan/scanners/pickle/rpa_member_payloads.py": [
            "for member_name, entries in sorted(index.items(), key=member_rank):",
            "'source_file': str(path or ''),",
        ],
        "Virus_Scan/scanners/pickle/rpyc_chunks.py": [
            "yield (f'rpyc_rpc_slot{slot}_chunk', chunk)",
        ],
        "Virus_Scan/scanners/pickle/rpyc_compression.py": [
            "yield (f'{kind_prefix}+compressed_scan_failure', data)",
            "encoding_hint=f'{kind_prefix}@{off}'",
        ],
        "Virus_Scan/scanners/pickle/rpyc_views.py": [
            "if ext in RENPY_BYTECODE_EXTENSIONS or 'renpy' in str(path or '').lower():",
        ],
        "Virus_Scan/scanners/pickle/source_detection.py": [
            "low = str(path or '').lower()",
            "low = str(text or '').lower()",
            "if ext not in {'.rpy', '.rpyc', '.rpyb', '.rpymc', '.py', '.rpym'} and 'renpy' not in str(path or '').lower():",
        ],
        "Virus_Scan/scanners/pickle/source_opcode_exec.py": [
            "low = str(text or '').lower()",
            "ext = str(ext or '').lower()",
        ],
        "Virus_Scan/scanners/pickle/global_references.py": [
            "x = str(g or '').strip().lower()",
            "text = str(module or '').strip().replace(' ', '.').replace('\\n', '.')",
            "return ('global', (str(module or '').strip() + '.' + str(name or '').strip()).strip('.').lower())",
        ],
        "Virus_Scan/scanners/pickle/payload_tags.py": [
            'payload_text = str(text or "")',
            "for rec in safe_decode_payloads(payload_text, max_depth=5)[:16]:",
            "path_l = str(path or '').replace('\\\\', '/').lower()",
            "decoded_text_l = str(decoded_text or '').lower()",
        ],
        "Virus_Scan/scanners/renpy.py": [
            "log_error(f'_global_raw_renpy_header pickle scan failed for {path}: {e}')",
            "ext = str(ext or '').lower()",
            "log_error(f'scan_renpy_file input read failed for {path}: {exc}')",
            "tags.extend(['rpyc_decoded_stream_inspected', f'{enc_kind}_analyzed'])",
            "log_error(f'renpy pickle graph scan failed for {path}: {e}')",
        ],
        "Virus_Scan/scanners/payload/base64_policy.py": [
            'c = str(candidate or "").strip()',
            'c = re.sub(r"\\s+", "", str(candidate or ""))',
        ],
        "Virus_Scan/scanners/payload/chain.py": [
            'out.append((decoded, f"{encoding_hint}+{name}"))',
        ],
        "Virus_Scan/scanners/payload/decode.py": [
            "def safe_decode_payloads(strings_blob: str, max_depth: int = _PAYLOAD_POLICY.default_max_depth",
            'queue: list[tuple[str, int, str, list[str]]] = [(str(strings_blob or ""), 0, "root", [])]',
            '{"b64decode": b64decode, "urlsafe_b64decode": urlsafe_b64decode}.items()',
        ],
        "Virus_Scan/scanners/payload/evidence.py": [
            '"depth": int(depth or 0),',
            '"evidence_id": f"payload_decode_failure:{stage}",',
            'error_source=f"payload_decode.{stage}",',
            'decode_depth=int(depth or 0),',
        ],
        "Virus_Scan/scanners/payload/records.py": [
            'low = str(text or "").lower()',
            '"parent_sha256": parent if re.fullmatch(r"[0-9a-f]{64}", str(parent or "")) else "",',
            '"evidence_id": f"decoded:{key[:16]}",',
            'encoding_hint=f"{encoding_hint}@{off}"',
        ],
        "Virus_Scan/scanners/payload/tags.py": [
            'for rec in safe_decode_payloads(str(strings_blob or "")):',
            'f"decoded_{rec.get(\'binary_magic\')}_payload"',
            'f"decoded_{encoding}_payload"',
        ],
        "Virus_Scan/scanners/raw_chunk_core.py": [
            "sample = str(text or '')[: int(sample_limit or 8192)]",
            "def should_context_scan(text, *, context_anchors: Iterable[str] = DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS",
            "sample = str(text or '')",
            "def should_decode_scan(text, *, decode_anchors: Iterable[str] = DEFAULT_GLOBAL_RAW_DECODE_ANCHORS",
            "offset = max(0, int(start or 0))",
            "raise range_error_cls(f\"raw range read failed for {path} offset={start} size={size}: {exc}\") from exc",
            "if not should_context_scan_func(str(text or '').lower()):",
        ],
        "Virus_Scan/scanners/text_extraction.py": [
            "text = str(value or '')",
            "enc = getattr(getattr(sys, 'stdout', None), 'encoding', None) or 'utf-8'",
            "tree = ast.parse(str(code or ''))",
            "for val in env.values():",
            "raw = str(strings_blob or '')",
            "ext = get_scan_extension(path) if path else Path(str(path or '')).suffix.lower()",
            "for rec in safe_decode_payloads(raw, max_depth=DECODE_LAYER_MAX_DEPTH)[:16]:",
            "text = str(blob or '')",
        ],
        "Virus_Scan/scanners/pickle/trigger_evidence.py": [
            "opname = str((oprec or {}).get('opcode') or '').strip()",
            "parts.append(f'{posn}:{opname} {argtxt}' if argtxt else f'{posn}:{opname}')",
            "f\"{callable_name} via {opcode_name} stream_offset={(rc or {}).get('stream_offset')} \"",
            "raw_triggers.append(f'{str(g).strip()} referenced by pickle GLOBAL/STACK_GLOBAL')",
        ],
        "Virus_Scan/scanners/strings_intrastage.py": [
            "s = str(text or '')",
            "min_chars = int(min_chars or INTRASTAGE_MIN_TEXT_CHARS)",
            "tasks.append((f'{prefix}_context_raw'",
            "tasks.append((f'{prefix}_context_chunk_{idx:02d}'",
        ],
        "Virus_Scan/scanners/text_validation_gates.py": [
            "logger(f'library baseline hard-proof text validation failed: {text_reason}')",
            "return bool(strong_smb and (exec_ctx or 'net use' in text or 'impacket' in text))",
            "return bool((pickle_terms or plaintext_global_reduce) and exec_ctx)",
        ],
        "Virus_Scan/scanners/pickle/literals.py": [
            "str(stage or 'pickle') + '_error'",
            "error_source='pickle.' + str(stage or 'unknown')",
            "'encoding': str(encoding or 'pickle_failure')",
            "return ('text', str(arg or ''))",
            "compact = re.sub('\\\\s+', '', str(cand or ''))",
            "for rec in safe_decode_payloads(compact, max_depth=2):",
            "frags = [str(x or '') for x in (analysis or {}).get('literal_fragments', []) if str(x or '').strip()]",
        ],
        "Virus_Scan/scanners/text_api_sequence.py": [
            "base_tags = ['text_api_extract_failed', f'{stage}_scan_error']",
            "error_source=f'text.{stage}'",
            "missing_reason=f'missing_{stage}_text'",
            "logger(f'API extract failed: {e}')",
        ],
    }
    for file_name, snippets in checks.items():
        source = Path(file_name).read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source, file_name + ": " + snippet
