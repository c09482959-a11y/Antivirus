"""Phase 2 scanner suppressed-failure classification audit.

This module is a scanner-owned CI gate.  It does not decide from filenames: it
parses the actual Python source under ``Virus_Scan/scanners`` and requires every
``record_suppressed_failure()`` call site to be classified by module/function.
The manifest is intentionally explicit so new suppressed scanner failures cannot
enter without a remediation classification and an evidence/outcome decision.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SuppressedFailureSite:
    module: str
    function: str
    expected_calls: int
    classification: str
    outcome: str
    evidence_path: str
    decision: str

    def key(self) -> tuple[str, str]:
        return (self.module, self.function)

    def to_record(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SuppressedFailureCall:
    module: str
    function: str
    line: int
    label: str
    domain: str

    def key(self) -> tuple[str, str]:
        return (self.module, self.function)

    def to_record(self) -> dict[str, object]:
        return asdict(self)


CLASSIFIED_SUPPRESSED_FAILURE_SITES: tuple[SuppressedFailureSite, ...] = (
    SuppressedFailureSite('Virus_Scan/scanners/image_lsb.py', 'extract_lsb_payload_gated', 1, 'recoverable telemetry/logging failure', 'structured runtime failure record', 'log failure is recorded after the scan path already degraded; decode errors return scanner_failure_evidence tags', 'safe telemetry degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/image_scan.py', '_fast_path_image_scan', 1, 'recoverable telemetry/evidence-publication branch failure', 'structured telemetry failure record', 'sample evidence publication failure is recorded and tags are still returned', 'safe telemetry degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/text_evidence.py', '_pickle_bytes_to_text_views', 2, 'expected malformed input', 'structured runtime failure record', 'decode failures are bounded and recorded; no pickle opcode execution occurs', 'safe malformed decode branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/rpyc_rpa_flow.py', 'iter_optional_rpa_views', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'RPA/RPYC member view failures are recorded; later RenPy container views continue', 'safe recoverable member-view branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/global_references.py', '_pickle_is_dangerous_callable_global', 1, 'expected malformed input', 'structured runtime failure record', 'callable-global normalization failure is recorded and returns non-dangerous only for malformed input', 'safe malformed global-name branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/opcode_history.py', 'record_opcode_history', 1, 'expected malformed input', 'structured runtime failure record', 'opcode history preview failures are recorded while opcode walk continues', 'safe malformed opcode-history branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/opcode_memo.py', 'memoize_stack_value', 1, 'expected malformed input', 'structured runtime failure record', 'pickle memo conversion failures are recorded while opcode walk continues', 'safe malformed memo branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/opcode_reduce.py', 'append_reduce_chain', 1, 'expected malformed input', 'structured runtime failure record', 'trigger-window append failures are recorded while reduce-chain evidence remains', 'safe malformed reduce evidence branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/opcode_summary.py', 'dedupe_summary_lists', 1, 'expected malformed input', 'structured runtime failure record', 'summary dedupe failures are recorded while existing analysis fields remain', 'safe malformed summary-dedupe branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/opcode_summary.py', 'dedupe_literal_fragments', 1, 'expected malformed input', 'structured runtime failure record', 'literal-fragment dedupe failures are recorded while existing literal evidence remains', 'safe malformed literal-dedupe branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/graph_base.py', '_safe_scan_extension', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'extension lookup failure is recorded; existing tags are preserved', 'safe tag-unification degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/trigger_evidence.py', 'record_trigger_windows', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'trigger-window formatting failures are recorded while base opcode evidence remains', 'safe trigger-window evidence degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/trigger_evidence.py', 'pickle_trigger_summaries', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'trigger-summary failures are recorded while base opcode evidence remains', 'safe trigger-summary evidence degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/fragment_tags.py', '_record_fragment_failure', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'fragment contextual/payload enrichment failures are recorded while base fragment evidence continues', 'safe fragment enrichment degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/source_detection.py', 'renpy_source_pickle_injection_tags', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'source-pattern scan failure is recorded and ordered tags accumulated before failure are preserved', 'safe RenPy source enrichment degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/escalation_base64.py', '_pickle_fast_base64_status', 1, 'expected malformed input', 'structured runtime failure record', 'malformed base64 status probe is recorded; caller emits malformed-base64 evidence tags', 'safe malformed base64 branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/escalation_base64.py', '_pickle_fast_base64_protocol_hint', 1, 'expected malformed input', 'structured runtime failure record', 'malformed base64 protocol probe is recorded; caller emits malformed-base64 evidence tags', 'safe malformed base64 branch'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/escalation_rpyc.py', '_pickle_fast_rpyc_view_hints', 1, 'recoverable scanner branch failure', 'structured runtime failure record', 'RPYC nested view scan failure is recorded while fast path continues to explicit deep-scan tags when other evidence exists', 'safe RPYC view degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/pickle/escalation_io.py', '_pickle_fast_prefilter_error', 1, 'recoverable scanner branch failure', 'explicit degraded pickle tags plus structured runtime failure record', 'top-level fast prefilter failure emits scanner failure evidence and forces full analysis instead of clean fast pass', 'safe pickle fast-path degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/renpy.py', '_global_raw_renpy_header', 1, 'expected malformed input', 'structured runtime failure record', 'bounded header read failure is recorded and returns non-executable empty header metadata', 'safe malformed/read-failure branch'),
    SuppressedFailureSite('Virus_Scan/scanners/strings_ast.py', '_record_string_ast_failure', 1, 'expected malformed input', 'structured runtime failure record', 'AST literal-folding failures are recorded while raw/context decoding still runs', 'safe AST enrichment degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/strings.py', 'scan_strings', 1, 'recoverable scanner branch failure', 'converted to explicit degraded scanner tags', 'returned tags include string_scan_error and scanner_degraded tags', 'safe degraded scanner result'),
    SuppressedFailureSite('Virus_Scan/scanners/strings_intrastage.py', '_intrastage_contextual_chunk_raw', 1, 'recoverable scanner branch failure', 'converted to explicit degraded scanner tags', 'returned tags include string_context_chunk_error and scanner_degraded tags', 'safe degraded chunk result'),
    SuppressedFailureSite('Virus_Scan/scanners/strings_intrastage.py', '_intrastage_decoded_chunk_raw', 1, 'recoverable scanner branch failure', 'converted to explicit degraded scanner tags', 'returned tags include string_decode_chunk_error and scanner_degraded tags', 'safe degraded chunk result'),
    SuppressedFailureSite('Virus_Scan/scanners/text_raw_chunks.py', '_global_raw_read_range_text_result', 1, 'recoverable scanner branch failure', 'converted to explicit scanner failure evidence', 'returned mapping carries failure_tags and failure_evidence', 'safe degraded raw-read result'),
    SuppressedFailureSite('Virus_Scan/scanners/text_raw_chunks.py', '_global_raw_should_context_scan', 1, 'recoverable scanner branch failure', 'structured scanner failure record through policy callback', 'raw chunk policy failure is recorded and boolean caller remains Phase 3 monitored', 'classified but still monitored by failure-state hardening'),
    SuppressedFailureSite('Virus_Scan/scanners/text_raw_chunks.py', '_global_raw_pe_api_header', 1, 'expected malformed input', 'structured runtime failure record', 'bounded PE header probe failure is recorded; result remains metadata-only', 'safe malformed/read-failure branch'),
    SuppressedFailureSite('Virus_Scan/scanners/text_raw_chunks.py', '_global_raw_renpy_chunk', 1, 'recoverable scanner branch failure', 'structured runtime failure record plus accumulated tags', 'RenPy injection helper failures are recorded while raw chunk tags continue', 'safe RenPy chunk enrichment degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/text_raw_chunks.py', '_global_raw_rpgm_js_ast_chunk', 1, 'expected malformed input', 'structured runtime failure record', 'regex probe failure is recorded while remaining RPGM JS checks continue', 'safe malformed regex branch'),
    SuppressedFailureSite('Virus_Scan/scanners/text_raw_chunks.py', '_intrastage_contextual_chunk_raw', 1, 'recoverable scanner branch failure', 'converted to explicit scanner failure evidence tags', 'returned tags include intrastage_contextual_chunk_error and scanner_failure_evidence_recorded', 'safe degraded chunk result'),
    SuppressedFailureSite('Virus_Scan/scanners/text_extraction.py', '_umige_ast_enriched_strings', 3, 'expected malformed input', 'structured runtime failure record', 'AST literal-folding failures are recorded while raw text remains available', 'safe AST enrichment degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/text_extraction.py', '_umige_build_extraction_view', 2, 'recoverable scanner branch failure', 'structured runtime failure record', 'AST/decode expansion failures are recorded while raw and normalized views remain available', 'safe extraction-view degradation'),
    SuppressedFailureSite('Virus_Scan/scanners/text_extraction.py', '_umige_normalize_obfuscated_text', 2, 'expected malformed input', 'structured runtime failure record', 'normalization regex failures are recorded while lower-cased degraded view remains available', 'safe normalization degradation'),
)


class _SuppressedFailureVisitor(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.stack: list[str] = []
        self.calls: list[SuppressedFailureCall] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ''
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name == 'record_suppressed_failure':
            label = ast.unparse(node.args[0]) if node.args else ''
            domain = ''
            for keyword in node.keywords:
                if keyword.arg == 'domain':
                    domain = ast.unparse(keyword.value)
            self.calls.append(SuppressedFailureCall(self.module, '.'.join(self.stack) or '<module>', int(node.lineno), label, domain))
        self.generic_visit(node)


def iter_suppressed_failure_calls(root: Path | str = '.') -> tuple[SuppressedFailureCall, ...]:
    base = Path(root)
    calls: list[SuppressedFailureCall] = []
    for path in sorted((base / 'Virus_Scan' / 'scanners').rglob('*.py')):
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
        module = path.relative_to(base).as_posix()
        visitor = _SuppressedFailureVisitor(module)
        visitor.visit(tree)
        calls.extend(visitor.calls)
    return tuple(calls)


def classified_suppressed_failure_manifest() -> tuple[SuppressedFailureSite, ...]:
    return CLASSIFIED_SUPPRESSED_FAILURE_SITES


def validate_suppressed_failure_manifest(root: Path | str = '.') -> dict[str, object]:
    calls = iter_suppressed_failure_calls(root)
    manifest = {site.key(): site for site in CLASSIFIED_SUPPRESSED_FAILURE_SITES}
    observed: dict[tuple[str, str], list[SuppressedFailureCall]] = {}
    for call in calls:
        observed.setdefault(call.key(), []).append(call)
    unclassified = [call.to_record() for call in calls if call.key() not in manifest]
    stale_manifest = [site.to_record() for site in CLASSIFIED_SUPPRESSED_FAILURE_SITES if site.key() not in observed]
    count_mismatches = []
    for key, site in dict.items(manifest):
        found = len(observed.get(key, ()))
        if found != site.expected_calls:
            count_mismatches.append({
                'module': site.module,
                'function': site.function,
                'expected_calls': site.expected_calls,
                'found_calls': found,
                'classification': site.classification,
            })
    unsafe_classifications = [
        site.to_record()
        for site in CLASSIFIED_SUPPRESSED_FAILURE_SITES
        if not site.classification or not site.outcome or not site.evidence_path or not site.decision
    ]
    return {
        'total_calls': len(calls),
        'classified_sites': len(CLASSIFIED_SUPPRESSED_FAILURE_SITES),
        'unclassified': unclassified,
        'stale_manifest': stale_manifest,
        'count_mismatches': count_mismatches,
        'unsafe_classifications': unsafe_classifications,
        'calls': [call.to_record() for call in calls],
        'manifest': [site.to_record() for site in CLASSIFIED_SUPPRESSED_FAILURE_SITES],
    }


__all__ = (
    'CLASSIFIED_SUPPRESSED_FAILURE_SITES',
    'SuppressedFailureCall',
    'SuppressedFailureSite',
    'classified_suppressed_failure_manifest',
    'iter_suppressed_failure_calls',
    'validate_suppressed_failure_manifest',
)
