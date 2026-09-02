from pathlib import Path, PurePosixPath

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.cli.exit_codes import score_from_result
from Virus_Scan.contracts.retained_scan_result import (
    retained_publication_record,
    retained_result_marker_present,
)
from Virus_Scan.reporting.risk_label import risk_label_from_score
from Virus_Scan.reporting.evidence_lines import cli_human_evidence_lines
from Virus_Scan.reporting.evidence_line_text import (
    safe_report_float,
    safe_report_mapping_get,
    safe_report_mapping_items,
    safe_report_path_text,
    safe_report_sequence,
    safe_report_text,
)


PLR2004N25_0 = 25.0


def _cli_file_kind(path: object) -> object:
    text = safe_report_path_text(path)
    ext = PurePosixPath(str.lower(text)).suffix
    if ext in {'.exe', '.dll', '.sys', '.ocx', '.so', '.dylib'}:
        return 'BINARY'
    if ext in {'.py', '.pyc', '.rpy', '.rpyc', '.rpyb', '.js', '.rb', '.sh', '.bat', '.ps1'}:
        return 'SCRIPT'
    if ext in {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp', '.svg', '.ogg', '.mp3', '.wav', '.ttf', '.otf'}:
        return 'ASSET'
    return 'FILE'


def _safe_cli_print(value: object='') -> None:
    text = safe_report_text(value)
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            print(text.encode('ascii', errors='backslashreplace').decode('ascii', errors='replace'))
        except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('reporting_cli_print_encoding_failed', _umige_suppressed_exc, domain='reporting')
            except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('reporting_cli_print_failed', _umige_suppressed_exc, domain='reporting')
        except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc


def _safe_basename(path: object) -> object:
    text = safe_report_path_text(path)
    if not text:
        return '<unavailable>'
    return Path(text).name


def _result_items(results: object) -> object:
    return safe_report_mapping_items(results, max_items=100000)


def print_compact_scan_report(results: object, target: object, output_path: object=None, *, yara_active: object=False, yara_rule_count: object=None, elapsed_sec: object=None) -> None:
    """Requested compact CLI report. Does not alter JSON or detection logic."""
    _safe_cli_print(str.__add__('[INFO] Scanning Target: ', safe_report_text(target) or '<unavailable>'))
    yara_state = 'true' if type(yara_active) is bool and yara_active else 'false'
    _safe_cli_print(str.__add__('[INFO] YARA active: ', yara_state))
    if yara_rule_count is None:
        _safe_cli_print('[INFO] YARA Rules Loaded: unknown')
    else:
        _safe_cli_print(str.__add__('[INFO] YARA Rules Loaded: ', safe_report_text(yara_rule_count) or 'unknown'))
    _safe_cli_print('')
    max_score = 0.0
    displayed = 0
    hidden_low = 0
    suppressed_medium = 0
    cli_cap = int_env('UMIGE_CLI_MAX_MEDIUM_DISPLAY', 500, 0, None)
    items = _result_items(results)
    for path, result in items:
        public_result = (
            retained_publication_record(result)
            if retained_result_marker_present(result)
            else result
        )
        score = score_from_result(public_result)
        max_score = max(max_score, score)
        risk = risk_label_from_score(score)
        if risk == 'LOW':
            hidden_low += 1
            continue
        displayed += 1
        if cli_cap >= 0 and displayed > cli_cap:
            suppressed_medium += 1
            continue
        name = _safe_basename(path)
        kind = _cli_file_kind(path)
        _safe_cli_print('[' + kind + '] ' + name)
        display_tags = display_tags_for_result(public_result, score)
        if display_tags:
            _safe_cli_print(str.__add__('Suspicious Tags: ', ', '.join(display_tags)))
        for ev_line in cli_human_evidence_lines(path, public_result):
            _safe_cli_print(ev_line)
        yara_hits = tuple(text for text in (safe_report_text(item, limit=120) for item in safe_report_sequence(safe_report_mapping_get(public_result, 'yara_hits'), max_items=5)) if text)
        if yara_hits:
            _safe_cli_print(str.__add__('YARA: ', ', '.join(yara_hits)))
        _safe_cli_print(''.join(('Score: ', format(safe_report_float(score, default=0.0), '.0f'), ' | ', risk, '\n')))
    _safe_cli_print('=== FINAL RESULT ===')
    _safe_cli_print(str.__add__('Files: ', int.__str__(len(items))))
    shown_medium = displayed - suppressed_medium
    _safe_cli_print(''.join(('CLI Shown: ', int.__str__(shown_medium), ' MEDIUM+')))
    if suppressed_medium:
        _safe_cli_print(str.__add__('CLI Suppressed MEDIUM+ Detail: ', int.__str__(suppressed_medium)))
    _safe_cli_print(str.__add__('CLI Hidden Low: ', int.__str__(hidden_low)))
    _safe_cli_print(str.__add__('Risk: ', risk_label_from_score(max_score)))
    elapsed = safe_report_float(elapsed_sec, default=-1.0)
    if elapsed < 0.0:
        _safe_cli_print('Scan Time: unknown')
    else:
        _safe_cli_print(str.__add__('Scan Time: ', str.__add__(format(elapsed, '.2f'), 's')))
    output_text = safe_report_path_text(output_path)
    if output_text:
        _safe_cli_print(str.__add__('Output: ', str(Path(output_text).resolve())))


def display_tags_for_result(result: object, score: object) -> object:
    """Only display suspicious tags at MEDIUM or higher; keep JSON unchanged."""
    if safe_report_float(score, default=0.0) < PLR2004N25_0:
        return []
    noisy_exact = {'file_seen', 'extension_consistent', 'magic_text', 'filetype_text', 'filetype_runtime', 'script_file', 'magic_type_script_text', 'observed_stage_runtime', 'router_stage_runtime', 'ext_stage_runtime', 'ext_stage_binary', 'filetype_binary', 'magic_pe', 'magic_type_pe_mz', 'pe_file', 'pe_exe', 'native_pe', 'executable_file', 'medium_entropy'}
    noisy_prefixes = ('ext_',)
    out = []
    for t in safe_report_sequence(safe_report_mapping_get(result, 'tags'), max_items=512):
        st = safe_report_text(t, limit=120)
        if not st:
            continue
        if st in noisy_exact or any((st.startswith(p) for p in noisy_prefixes)):
            continue
        out.append(st)
    return sorted(set(out))[:24]

__all__ = ('cli_human_evidence_lines', 'display_tags_for_result', 'print_compact_scan_report')
