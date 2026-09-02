from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from pathlib import Path
from Virus_Scan.runtime.api import log_error
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.reporting.evidence_line_text import safe_report_text
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.core.jsonio import atomic_json_save
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

PLR2004N0_75 = 0.75
PLR2004N126 = 126
PLR2004N32 = 32

# Explicit reporting constants previously supplied by hidden shared-state hydration.
QUALITY_GATE_VERSION = 'explainability_quality_gates_v1'

def _cli_file_kind(path: object, result: object=None) -> object:
    """Compact display kind for scan output."""
    ext = get_scan_extension(path)
    stage = ''
    try:
        stage = safe_report_text((result or {}).get('effective_stage'), limit=80).lower() if type(result) is dict else ''
    except TELEMETRY_FAILURE_ERRORS:
        stage = ''
    if stage == 'binary' or ext in {'.exe', '.dll', '.sys', '.ocx', '.so', '.dylib'}:
        return 'BINARY'
    if stage == 'runtime' or ext in {'.py', '.pyc', '.rpy', '.rpyc', '.rpyb', '.js', '.rb', '.sh', '.bat', '.ps1'}:
        return 'SCRIPT'
    if ext in {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp', '.svg', '.ogg', '.mp3', '.wav', '.ttf', '.otf'}:
        return 'ASSET'
    return 'FILE'

def _decode_printable_ratio(data: object) -> object:
    try:
        if type(data) not in (bytes, bytearray):
            return 0.0
        sample = bytes(data[:4096])
        if len(sample) == 0:
            return 0.0
        printable = 0
        for b in sample:
            if b in (9, 10, 13) or PLR2004N32 <= b <= PLR2004N126:
                printable += 1
        return printable / max(1, len(sample))
    except TELEMETRY_FAILURE_ERRORS as exc:
        try:
            record_suppressed_failure('reporting_output_printable_ratio_failed', exc, domain='reporting')
        except TELEMETRY_FAILURE_ERRORS as record_exc:
            _ = record_exc
        return 0.0

def _decoded_payload_interesting(text: object, raw_bytes: object=b'') -> object:
    try:
        low = safe_report_text(text).lower()
        if raw_bytes.startswith((b'MZ', b'\x7fELF')) or raw_bytes[:4] in (b'PK\x03\x04', b'Rar!'):
            return True
        anchors = ('powershell', 'pwsh', 'encodedcommand', '-enc', 'cmd.exe', 'schtasks', 'certutil', 'bitsadmin', 'mshta', 'rundll32', 'regsvr32', 'wmic', 'invoke-webrequest', 'downloadstring', 'downloadfile', 'frombase64string', 'virtualalloc', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'mimikatz', 'sekurlsa', 'lsass', 'cryptunprotectdata', 'runonce', 'currentversion\\run', 'http://', 'https://', 'subprocess', 'os.system', 'eval(', 'exec(')
        if any((a in low for a in anchors)):
            return True
        if _decode_printable_ratio(raw_bytes) >= PLR2004N0_75 and any((x in low[:2048] for x in ('import ', 'function ', 'var ', 'const ', 'class ', 'label ', 'define ', 'return'))):
            return True
    except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return False

def _queue_file_results_dir(queue_dir: object) -> object:
    """Per-file durable result records used as the completion authority.

    Worker aggregate output JSON is non-authoritative. A
    file job may not be moved to done/ until its own result record exists and can
    be read back. This prevents done/ from meaning only "worker reached finally".
    """
    d = Path(queue_dir) / 'file_results'
    try:
        d.mkdir(parents=True, exist_ok=True)
    except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc
    return d

def _safe_cli_print(value: object='') -> None:
    """Print without allowing raw forensic bytes to raise UnicodeEncodeError."""
    text = safe_report_text(value)
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            print(text.encode('ascii', errors='backslashreplace').decode('ascii', errors='replace'))
        except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('reporting_output_cli_print_encoding_failed', _umige_suppressed_exc, domain='reporting')
            except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    except TELEMETRY_FAILURE_ERRORS:
        try:
            print()
        except TELEMETRY_FAILURE_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except TELEMETRY_FAILURE_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc


def build_score_breakdown(raw_weighted_score: object=None, calibrated_score: object=None, post_context_score: object=None, final_score: object=None, caps: object=None, high_gate: object=None, contextual_expected: object=None, renpy_cap: object=None) -> object:
    """Compact score audit trail for reports; scoring behavior is unchanged."""
    return {'version': QUALITY_GATE_VERSION, 'raw_weighted_score': raw_weighted_score, 'calibrated_score': calibrated_score, 'post_context_amplifier_score': post_context_score, 'final_score': final_score, 'caps': caps or [], 'contextual_expected_behavior': contextual_expected or {}, 'anchor_chain_high_gate': high_gate or {}, 'renpy_failsafe_cap': renpy_cap}

def clear_scan_results_before_scan(output_path: object, *, preserve: object=False) -> None:
    """Clear authoritative and recovery scan-result files at scan start.

    The final JSON and its sibling partial checkpoint describe the same scan
    run.  Clearing only the final JSON leaves a stale larger ``.partial`` file
    eligible for recovery at report time, which can republish records from an
    earlier scan.
    """
    if preserve:
        return
    try:
        output_text = safe_report_text(output_path)
        if output_text:
            atomic_json_save(output_text, {}, backups=0)
            partial_path = str.__add__(str(Path(output_text).resolve()), ".partial")
            partial_checkpoint_path = str.__add__(str(Path(output_text).resolve()), ".partial.checkpoint.json")
            Path(partial_path).unlink(missing_ok=True)
            Path(partial_checkpoint_path).unlink(missing_ok=True)
    except TELEMETRY_FAILURE_ERRORS as e:
        log_error(str.__add__('initial scan results clear failed: ', no_hook_type_name(e)))
