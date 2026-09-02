"""Scanner-owned text validation gates and high-risk tag proof checks."""

from dataclasses import dataclass
from pathlib import Path
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text
from Virus_Scan.scanners.text_behavior import _is_renpy_bytecode_path, _scanner_path_text
from Virus_Scan.scanners.text_extraction import _tag_validation_text
from Virus_Scan.scanners.text_policy import (
    BROAD_UNVALIDATED_TAGS,
    CORRELATION_GROUP_KEYWORDS,
    _LIBRARY_BASELINE_HARD_PROOF_TAGS,
    _RUNTIME_STRONG_ATTACK_CONTEXT,
)
from Virus_Scan.utils.text_match import has_any_text as _has_any_text




def _scanner_exact_text(value: object, *, missing_reason: object = 'missing_scanner_text', unsupported_reason: object = 'unsafe_scanner_text_rejected') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    return (text, reason)


def _scanner_lower_token(value: object, *, missing_reason: object = 'missing_scanner_token', unsupported_reason: object = 'unsafe_scanner_token_rejected') -> object:
    text, reason = _scanner_exact_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return ('', reason)
    return (text.strip().lower(), '')


def _scanner_tagset(tags: object = None) -> object:
    if tags is None:
        return (frozenset(), '')
    if type(tags) is str:
        token, reason = _scanner_lower_token(tags, unsupported_reason='unsafe_scanner_tag_rejected')
        return (frozenset((token,)) if token else frozenset(), reason)
    if type(tags) not in (tuple, list, set, frozenset):
        return (frozenset(), 'unsafe_scanner_tags_rejected')
    out = set()
    first_reason = ''
    for item in tags:
        token, reason = _scanner_lower_token(item, unsupported_reason='unsafe_scanner_tag_rejected')
        if reason and not first_reason:
            first_reason = reason
        if token:
            out.add(token)
    return (frozenset(out), first_reason)


def _scanner_validation_text(validation_text: object, strings_blob: object) -> object:
    try:
        raw_text = validation_text(strings_blob)
    except SCAN_CONTENT_ERRORS:
        return ('', 'probe_error')
    text, reason = _scanner_exact_text(
        raw_text,
        missing_reason='missing_scanner_validation_text',
        unsupported_reason='unsafe_scanner_validation_text_rejected',
    )
    if reason:
        return ('', reason)
    return (text.lower(), '')


def _scanner_score(score: object) -> object:
    if score is None:
        return (0.0, '')
    return no_hook_finite_float(
        score,
        default=100.0,
        minimum=0.0,
        reason='unsafe_scanner_score_rejected',
        non_finite_reason='non_finite_scanner_score_rejected',
        allow_exact_text=True,
    )


def _scanner_path_suffix(path: object) -> object:
    if path is None:
        return ('', '')
    path_text, reason = _scanner_path_text(path)
    if reason:
        return ('', reason)
    try:
        return (Path(path_text).suffix.lower(), '')
    except SCAN_CONTENT_ERRORS:
        return ('', 'scanner_path_suffix_failed')

def infer_correlation_group(signal: object, tags: object = None) -> object:
    """Return a stable correlation group for related evidence.

    This prevents base64/decoded-string/encoded-PowerShell style indicators
    from being fused as independent proof.  It is metadata-only unless a caller
    explicitly uses the group summary.
    """
    signal_text, signal_reason = _scanner_exact_text(
        signal,
        missing_reason='missing_scanner_signal',
        unsupported_reason='unsafe_scanner_signal_rejected',
    )
    tagset, tag_reason = _scanner_tagset(tags)
    joined = (signal_text + ' ' + ' '.join(sorted(tagset))).lower()
    if ((signal_reason and not signal_text) or tag_reason) and not joined.strip():
        return 'scanner_validation_input_rejected'
    for group, keys in CORRELATION_GROUP_KEYWORDS:
        if any((k in joined for k in keys)):
            return group
    return 'generic_behavior'


def library_baseline_hard_proof_status(tags: object = None, strings_blob: object = '', *, validation_text: object = _tag_validation_text, logger: object = log_error) -> object:
    """Return explicit hard-proof gate status for library-baseline learning."""
    tagset, tag_reason = _scanner_tagset(tags)
    if tag_reason:
        return ('tag_input_rejected', False)
    if tagset & _LIBRARY_BASELINE_HARD_PROOF_TAGS:
        return ('tag_hard_proof', True)
    text, text_reason = _scanner_validation_text(validation_text, strings_blob)
    if text_reason:
        try:
            logger('library baseline hard-proof text validation failed: ' + text_reason)
        except SCAN_CONTENT_ERRORS as log_exc:
            _ = log_exc
        return ('probe_error', True)
    has_hard_proof = bool(_has_any_text(text, _RUNTIME_STRONG_ATTACK_CONTEXT))
    return ('text_hard_proof' if has_hard_proof else 'no_hard_proof', has_hard_proof)


def library_baseline_has_hard_proof(tags: object = None, strings_blob: object = '', *, validation_text: object = _tag_validation_text, logger: object = log_error) -> object:
    _status, has_hard_proof = library_baseline_hard_proof_status(tags, strings_blob, validation_text=validation_text, logger=logger)
    return bool(has_hard_proof)


def reference_url_only_score_cap(score: object, tags: object = None, path: object = None, strings_blob: object = '') -> object:
    """Cap source files where the only network signal is a reference/comment URL."""
    score, score_reason = _scanner_score(score)
    evidence = [score_reason] if score_reason else []
    should_evaluate_reference = True
    text = ''
    if should_evaluate_reference:
        text, text_reason = _scanner_validation_text(_tag_validation_text, strings_blob)
        if text_reason:
            evidence.append(text_reason)
            should_evaluate_reference = False

    suffix = ''
    if should_evaluate_reference:
        suffix, suffix_reason = _scanner_path_suffix(path)
        if suffix_reason:
            evidence.append(suffix_reason)
            should_evaluate_reference = False
        elif suffix not in {'.rpy', '.py', '.rpym', '.txt'}:
            should_evaluate_reference = False

    tagset = frozenset()
    if should_evaluate_reference:
        tagset, tag_reason = _scanner_tagset(tags)
        if tag_reason:
            evidence.append(tag_reason)
            should_evaluate_reference = False
        elif not {'reference_url', 'url_present', 'reference_url_behavior_suppressed'} & tagset:
            should_evaluate_reference = False

    if should_evaluate_reference:
        hard = tagset & {
            'remote_payload_download', 'network_download', 'c2_beacon', 'network_c2',
            'backdoor_or_c2', 'remote_command_channel', 'process_exec', 'cmd_exec',
            'powershell_exec', 'encoded_powershell', 'amsi_scanbuffer_patch',
            'etw_eventwrite_patch', 'defender_disable', 'credential_dump_attempt',
            'lsass_access', 'token_exfiltration', 'http_upload', 'archive_dropper',
            'dropper_behavior', 'pickle_dangerous_global', 'pickle_reduce_opcode',
        }
        runtime_net = _has_any_text(text, [
            'requests.get', 'requests.post', 'urllib.request', 'urlopen(',
            'urlretrieve(', 'downloadfile', 'downloadstring', 'fetch(',
            'xmlhttprequest', 'xhr.open', 'socket.', '.connect(', 'subprocess',
            'os.system', 'popen(', 'createprocess',
        ])
        if not hard and ('reference_url_behavior_suppressed' in tagset or not runtime_net):
            score = min(score, 18.0)
            evidence.append('reference_url_only_cap')
    return (score, evidence)


@dataclass(frozen=True, slots=True)
class _HighRiskValidationContext:
    tag: str
    text: str
    is_rpyc: bool
    exec_ctx: bool
    net_ctx: bool
    compact: str


def _validate_lateral_movement_tag(context: _HighRiskValidationContext) -> bool | None:
    tag = context.tag
    text = context.text
    compact = context.compact
    if tag in {'wmi_exec', 'win32_process_create'}:
        strong_wmi = _has_any_text(text, [
            'wmic process call create', 'win32_process.create', 'invoke-wmimethod',
            'get-wmiobject', 'invoke-cimmethod', 'wmic.exe',
        ]) or (
            ('wmic' in compact and 'process' in compact and 'call' in compact and 'create' in compact)
            or ('win32_process' in compact and 'create' in compact)
        )
        return strong_wmi and context.exec_ctx
    if tag in {'admin_share_access', 'smb_activity', 'impacket_exec'}:
        strong_smb = _has_any_text(text, [
            r'\\admin$', r'\\ipc$', r'\\c$', 'net use', 'smbexec',
            'wmiexec', 'psexec.py', 'impacket', 'tree_connect',
        ])
        return strong_smb and (context.exec_ctx or 'net use' in text or 'impacket' in text)
    if tag in {'remote_service_creation', 'remote_scheduled_task', 'remote_registry'}:
        return context.exec_ctx and _has_any_text(text, [
            'createservice', 'openscmanager', 'svcctl', 'sc create', 'schtasks /s',
            'reg connect', 'remote registry',
        ])
    return None


def _validate_credential_and_execution_tag(context: _HighRiskValidationContext) -> bool | None:
    tag = context.tag
    text = context.text
    if tag in {'credential_dump_attempt', 'lsass_access', 'memory_dump', 'credential_api_access'}:
        return bool(_has_any_text(text, [
            'mimikatz', 'sekurlsa', 'lsass', 'minidumpwritedump', 'comsvcs.dll',
            'procdump', 'nanodump', 'credread', 'credenumerate', 'cryptunprotectdata',
        ]))
    if tag == 'token_secret_access':
        strong_token = _has_any_text(text, [
            'refresh_token', 'access_token', 'aws_access_key_id', 'secret_access_key',
        ])
        return strong_token and (context.net_ctx or not context.is_rpyc)
    if tag in {'powershell_exec', 'cmd_exec', 'process_exec', 'fileless_execution'}:
        return context.exec_ctx
    return None


def _validate_bypass_and_injection_tag(context: _HighRiskValidationContext) -> bool | None:
    tag = context.tag
    text = context.text
    if tag in {'amsi_bypass_attempt', 'etw_bypass_attempt', 'amsi_scanbuffer_patch', 'etw_eventwrite_patch'}:
        patch_terms = _has_any_text(text, [
            'virtualprotect', 'writeprocessmemory', 'memcpy', 'patch', '0x31', '0xc3',
        ])
        if tag in {'amsi_bypass_attempt', 'amsi_scanbuffer_patch'}:
            amsi_terms = _has_any_text(text, [
                'amsiscanbuffer', 'amsi.dll', 'amsiinitfailed', 'amsiutils',
                'patch amsi', 'disable amsi', 'bypass amsi', 'amsi bypass',
            ])
            return amsi_terms and (patch_terms or context.exec_ctx)
        etw_terms = _has_any_text(text, [
            'etweventwrite', 'nttraceevent', 'eventwrite', 'patch etw',
            'disable etw', 'bypass etw', 'etw bypass', 'etw patch',
        ])
        return etw_terms and (patch_terms or context.exec_ctx)
    if tag in {'process_injection', 'memory_write', 'memory_protect', 'thread_execution'}:
        return _has_any_text(text, [
            'writeprocessmemory', 'virtualprotect', 'virtualallocex',
            'createremotethread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext',
        ])
    return None


def _validate_network_and_archive_tag(context: _HighRiskValidationContext) -> bool | None:
    tag = context.tag
    text = context.text
    if tag in {'network_c2', 'backdoor_or_c2', 'remote_command_channel', 'c2_beacon', 'c2_or_remote_command'}:
        c2_terms = _has_any_text(text, [
            'command and control', 'c2', 'beacon', 'checkin', 'check-in',
            'sleep jitter', '/api/checkin', '/gate.php', '/panel/', 'reverse shell',
            'getcommand', 'tasking', 'implant', 'heartbeat', 'poll', 'cmd=', 'post /api',
        ])
        socket_terms = ('recv(' in text or 'send(' in text) and _has_any_text(
            text, ['command', 'cmd', 'task', 'shell', 'beacon', 'implant']
        )
        return context.net_ctx and (c2_terms or socket_terms) and context.exec_ctx
    if tag in {'archive_dropper', 'embedded_archive_payload', 'dropper_behavior'}:
        archive_ctx = _has_any_text(text, [
            'zipfile', 'extractall', '7z.exe', 'rar.exe', 'tarfile', 'cabinet',
            'expand.exe', 'gzipstream', 'deflatestream', 'pk\x03\x04',
        ])
        payload_ctx = _has_any_text(text, [
            '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr',
            '.msi', 'writeallbytes', 'createfile', '%temp%', 'appdata', 'startup',
            'currentversion\run',
        ])
        write_or_extract_ctx = _has_any_text(text, [
            'extractall', 'extract(', 'writeallbytes', 'createfile', 'open(',
            'copyfile', 'movefile', 'safe_extract', 'unpack', 'decompress',
        ])
        persistence_ctx = context.exec_ctx or _has_any_text(
            text, ['startup', 'currentversion\run', 'schtasks', 'service create']
        )
        return archive_ctx and payload_ctx and write_or_extract_ctx and persistence_ctx
    return None


def _validate_pickle_and_persistence_tag(context: _HighRiskValidationContext) -> bool | None:
    tag = context.tag
    text = context.text
    compact = context.compact
    if tag in {'pickle_dangerous_global', 'pickle_callable_reference', 'pickle_reduce_opcode', 'pickle_external_executable_reference'}:
        pickle_terms = _has_any_text(text, [
            'pickle.loads', 'pickle.load(', 'pickletools', 'pickletools.dis',
            '__reduce__', '__reduce_ex__', 'stack_global', 'opcode: global',
            'opcode: reduce', 'global opcode', 'reduce opcode', 'cos\nsystem',
            'cposix\nsystem', 'cnt\nsystem', 'posix\nsystem', 'nt\nsystem',
            'builtins\neval', 'builtins\nexec',
        ])
        plaintext_global_reduce = all(term in text for term in ('pickle', 'global', 'reduce')) and _has_any_text(
            text, ['cmd.exe', 'powershell', 'os system', 'os.system', 'subprocess', 'popen']
        )
        return (pickle_terms or plaintext_global_reduce) and context.exec_ctx
    if tag in {'schtasks_create', 'scheduled_task', 'scheduled_execution'}:
        strong_task = 'schtasks' in compact and ('/create' in compact or ' /tn ' in compact or ' /tr ' in compact)
        return strong_task and context.exec_ctx
    if tag == 'shadowcopy_delete':
        strong_shadow = ('shadowcopy' in compact and 'delete' in compact) or 'vssadmin delete shadows' in text
        return strong_shadow and context.exec_ctx
    return None



def validate_high_risk_tag(tag: object, strings_blob: object = '', path: object = None) -> object:
    """Return True only when a high-risk tag has enough concrete context."""
    tag_text, tag_reason = _scanner_lower_token(
        tag,
        missing_reason='missing_high_risk_tag',
        unsupported_reason='unsafe_high_risk_tag_rejected',
    )
    if tag_reason or not tag_text:
        return False
    text, text_reason = _scanner_validation_text(_tag_validation_text, strings_blob)
    if text_reason:
        return False
    context = _HighRiskValidationContext(
        tag=tag_text,
        text=text,
        is_rpyc=_is_renpy_bytecode_path(path),
        exec_ctx=_has_any_text(text, [
            'subprocess', 'os.system', 'popen(', 'popen', 'createprocess',
            'shellexecute', 'winexec', 'cmd.exe', 'cmd /c', 'powershell', 'pwsh',
            'start-process', 'exec(', 'eval(', 'renpy.python.py_exec_bytecode',
        ]),
        net_ctx=_has_any_text(text, [
            'http://', 'https://', 'socket', 'connect(', 'webhook', 'telegram', 'discord',
        ]),
        compact=re.sub(r'[^a-z0-9_./$\\-]+', ' ', text),
    )
    decision = _validate_lateral_movement_tag(context)
    if decision is None:
        decision = _validate_credential_and_execution_tag(context)
    if decision is None:
        decision = _validate_bypass_and_injection_tag(context)
    if decision is None:
        decision = _validate_network_and_archive_tag(context)
    if decision is None:
        decision = _validate_pickle_and_persistence_tag(context)
    if decision is None:
        decision = tag_text not in BROAD_UNVALIDATED_TAGS
    return decision


__all__ = (
    'infer_correlation_group',
    'library_baseline_hard_proof_status',
    'library_baseline_has_hard_proof',
    'reference_url_only_score_cap',
    'validate_high_risk_tag',
)
