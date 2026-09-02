"""Text-view helpers for scanner-owned pickle evidence projection."""
from __future__ import annotations

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (
    OSError,
    EOFError,
    ValueError,
    TypeError,
    RuntimeError,
    KeyError,
    AttributeError,
    UnicodeError,
)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_DECODE_MAX_DECODED_BYTES = _PICKLE_POLICY.decode_max_decoded_bytes


def _pickle_exact_text_or_none(value: object) -> object:
    if value is None:
        return ""
    if type(value) is str:
        return value
    return None


def _pickle_exact_bytes_or_none(value: object) -> object:
    if value is None:
        return b""
    if type(value) is bytes:
        return value
    if type(value) is bytearray:
        return bytes(value)
    return None


def _pickle_text_terms_or_none(values: object) -> object:
    if values is None:
        return ()
    if type(values) is tuple or type(values) is list:
        return tuple(values)
    if type(values) is frozenset:
        return tuple(sorted(values))
    return None


def _has_any_text(text: object, needles: object) -> object:
    base_text = _pickle_exact_text_or_none(text)
    terms = _pickle_text_terms_or_none(needles)
    if base_text is None or terms is None:
        return False
    low = base_text.lower()
    for needle in terms:
        needle_text = _pickle_exact_text_or_none(needle)
        if needle_text is not None and needle_text.lower() in low:
            return True
    return False


def _has_command_exec_behavior(text: object) -> object:
    return _has_any_text(text, [
        'powershell', 'cmd.exe', 'subprocess', 'popen(', 'os.system',
        'process.start', 'createprocess', 'child_process', 'exec(', 'eval(',
    ])


def _has_pickle_exec_behavior(text: object) -> object:
    pickle_terms = _has_any_text(text, [
        'pickle.loads', 'pickle.load(', 'pickletools', 'pickletools.dis',
        '__reduce__', '__reduce_ex__', 'stack_global', 'opcode: global',
        'opcode: reduce', 'global opcode', 'reduce opcode', 'cos\nsystem',
        'cposix\nsystem', 'cnt\nsystem', 'posix\nsystem', 'nt\nsystem',
        'builtins\neval', 'builtins\nexec', 'subprocess\npopen',
    ])
    dangerous_pickle_callable = _has_any_text(text, [
        'cos\nsystem', 'cposix\nsystem', 'cnt\nsystem', 'posix\nsystem',
        'nt\nsystem', 'builtins\neval', 'builtins\nexec', 'subprocess\npopen',
    ])
    return bool(pickle_terms and (_has_command_exec_behavior(text) or dangerous_pickle_callable))


def pickle_decode_interesting_text_status(text: object, raw: object = b'') -> object:
    low_text = _pickle_exact_text_or_none(text)
    if low_text is None:
        return 'probe_error'
    raw_bytes = _pickle_exact_bytes_or_none(raw)
    low = low_text.lower()
    if raw_bytes is not None and len(raw_bytes) > 0 and (
        raw_bytes.startswith((b'MZ', b'\x7fELF', b'PK\x03\x04'))
    ):
        return 'interesting'
    anchors = (
        'subprocess', 'popen(', 'os.system', 'exec(', 'eval(', 'compile(',
        'urllib.request', 'urlopen', 'urlretrieve', 'requests.get',
        'requests.post', 'http://', 'https://', '.exe', 'appdata',
        'localappdata', 'local extension settings', 'chrome', 'user data',
        'login data', 'cookies', 'nkbihfbeogaeaoehlefnkodbefgpgknn',
        'bfnaelmomeimhlpmgjnjophhpkkoljpa', 'hnfanknocfeofbddgcijnmhnfnkdnaad',
        'mcohilncbfahbmgdjkbpemcciiolgcge', 'egjidjbpglichdcondbcbdnbeeppgdph',
        'omaabbefbmiijedngplfjmnooppbclkk', 'jsonrpc', 'eth_call',
        'ethereum', 'sepolia', 'publicnode', 'tenderly', '1rpc.io',
        'drpc.org', 'ssl.cert_none', 'cert_none', 'verify_mode',
        'check_hostname', 'create_default_context', 'zlib.decompress',
        'base64.b64decode', 'marshal.loads', 'pickle.loads', 'threading.thread',
    )
    return 'interesting' if any((a in low for a in anchors)) else 'ordinary'


def _pickle_decode_interesting_text(text: object, raw: object = b'') -> object:
    return pickle_decode_interesting_text_status(text, raw=raw) == 'interesting'


def _pickle_bytes_to_text_views(raw: object) -> object:
    views = []
    raw_bytes = _pickle_exact_bytes_or_none(raw)
    if raw_bytes is None:
        try:
            record_suppressed_failure(
                'suppressed_exception',
                ValueError('unsupported_pickle_raw_bytes_boundary'),
                domain='runtime',
            )
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
        return views
    if len(raw_bytes) == 0:
        return views
    for enc in ('utf-8', 'utf-16le', 'latin1'):
        try:
            s = raw_bytes[:PICKLE_DECODE_MAX_DECODED_BYTES].decode(enc, errors='ignore')
            if s and s not in views:
                views.append(s)
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    return views


__all__ = (
    '_has_any_text',
    '_has_command_exec_behavior',
    '_has_pickle_exec_behavior',
    '_pickle_bytes_to_text_views',
    '_pickle_decode_interesting_text',
    'pickle_decode_interesting_text_status',
)
