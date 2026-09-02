"""Scanner-owned pickle GLOBAL/STACK_GLOBAL reference classification."""
from __future__ import annotations

import re
from typing import NoReturn

from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

PICKLE_SCAN_RECOVERABLE_EXCEPTIONS = (OSError, EOFError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError)
_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_SAFE_RECONSTRUCT_GLOBALS = _PICKLE_POLICY.safe_reconstruct_globals
PICKLE_SAFE_RECONSTRUCT_PREFIXES = _PICKLE_POLICY.safe_reconstruct_prefixes
PICKLE_DANGEROUS_GLOBALS = _PICKLE_POLICY.dangerous_globals
PICKLE_SUSPICIOUS_GLOBAL_PARTS = _PICKLE_POLICY.suspicious_global_parts
PICKLE_DANGEROUS_GLOBAL_RE = re.compile(r'(?:^|\.)(?:system|popen|run|eval|exec|compile|spawn|call)$')
_PICKLE_GLOBAL_NORMALIZATION_FAILED = 'pickle global normalization failed'


def _raise_pickle_global_normalization_failed(cause: BaseException) -> NoReturn:
    raise ValueError(_PICKLE_GLOBAL_NORMALIZATION_FAILED) from cause


def _pickle_global_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_pickle_global_text",
        unsupported_reason="unsafe_pickle_global_text_rejected",
    )
    if reason:
        return "", reason
    return text.strip().lower(), ""


def _pickle_is_safe_reconstruct_global(g: object) -> object:
    x, reason = _pickle_global_text(g)
    if reason or not x:
        return False
    return x in PICKLE_SAFE_RECONSTRUCT_GLOBALS or any((x.startswith(p) for p in PICKLE_SAFE_RECONSTRUCT_PREFIXES))


def _pickle_is_dangerous_callable_global(g: object) -> object:
    """True only for callable targets that can execute/import/load code."""
    x, reason = _pickle_global_text(g)
    if reason:
        try:
            record_suppressed_failure('suppressed_exception', TypeError(reason), domain='runtime')
        except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as _umige_reporting_exc:
            _ = _umige_reporting_exc
        return False
    if not x or _pickle_is_safe_reconstruct_global(x):
        return False
    if x in PICKLE_DANGEROUS_GLOBALS:
        return True
    if PICKLE_DANGEROUS_GLOBAL_RE.search(x):
        return True
    return x.startswith(('subprocess.', 'os.', 'posix.', 'nt.', 'runpy.', 'importlib.', 'marshal.', 'pickle.', 'cloudpickle.', 'dill.'))


def pickle_reference_global_status(g: object) -> object:
    x, reason = _pickle_global_text(g)
    if reason:
        return 'probe_error'
    if not x or _pickle_is_safe_reconstruct_global(x):
        return 'safe_or_empty'
    if _pickle_is_dangerous_callable_global(x):
        return 'dangerous'
    if any((part in x for part in PICKLE_SUSPICIOUS_GLOBAL_PARTS)):
        return 'suspicious'
    return 'ordinary'


def _pickle_is_suspicious_reference_global(g: object) -> object:
    return pickle_reference_global_status(g) in {'dangerous', 'suspicious'}


def _pickle_canonical_global_status(module: object, name: object = None) -> object:
    """Return explicit pickle global normalization status without sentinel globals."""
    module_text, module_reason = _pickle_global_text(module)
    if module_reason:
        return ('parse_error', TypeError(module_reason))
    if name is None:
        text = module_text.replace(' ', '.').replace('\n', '.')
        text = re.sub('\\.+', '.', text).strip('.')
        return ('global', text.lower())
    name_text, name_reason = _pickle_global_text(name)
    if name_reason:
        return ('parse_error', TypeError(name_reason))
    return ('global', (module_text.strip() + '.' + name_text.strip()).strip('.').lower())


def _pickle_canonical_global(module: object, name: object = None) -> object:
    status, value = _pickle_canonical_global_status(module, name)
    if status == 'parse_error':
        exception_message = 'pickle global normalization failed'
        raise ValueError(exception_message) from value if isinstance(value, BaseException) else TypeError(str(value))
    if type(value) is str:
        return value
    _raise_pickle_global_normalization_failed(TypeError('pickle_global_not_text'))


__all__ = (
    '_pickle_canonical_global',
    '_pickle_canonical_global_status',
    '_pickle_is_dangerous_callable_global',
    '_pickle_is_safe_reconstruct_global',
    '_pickle_is_suspicious_reference_global',
    'pickle_reference_global_status',
)
