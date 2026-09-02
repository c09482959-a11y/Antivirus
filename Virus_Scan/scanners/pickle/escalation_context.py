"""Text-context decisions for pickle fast escalation."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot

_PICKLE_POLICY = load_pickle_policy_snapshot()
PICKLE_FAST_DANGEROUS_TEXT = _PICKLE_POLICY.fast_dangerous_text
PICKLE_FAST_EXEC_TEXT = _PICKLE_POLICY.fast_exec_text
source_escalation_needles = ('base64.b64decode', 'zlib.decompress', 'marshal.loads')
source_pickle_exts = frozenset(('.rpy', '.rpym'))


def _pickle_fast_context_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_pickle_fast_context_text',
        unsupported_reason='unsafe_pickle_fast_context_text_rejected',
    )
    return '' if reason else text


def _pickle_fast_text_has_pickle_context(text: object) -> object:
    return any((needle in _pickle_fast_context_text(text) for needle in PICKLE_FAST_DANGEROUS_TEXT))


def _pickle_fast_text_has_exec_context(text: object) -> object:
    low = _pickle_fast_context_text(text)
    return any((needle in low for needle in PICKLE_FAST_EXEC_TEXT))


def _pickle_fast_source_escalation(ext: object, low_text: object, exec_text: object) -> object:
    if ext not in source_pickle_exts:
        return False
    if 'pickle' not in low_text and '__reduce__' not in low_text and 'persistent_load' not in low_text:
        return False
    return exec_text is True or any((needle in low_text for needle in source_escalation_needles))


__all__ = ('PICKLE_FAST_DANGEROUS_TEXT', 'PICKLE_FAST_EXEC_TEXT', '_pickle_fast_source_escalation', '_pickle_fast_text_has_exec_context', '_pickle_fast_text_has_pickle_context')
