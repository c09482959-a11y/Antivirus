"""Markov-owned exact text boundary helpers.

Markov probability/evidence paths must not invoke caller-owned ``__str__`` or
string subclass hooks while canonicalizing behavior-flow, stage, reason, or
counter keys. Unsupported objects are represented by the caller-provided
default text so model failures never become hidden clean text through arbitrary
coercion.
"""
from __future__ import annotations


from Virus_Scan.models.contracts.no_hook_materialization import no_hook_text

def markov_detached_text(value: object, *, default_text: str = '') -> tuple[str, str]:
    """Return detached Markov text and an optional unavailable reason."""
    text, reason = no_hook_text(
        value,
        missing_reason='missing_markov_text',
        unsupported_reason='unsupported_markov_text',
    )
    if reason:
        return default_text, reason if default_text == '' else ''
    text = str.strip(text)
    if text == '':
        return default_text, '' if default_text != '' else 'empty_markov_text'
    return text, ''


def markov_text(value: object, *, default_text: str = '') -> str:
    text, _reason = markov_detached_text(value, default_text=default_text)
    return text


__all__ = ('markov_detached_text', 'markov_text')
