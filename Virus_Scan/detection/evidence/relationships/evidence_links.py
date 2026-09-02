"""Decoded-payload evidence link ownership.

Detection links already-observed text facts into semantic relationships. Payload
candidate decoding itself remains scanner-owned and is expected to have happened
before this evidence linker sees the extraction view.
"""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage

DECODE_LAYER_MAX_DEPTH = 5
_EXEC_NEEDLES = (
    'exec(', 'eval(', 'subprocess', 'os.system', 'createprocess', 'powershell',
    'cmd.exe', 'child_process', 'shellexecute', 'start-process', 'popen(',
)
_NETWORK_NEEDLES = (
    'http://', 'https://', 'socket.create_connection', 'requests.post',
    'webhook', 'api.telegram.org', 'fetch(', 'xmlhttprequest', 'websocket(',
)
_INJECTION_NEEDLES = (
    'virtualalloc', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex',
)
_PERSISTENCE_NEEDLES = ('currentversion\\run', 'schtasks', 'startup', 'runonce')
_DECODE_CONTEXT_NEEDLES = (
    'base64', 'frombase64string', 'atob(', 'buffer.from', 'encodedcommand',
    'payload_decode_candidate', 'decoded_payload_rescanned', 'decoded_',
)
_BINARY_MAGIC_NEEDLES = ('mz\x00', 'pk\x03\x04', '%pdf', '\x7felf')


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _has_decode_context(text: str) -> bool:
    return _contains_any(text, _DECODE_CONTEXT_NEEDLES) or (
        len(text) >= 120 and _contains_any(text, _EXEC_NEEDLES + _NETWORK_NEEDLES)
    )


def umige_evidence_link_tags(strings_blob: object, path: object = None) -> object:
    """Create lightweight evidence-link tags from scanner-observed extraction text.

    This function intentionally does not decode payloads. Scanner-owned text
    extraction/payload observation provides decoded text in the extraction view;
    detection only links that observed text to behavior evidence.
    """
    tags: list[str] = []
    text, reason = no_hook_text(
        strings_blob,
        missing_reason="decoded_payload_evidence_links_text_missing",
        unsupported_reason="decoded_payload_evidence_links_text_unavailable",
    )
    if reason:
        if reason == "decoded_payload_evidence_links_text_missing":
            return []
        return sorted(set(failure_tags_for_stage("decoded_payload_evidence_links", reason, context=path)))
    low = str.lower(text)
    if not low:
        return []
    if _has_decode_context(low):
        tags.append('evidence_link:decode_observed')
    if _contains_any(low, _BINARY_MAGIC_NEEDLES):
        tags.extend(['payload_decode_confirmed', 'evidence_link:decoded_binary_payload'])
    if _contains_any(low, _EXEC_NEEDLES):
        tags.extend(['payload_execution', 'evidence_link:decoded_payload_to_execution'])
    if _contains_any(low, _NETWORK_NEEDLES):
        tags.extend(['network_activity', 'evidence_link:decoded_payload_to_network'])
    if _contains_any(low, _INJECTION_NEEDLES):
        tags.extend(['process_injection', 'evidence_link:decoded_payload_to_injection'])
    if _contains_any(low, _PERSISTENCE_NEEDLES):
        tags.extend(['persistence', 'evidence_link:decoded_payload_to_persistence'])
    current = set(tags)
    if {'evidence_link:decoded_payload_to_execution', 'evidence_link:decoded_payload_to_network'}.issubset(current):
        tags.append('evidence_link:decoded_payload_execution_network_correlation')
    return sorted(set(tags))


__all__ = ('umige_evidence_link_tags',)
