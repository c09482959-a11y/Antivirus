"""Scanner-owned appended payload detection for binary/image-like inputs."""
from __future__ import annotations

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.scanners.binary_entropy_helpers import entropy_from_counts as _entropy_from_counts


PLR2004N256 = 256
PLR2004N7_35 = 7.35
PLR2004N8 = 8


def scan_appended_payload(data: object, tags: object) -> object:
    """Detect real bytes appended after image EOF markers without clean failure fallback."""
    suspicious = False
    try:
        eof_index, kind = _appended_payload_eof(data)
        if eof_index <= 0 or len(data) <= eof_index:
            return False
        nonzero = data[eof_index:].strip(b'\x00\r\n\t ')
        if len(nonzero) < PLR2004N256:
            return False
        _add_appended_observation_tags(tags, kind)
        suspicious = True
        payload_result = _appended_payload_result(nonzero)
        tags.extend(payload_result['tags'])
        if type(kind) is str and kind and payload_result['confirmed']:
            tags.append(str.__add__(kind, '_appended_payload'))
    except SCAN_CONTENT_ERRORS as exc:
        tags.extend(scanner_failure_evidence_tags(
            'binary',
            'appended_payload_scan',
            exc,
            ['appended_payload_scan_error', 'scanner_appended_payload_error'],
            state='degraded',
            error_category='embedded_payload_scan_failure',
            file_type='image_or_binary_payload',
        ))
    return suspicious


def _appended_payload_eof(data: object) -> tuple[int, str | None]:
    if not data:
        return (-1, None)
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        marker = b'IEND\xaeB`\x82'
        pos = data.rfind(marker)
        return (pos + len(marker), 'png') if pos >= 0 else (-1, None)
    if data.startswith(b'\xff\xd8'):
        pos = data.rfind(b'\xff\xd9')
        return (pos + 2, 'jpeg') if pos >= 0 else (-1, None)
    if data.startswith((b'GIF87a', b'GIF89a')):
        pos = data.rfind(b';')
        return (pos + 1, 'gif') if pos >= 0 else (-1, None)
    if data.startswith(b'RIFF') and data[8:12] == b'WEBP' and len(data) >= PLR2004N8:
        declared = int.from_bytes(data[4:8], 'little') + 8
        return (declared, 'webp') if 0 < declared <= len(data) else (-1, None)
    return (-1, None)


def _add_appended_observation_tags(tags: list[str], kind: str | None) -> None:
    tags += ['image_appended_data', 'stego_candidate_observation']
    if type(kind) is str and kind:
        tags.append(str.__add__(kind, '_appended_data'))


def _appended_payload_result(nonzero: bytes) -> dict:
    low = nonzero[:min(len(nonzero), 262144)].lower()
    entropy = _payload_entropy(nonzero)
    has_payload_magic = _has_payload_magic(low)
    tags = []
    if entropy >= PLR2004N7_35:
        tags += ['high_entropy_appended_payload', 'possible_encrypted_stego_payload']
    if has_payload_magic or entropy >= PLR2004N7_35:
        tags += ['image_payload_confirmed', 'image_appended_payload', 'embedded_payload_after_eof']
    if has_payload_magic:
        tags += ['embedded_executable_or_command', 'high_confidence_image_payload']
    confirmed = has_payload_magic is True or entropy >= PLR2004N7_35
    return {'confirmed': confirmed, 'tags': tags}


def _payload_entropy(nonzero: bytes) -> float:
    counts = [0] * 256
    sample = nonzero[:262144]
    for byte in sample:
        counts[byte] += 1
    return _entropy_from_counts(counts, len(sample))


def _has_payload_magic(low: bytes) -> bool:
    magic_prefixes = (b'mz', b'pk\x03\x04', b'\x1f\x8b\x08', b"7z\xbc\xaf'\x1c")
    text_markers = [b'powershell', b'cmd.exe', b'#!/bin/sh', b'#!/usr/bin/env', b'<script', b'frombase64string']
    return low.startswith(magic_prefixes) or any(marker in low[:8192] for marker in text_markers)


__all__ = ('scan_appended_payload',)
