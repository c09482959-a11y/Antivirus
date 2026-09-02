"""Scanner-owned embedded binary/archive payload signature validation."""
from __future__ import annotations

from dataclasses import dataclass


PLR2004N4096 = 4096

@dataclass(frozen=True, slots=True)
class EmbeddedPECandidateStatus:
    status: str
    tag: str | None = None


def validated_embedded_payload_hits(sample: object, min_offset: int = 32) -> object:
    """Return embedded payload tags only for validated or visibly malformed payload headers."""
    hits: list[tuple[int, str]] = []
    if not sample:
        return hits
    data = bytes(sample)
    pos = data.find(b'MZ', min_offset)
    while pos != -1:
        status = _embedded_pe_candidate_status(data, pos, min_offset)
        if status.status == 'valid':
            hits.append((pos, 'embedded_pe_signature'))
            break
        if status.status == 'malformed' and status.tag:
            hits.append((pos, status.tag))
        pos = data.find(b'MZ', pos + 1)
    hits.extend(_embedded_archive_hits(data, min_offset))
    return hits


def _embedded_pe_candidate_status(data: bytes, off: int, min_offset: int) -> EmbeddedPECandidateStatus:
    if off < min_offset or data[off:off + 2] != b'MZ':
        return EmbeddedPECandidateStatus('not_pe')
    if off + 64 > len(data):
        return EmbeddedPECandidateStatus('not_pe')
    pe_off = int.from_bytes(data[off + 60:off + 64], 'little', signed=False)
    if pe_off <= 0 or pe_off > PLR2004N4096:
        return EmbeddedPECandidateStatus('not_pe')
    pe_sig_start = off + pe_off
    if pe_sig_start + 4 > len(data):
        return EmbeddedPECandidateStatus('malformed', 'embedded_pe_header_truncated')
    if data[pe_sig_start:pe_sig_start + 4] != b'PE\x00\x00':
        return EmbeddedPECandidateStatus('malformed', 'embedded_pe_signature_missing')
    return EmbeddedPECandidateStatus('valid')


def _embedded_archive_hits(data: bytes, min_offset: int) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for sig, tag in ((b'PK\x03\x04', 'embedded_zip_signature'), (b"7z\xbc\xaf'\x1c", 'embedded_7z_signature'), (b'Rar!\x1a\x07', 'embedded_rar_signature')):
        off = data.find(sig, min_offset)
        if off != -1:
            hits.append((off, tag))
    return hits


__all__ = ('EmbeddedPECandidateStatus', 'validated_embedded_payload_hits')
