"""Scanner-owned pickle compressed-payload record iteration."""
from __future__ import annotations

from Virus_Scan.runtime.api import is_programmer_error
from Virus_Scan.scanners.config.loader import load_pickle_policy_snapshot
from Virus_Scan.scanners.payload_decode import embedded_payload_records_from_bytes
from Virus_Scan.scanners.pickle.literals import PickleFailureRequest, _pickle_failure_record

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
PICKLE_DECODE_MAX_OFFSETS = _PICKLE_POLICY.decode_max_offsets


def _iter_raw_compressed_payload_records(data: object) -> object:
    """Yield embedded compressed payload records through canonical payload decoding."""
    try:
        yield from embedded_payload_records_from_bytes(
            data,
            encoding_hint='pickle_raw_compressed_stream',
            max_offsets=PICKLE_DECODE_MAX_OFFSETS,
        )
    except PICKLE_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        if is_programmer_error(exc):
            raise
        yield _pickle_failure_record(PickleFailureRequest('raw_compressed_payload_records', exc, encoding='raw_compressed_stream'))


__all__ = ('_iter_raw_compressed_payload_records',)
