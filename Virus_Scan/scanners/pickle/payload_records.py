"""Scanner-owned pickle embedded payload record public facade.

Concrete ownership is split across bounded pickle modules:
- payload_literal_records.py owns literal decoding projection.
- payload_opcode_records.py owns pickle opcode literal iteration.
- payload_compressed_records.py owns compressed payload expansion records.
"""
from __future__ import annotations

from Virus_Scan.scanners.pickle.payload_compressed_records import _iter_raw_compressed_payload_records
from Virus_Scan.scanners.pickle.payload_literal_records import _try_decode_pickle_literal
from Virus_Scan.scanners.pickle.payload_opcode_records import iter_pickle_payload_records, _iter_pickle_payload_records

__all__ = (
    '_iter_pickle_payload_records',
    '_iter_raw_compressed_payload_records',
    '_try_decode_pickle_literal',
    'iter_pickle_payload_records',
)
