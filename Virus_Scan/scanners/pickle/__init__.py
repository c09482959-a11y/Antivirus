"""Bounded scanner-owned pickle submodules."""
from __future__ import annotations

from Virus_Scan.scanners.pickle.protocol import has_pickle_protocol_header, pickle_protocol_offsets

__all__ = ("has_pickle_protocol_header", "pickle_protocol_offsets")
