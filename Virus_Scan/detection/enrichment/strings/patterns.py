"""Canonical immutable string indicator patterns for detection enrichment."""

import re

UMIGE_B64_LONG_RE = re.compile(r'(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{80,}={0,2})(?![A-Za-z0-9+/=_-])')
UMIGE_IPV4_RE = re.compile(r'\b(?!(?:10|127)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.|0\.|255\.)\d{1,3}(?:\.\d{1,3}){3}\b')

__all__ = ("UMIGE_B64_LONG_RE", "UMIGE_IPV4_RE")
