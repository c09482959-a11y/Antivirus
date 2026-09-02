"""Canonical obfuscation/encoding heuristic registry."""
from __future__ import annotations
import re
from Virus_Scan.heuristics.no_hook import heuristic_text
OBFUSCATION_PATTERNS=(
    ("base64", r"(?:frombase64string|atob\s*\(|base64\.b64decode|[A-Za-z0-9+/]{80,}={0,2})", "encoded_data_context"),
    ("gzip", r"\x1f\x8b\x08|gzip|zlib\.decompress", "embedded_gzip_payload"),
    ("xor", r"\bxor\b|\^\s*0x[0-9a-f]{2}", "xor_obfuscation_candidate"),
    ("packed", r"upx|themida|vmprotect|packed", "packed_or_obfuscated"),
)

def evaluate_obfuscation(text: str | bytes, *, source: str | None=None) -> dict:
    blob = heuristic_text(text)
    tags=[]; fam=[]
    for f, pat, tag in OBFUSCATION_PATTERNS:
        if re.search(pat, blob, re.IGNORECASE|re.DOTALL): fam.append(f); tags.append(tag)
    if 'base64' in fam and ('gzip' in fam or 'xor' in fam): tags.append('encoded_payload_candidate')
    return {"tags": list(dict.fromkeys(tags)), "families": sorted(set(fam)), "source": heuristic_text(source) or None}
__all__=("OBFUSCATION_PATTERNS", "evaluate_obfuscation")
