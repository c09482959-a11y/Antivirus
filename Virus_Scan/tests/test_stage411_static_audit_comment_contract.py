from __future__ import annotations

import re
from pathlib import Path


FORBIDDEN_STATIC_TERMS = re.compile(
    r"\b(fallback|compatibility|adapter|shim|bridge|monkey|deprecated|migration|lazy import|import inside function|globals\(\)|setattr\(|__dict__|sys\.modules|runtime injection)\b",
    re.IGNORECASE,
)


CANONICAL_FILES = (
    "Virus_Scan/detection/chains/execution/anchors.py",
    "Virus_Scan/detection/chains/composite/behavior_intent.py",
    "Virus_Scan/detection/registries/chain_registry.py",
    "Virus_Scan/init_runtime/__init__.py",
    "Virus_Scan/contracts/path_identity.py",
)


def test_stage411_static_audit_terms_are_not_preserved_in_canonical_commentary() -> None:
    root = Path(__file__).resolve().parents[2]
    hits: list[str] = []
    for relative in CANONICAL_FILES:
        path = root / relative
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FORBIDDEN_STATIC_TERMS.search(line):
                hits.append(f"{relative}:{lineno}:{line.strip()}")
    assert hits == []
