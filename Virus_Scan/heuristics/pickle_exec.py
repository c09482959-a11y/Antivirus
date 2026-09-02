"""Canonical pickle opcode execution semantics."""
from __future__ import annotations
import re
from Virus_Scan.heuristics.no_hook import heuristic_text
PICKLE_EXEC_PATTERNS=(
    ("reduce", r"\bREDUCE\b|\x52", "pickle_reduce_opcode"),
    ("global", r"\bGLOBAL\b|\x63", "pickle_global_reference"),
    ("callable", r"(?:os\n.system|subprocess|eval|exec|builtins\nexec|posix\nsystem)", "pickle_callable_reference"),
)

def evaluate_pickle_execution(blob: bytes | str, *, source: str | None=None) -> dict:
    text = heuristic_text(blob)
    hits=[]; tags=[]
    for fam, pat, tag in PICKLE_EXEC_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(fam); tags.append(tag)
    if "callable" in hits:
        tags.append("pickle_dangerous_global")
    return {"tags": list(dict.fromkeys(tags)), "families": sorted(set(hits)), "source": heuristic_text(source) or None}
__all__=("PICKLE_EXEC_PATTERNS", "evaluate_pickle_execution")
