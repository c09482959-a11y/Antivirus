"""Canonical script/process execution heuristic registry.

Stage 23 centralizes the weakly duplicated script-execution families used by
text, RPGM, Ren'Py and Unity collectors.  It emits canonical scoreable tags only
when there is concrete behavior context, while preserving engine-aware damping
through the numeric score metadata.
"""
from __future__ import annotations
import re
from dataclasses import asdict, dataclass
from Virus_Scan.heuristics.no_hook import heuristic_lower, heuristic_text

@dataclass(frozen=True)
class HeuristicHit:
    family: str
    tag: str
    pattern: str
    weight: float = 1.0

SCRIPT_EXEC_PATTERNS: tuple[tuple[str, str, str, float], ...] = (
    ("powershell", r"\b(?:powershell|pwsh)(?:\.exe)?\b", "powershell_exec", 1.0),
    ("cmd", r"\b(?:cmd|cmd\.exe)\s*/[cqk]", "cmd_exec", 0.9),
    ("encoded_ps", r"(?:-|/)enc(?:odedcommand)?\b|frombase64string\s*\(", "encoded_powershell", 1.15),
    ("python_exec", r"\b(?:eval|exec)\s*\(", "dynamic_execution", 0.65),
    ("subprocess", r"\b(?:subprocess\.(?:popen|run|call)|os\.system|popen\(|child_process\.(?:exec|spawn|fork))\b", "process_exec", 1.0),
    ("native_injection", r"\b(?:virtualalloc(?:ex)?|writeprocessmemory|createremotethread(?:ex)?|ntcreatethreadex|queueuserapc|setthreadcontext)\b", "process_injection", 1.2),
    ("unity_process", r"\b(?:process\.start|createprocess|shellexecute|winexec)\b", "process_exec", 0.95),
    ("js_eval_decode", r"\b(?:eval|function)\s*\(.{0,120}(?:atob|fromcharcode|base64|unescape)|(?:atob|fromcharcode|base64|unescape).{0,120}\b(?:eval|function)\s*\(", "payload_decode_candidate", 1.15),
    ("js_network_eval", r"\b(?:xmlhttprequest|fetch\s*\(|https?\.request|websocket)\b.{0,160}\b(?:eval|function|child_process|atob)\b", "rpgm_js_network_exec_candidate", 1.05),
    ("token_theft", r'''\b(?:discord token|authorization['"]?\s*[:=]|access_token|refresh_token|login data|cookies\.sqlite|webhook)\b''', "token_secret_access", 1.0),
)

def _ctx_multiplier(engine: str | None) -> float:
    e = heuristic_lower(engine)
    if e in {"unity", "rpgm", "renpy"}:
        return 0.85
    return 1.0

def _engine_from_source(source: str | None, engine: str | None) -> str | None:
    engine_text = heuristic_text(engine)
    if engine_text:
        return engine_text
    src = heuristic_lower(source).replace('\\','/')
    if '/www/js' in src or 'rpg_' in src or src.endswith('.js'):
        return 'rpgm'
    if src.endswith(('.rpy','.rpyc','.rpym')) or 'renpy' in src:
        return 'renpy'
    if src.endswith(('.cs','.dll','.assets','.bundle')) or 'unity' in src:
        return 'unity'
    return None

def _script_execution_hits(low: str, engine: str | None) -> list[HeuristicHit]:
    multiplier = _ctx_multiplier(engine)
    return [
        HeuristicHit(family, tag, pattern, weight * multiplier)
        for family, pattern, tag, weight in SCRIPT_EXEC_PATTERNS
        if re.search(pattern, low, re.IGNORECASE | re.DOTALL)
    ]


def _script_process_observation_tags(families: set[str]) -> list[str]:
    tags: list[str] = []
    if {"encoded_ps", "powershell"}.issubset(families):
        tags.extend(("payload_execution", "script_execution", "process_exec"))
    process_family = bool({"subprocess", "cmd", "unity_process"} & families)
    powershell_family = bool({"powershell", "encoded_ps"} & families)
    if process_family and powershell_family:
        tags.extend(("payload_execution", "script_execution", "process_exec"))
    return tags


def _script_payload_observation_tags(low: str, families: set[str]) -> list[str]:
    tags: list[str] = []
    if "js_eval_decode" in families:
        tags.extend(("payload_execution", "script_execution", "encoded_payload", "encoded_payload_candidate"))
    if "js_network_eval" in families:
        tags.extend(("network_activity", "network_download", "remote_payload_download", "script_execution", "payload_execution"))
    native_chain = (
        "native_injection" in families
        and "virtualalloc" in low
        and ("createremotethread" in low or "ntcreatethreadex" in low)
    )
    if native_chain:
        tags.extend(("memory_allocate", "memory_write", "thread_execution", "process_injection", "in_memory_execution", "shellcode_exec"))
    return tags


def _script_exfiltration_observation_tags(low: str, families: set[str]) -> list[str]:
    exfil_terms = ("webhook", "http://", "https://", "requests.post", "xmlhttprequest", "fetch(")
    tags: list[str] = []
    if "token_theft" in families and any(term in low for term in exfil_terms):
        tags.extend(("credential_access", "network_exfiltration", "token_exfiltration", "high_confidence_credential_theft"))
    return tags


def _script_execution_observation_tags(low: str, families: set[str]) -> list[str]:
    return (
        _script_process_observation_tags(families)
        + _script_payload_observation_tags(low, families)
        + _script_exfiltration_observation_tags(low, families)
    )


def _ordered_unique_tags(tags: list[str]) -> list[str]:
    deduplicated: list[str] = []
    for tag in tags:
        if tag not in deduplicated:
            deduplicated.append(tag)
    return deduplicated


def evaluate_script_execution(text: str, *, engine: str | None = None, source: str | None = None) -> dict:
    low = heuristic_lower(text)
    resolved_engine = _engine_from_source(source, engine)
    hits = _script_execution_hits(low, resolved_engine)
    families = {hit.family for hit in hits}
    tags = _ordered_unique_tags(
        [hit.tag for hit in hits] + _script_execution_observation_tags(low, families)
    )
    return {
        "tags": tags,
        "hits": [asdict(hit) for hit in hits],
        "families": sorted(families),
        "score": min(1.0, sum(hit.weight for hit in hits) / 3.0),
        "source": heuristic_text(source) or None,
        "engine": resolved_engine,
    }

__all__=("HeuristicHit", "SCRIPT_EXEC_PATTERNS", "evaluate_script_execution")
