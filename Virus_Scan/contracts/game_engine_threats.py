"""Canonical game-engine threat contracts and text primitives.

This module owns neutral, side-effect-free primitives shared by scanner-facing
heuristics and detection-owned semantic evaluation.  Keeping these primitives in
contracts prevents root heuristics and detection heuristics from carrying same-body
helper implementations while preserving the existing public evaluators.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


@dataclass(frozen=True)
class GameThreatHit:
    family: str
    tag: str
    reason: str


class GameThreatAccumulator:
    """Small bounded accumulator for deterministic game-threat tag records."""

    def __init__(self) -> None:
        self.tags: list[str] = []
        self.hits: list[GameThreatHit] = []

    def add(self, family: str, reason: str, *new_tags: str) -> None:
        for tag in new_tags:
            if tag not in self.tags:
                self.tags.append(tag)
                self.hits.append(GameThreatHit(family, tag, reason))

    def to_record(self, *, engine: str, source: str | None) -> dict[str, object]:
        return {
            "tags": list(self.tags),
            "hits": [asdict(hit) for hit in self.hits],
            "engine": _contract_text(engine),
            "source": _contract_text(source),
        }


BROWSER_STORE_TERMS = (
    "login data", "cookies.sqlite", "cookies", "local state", "leveldb",
    "local storage", "localstorage", "sessionstorage", "indexeddb",
    "discord", "discordcanary", "discordptb", "chrome\\user data",
    "google\\chrome\\user data", "appdata\\roaming", "appdata\\local",
    "authorization", "access_token", "refresh_token", "token",
)
READ_TERMS = (
    "readfilesync", "readfile(", ".read(", "open(", "fs.read", "file.read",
    "path.join", "os.path", "homedir", "getenv", "environment.getfolderpath",
)
EXFIL_TERMS = (
    "fetch(", "xmlhttprequest", ".send(", ".post(", "requests.post", "webhook",
    "discord.com/api/webhooks", "api.telegram.org", "socket.send", "https.request",
    "content-type", "multipart/form-data", "body:", "upload", "postasync",
)
EXEC_TERMS = (
    "eval(", "exec(", "function(", "new function", "child_process", ".exec(",
    ".spawn(", "powershell", "cmd.exe", "subprocess", "os.system", "popen(",
)
INJECTION_TERMS = (
    "dllimport", "virtualalloc", "virtualallocex", "writeprocessmemory",
    "virtualprotect", "createremotethread", "ntcreatethreadex", "queueuserapc",
    "setthreadcontext", "il2cpp", "mono", "assembly-csharp",
)
KNOWN_MALWAREBAZAAR_FAMILIES = frozenset({
    "redline", "lumma", "stealc", "vidar", "raccoon", "raccoonstealer",
    "azorult", "formbook", "xloader", "agenttesla", "snakekeylogger",
    "lokibot", "fareit", "pony", "ursnif", "asyncrat", "njrat", "quasar",
    "remcos", "darkcomet", "nanocore", "warzonerat", "avemaria",
    "ave_maria", "netwire", "gh0strat", "gh0st", "plugx", "cobaltstrike",
    "sliver", "meterpreter", "metasploit", "qakbot", "emotet", "trickbot",
    "smokeloader", "amadey", "guloader", "bumblebee", "socgholish",
    "icedid", "icedidloader", "darkgate", "dridex", "gozi", "zeus",
    "raspberryrobin", "lockbit", "blackcat", "conti", "ryuk", "clop",
    "xmrig", "kinsing", "mirai", "gafgyt", "mozi",
})
MALWAREBAZAAR_CATEGORY_TERMS = (
    "stealer", "credential", "keylogger", "formgrabber", "clipper", "rat",
    "backdoor", "implant", "beacon", "remote shell", "reverse shell", "loader",
    "downloader", "dropper", "botnet", "banker", "webinject", "ransomware",
    "encrypt", "miner", "cryptominer", "ddos", "worm", "wiper", "destructive",
    "mbr", "rootkit", "kernel driver", "adware", "browser injection", "unwanted",
    "shellcode", "process injection", "malware",
)
MB_METADATA_KEY_RE = r"[\"']?(?:signature|tags?|yara_rules?|vendor_intel|file_name|file_type|sha256_hash|imphash|tlsh)[\"']?\s*[=:]"


def _contract_text(value: object, *, missing_reason: str = "missing_game_threat_text", unsupported_reason: str = "unsafe_game_threat_text_rejected") -> str:
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return ""
    return text


def engine_from_path(path: str | None) -> str:
    low = _contract_text(path).replace("\\", "/").lower()
    suffix_rules = (
        ("renpy", (".rpy", ".rpyc", ".rpym")),
        ("rpgm", (".js",)),
        ("unity", (".cs", ".dll", ".so", ".bundle", ".assets")),
    )
    marker_rules = (
        ("renpy", ("/game/", "renpy")),
        ("rpgm", ("/www/js", "rpgm", "nw.js")),
        ("unity", ("unity", "assembly-csharp")),
    )
    for engine, suffixes in suffix_rules:
        if low.endswith(suffixes):
            return engine
    for engine, markers in marker_rules:
        if contains_any_term(low, markers):
            return engine
    return "unknown"


def contains_any_term(text: str, terms: tuple[str, ...] | list[str]) -> bool:
    safe_text = _contract_text(text)
    if not safe_text or type(terms) not in (tuple, list):
        return False
    return any(isinstance(term, str) and term in safe_text for term in terms)


def matches_regex(text: str, pattern: str) -> bool:
    safe_text = _contract_text(text)
    safe_pattern = _contract_text(pattern)
    if not safe_text or not safe_pattern:
        return False
    return re.search(safe_pattern, safe_text, re.IGNORECASE | re.DOTALL) is not None


def strip_negated_behavior_phrases(text: str) -> str:
    """Remove narrow natural-language negated indicators before evaluation."""
    low = _contract_text(text).lower()
    primitives = (
        "eval", "child_process", "fetch", "webhook", "telegram", "discord",
        "powershell", "cmd.exe", "appdata", "startup", "runonce",
        "currentversion\\run", "credential", "cookie", "login data", "token",
        "socket", "websocket", "process.start", "subprocess", "exec", "network",
        "persistence", "ransomware", "encrypt", "encrypts", "miner", "cryptominer",
        "xmrig", "wiper", "rootkit", "adware", "browser injection", "botnet", "ddos",
    )
    low = re.sub(
        r"\b(?:no|not|without|never)\s+[^.,;\n]{0,80}\b(?:startup|runonce|appdata|network|credential|token|cookie|eval|child_process|powershell|cmd\.exe|process\.start|subprocess|exec|ransomware|encrypt|miner|cryptominer|xmrig|wiper|rootkit|adware|browser\s+injection|botnet|ddos)\b[^.,;\n]{0,80}",
        " ",
        low,
        flags=re.IGNORECASE,
    )
    for primitive in sorted(primitives, key=len, reverse=True):
        pattern = r"\b(?:no|not|without|never)\s+(?:[a-z0-9_./\\-]+\s+){0,3}" + re.escape(primitive)
        low = re.sub(pattern, " ", low, flags=re.IGNORECASE)
    return low


def has_malwarebazaar_metadata_marker(low: str) -> bool:
    safe_low = _contract_text(low)
    return "malwarebazaar" in safe_low or re.search(MB_METADATA_KEY_RE, safe_low, re.IGNORECASE) is not None


def malwarebazaar_metadata_sections(low: str, window: int = 500) -> str:
    safe_low = _contract_text(low)
    bounded_window = max(0, window) if type(window) is int and type(window) is not bool else 500
    sections = re.findall(MB_METADATA_KEY_RE + r"[^;\n]{0," + int.__str__(bounded_window) + r"}", safe_low, re.IGNORECASE)
    if sections:
        return " ".join(sections)
    return safe_low[:1000] if "malwarebazaar" in safe_low else ""


def malwarebazaar_metadata_family(low: str) -> str:
    if not has_malwarebazaar_metadata_marker(low):
        return ""
    haystack = malwarebazaar_metadata_sections(low, 500)
    for family in sorted(KNOWN_MALWAREBAZAAR_FAMILIES, key=len, reverse=True):
        if re.search(r"(?<![a-z0-9])" + re.escape(family) + r"(?![a-z0-9])", haystack, re.IGNORECASE):
            return family
    return ""


def is_malwarebazaar_malicious_metadata(low: str) -> bool:
    if not has_malwarebazaar_metadata_marker(low):
        return False
    if malwarebazaar_metadata_family(low):
        return True
    metadata_sections = malwarebazaar_metadata_sections(low, 240)
    return contains_any_term(metadata_sections, MALWAREBAZAAR_CATEGORY_TERMS)


__all__ = (
    "BROWSER_STORE_TERMS",
    "EXEC_TERMS",
    "EXFIL_TERMS",
    "INJECTION_TERMS",
    "KNOWN_MALWAREBAZAAR_FAMILIES",
    "MALWAREBAZAAR_CATEGORY_TERMS",
    "MB_METADATA_KEY_RE",
    "READ_TERMS",
    "GameThreatAccumulator",
    "GameThreatHit",
    "contains_any_term",
    "engine_from_path",
    "has_malwarebazaar_metadata_marker",
    "is_malwarebazaar_malicious_metadata",
    "malwarebazaar_metadata_family",
    "malwarebazaar_metadata_sections",
    "matches_regex",
    "strip_negated_behavior_phrases",
)
