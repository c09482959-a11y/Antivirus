"""Evidence-specific line extractors for the compact CLI report."""

import gzip
from dataclasses import dataclass
from pathlib import Path
import re

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.reporting.evidence_line_text import (
    add_unique_line,
    context_around,
    first_regex,
    looks_like_tag_name,
    safe_report_mapping_get,
    safe_report_path_text,
    safe_report_sequence,
    safe_report_text,
)

from Virus_Scan.reporting.evidence_line_rules import (
    DECODE_TAGS,
    EMBEDDED_PAYLOAD_TAGS,
    EVIDENCE_RULES,
    PICKLE_OBSERVATION_NAMES,
    PICKLE_PATTERNS,
    PICKLE_TAGS,
)

@dataclass(frozen=True, slots=True)
class EvidenceLineContext:
    path: object
    lines: object
    seen: object
    tags: object
    strings_blob: object
    raw_text: object
    evidence: object
    ordered: object


def add_url_lines(lines: object, seen: object, tags: object, strings_blob: object, raw_text: object) -> None:
    network_tags = {"url_present", "network_activity", "asset_resource_fetch", "browser_xhr_fetch", "http_upload", "network_download", "remote_resource_fetch", "c2_candidate"}
    if not (tags & network_tags or re.search("https?://|www\\.", strings_blob, re.IGNORECASE)):
        return
    url_re = re.compile("(?i)\\b(?:https?://|ftp://|wss?://|www\\.)[^\\s'\\\"<>\\)\\]}]{3,260}")
    for url in url_re.findall(strings_blob or raw_text or "")[:4]:
        add_unique_line(lines, seen, "Url", url.rstrip(".,;"), 220)
    if not any(line.startswith("Url:") for line in lines):
        host = first_regex(strings_blob, ["\\b(?:[a-z0-9-]+\\.)+[a-z]{2,}\\b", "\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b"], 0)
        add_unique_line(lines, seen, "Url", host, 160)


def add_decode_lines(lines: object, seen: object, tags: object, strings_blob: object) -> None:
    if not (tags & DECODE_TAGS or re.search("[A-Za-z0-9+/]{80,}={0,2}", strings_blob or "")):
        return
    recs = []
    for rec in list(recs or [])[:4]:
        enc = safe_report_text(safe_report_mapping_get(rec, "encoding"), limit=80) or "decoded"
        chain_values = safe_report_sequence(safe_report_mapping_get(rec, "decode_chain"), max_items=16) or (enc,)
        chain = "->".join(text for text in (safe_report_text(x, limit=80) for x in chain_values) if text) or enc
        txt = safe_report_text(safe_report_mapping_get(rec, "text"))
        ctx = first_regex(txt, ["(?:powershell(?:\\.exe)?|pwsh|cmd(?:\\.exe)?|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget)[^\\r\\n\\x00]{0,220}", "(?:frombase64string|iex\\s*\\(|subprocess\\.(?:popen|run|call)|os\\.system|eval\\s*\\(|exec\\s*\\()[^\\r\\n\\x00]{0,220}", "https?://[^\\s'\\\"<>\\)\\]}]{3,220}", "MZ.{0,24}"], 0) or txt[:220]
        prefix = "DecodedBase64" if "base64" in chain.lower() else "Decoded"
        add_unique_line(lines, seen, prefix, str.__add__(str.__add__(chain, " -> "), ctx), 260)


def add_embedded_payload_lines(context: EvidenceLineContext) -> None:
    if not context.tags & EMBEDDED_PAYLOAD_TAGS:
        return
    blob = context.raw_text or context.strings_blob
    label = "EmbeddedPayload"
    detail = ""
    if "embedded_gzip_payload" in context.tags or "gzip" in context.tags:
        label, detail = "EmbeddedGzip", gzip_detail(context.path, blob)
    elif "embedded_zlib_payload" in context.tags:
        label = "EmbeddedZlib"
        detail = first_regex(blob, ["zlib.{0,120}", "deflate.{0,120}", "\x78[\x01\x5e\x9c\xda].{0,80}"], 20) or "zlib/deflate stream marker found"
    elif "embedded_pe_payload" in context.tags or "embedded_executable_marker" in context.tags:
        label = "EmbeddedExe"
        detail = first_regex(blob, ["MZ.{0,80}", "This program cannot be run in DOS mode.{0,120}", "PE\x00\x00.{0,80}"], 20) or "embedded executable marker found"
    else:
        label = "EmbeddedArchive"
        detail = first_regex(blob, ["PK\x03\x04.{0,80}", "7z\xbc\xaf\x27\x1c.{0,80}", "Rar!.{0,80}", "archive.{0,120}"], 20) or "embedded archive/container marker found"
    add_unique_line(context.lines, context.seen, label, detail, 220)



def gzip_detail(path: object, blob: object) -> object:
    detail = ""
    try:
        path_text = safe_report_path_text(path)
        if not path_text:
            return first_regex(blob, ["gzip.{0,120}", "GZipStream.{0,160}"], 20) or "gzip stream marker found"
        raw_bytes = Path(path_text).read_bytes()[:1500000]
        offset = raw_bytes.find(b"\x1f\x8b")
        if offset >= 0:
            decoded = gzip.decompress(raw_bytes[offset:])[:4096].decode("latin1", errors="ignore")
            detail = first_regex(decoded, ["(?:powershell|cmd(?:\\.exe)?|wscript|cscript|mshta|subprocess|os\\.system|eval\\s*\\(|exec\\s*\\(|https?://)[^\\r\\n\\x00]{0,220}"], 0) or decoded[:220]
    except TELEMETRY_FAILURE_ERRORS:
        detail = ""
    return detail or first_regex(blob, ["gzip.{0,120}", "GZipStream.{0,160}"], 20) or "gzip stream marker found"


def add_pickle_lines(context: EvidenceLineContext) -> None:
    pickle_tags = context.tags & PICKLE_TAGS
    if not pickle_tags:
        return
    hints, opcode_windows = pickle_hints(
        context.evidence,
        context.strings_blob,
        context.raw_text,
    )
    observation_names = [tag for tag in PICKLE_OBSERVATION_NAMES if tag in pickle_tags]
    detail = " + ".join(observation_names[:3])
    if hints:
        detail = (detail + " -> " if detail else "") + hints[0]
    elif detail:
        detail = detail.replace("_", " ")
    add_unique_line(
        context.lines,
        context.seen,
        "Pickle",
        detail or "pickle opcode evidence",
        260,
    )
    if opcode_windows:
        add_unique_line(
            context.lines,
            context.seen,
            "PickleOpcode",
            opcode_windows[0],
            420,
        )



def pickle_hints(evidence: object, strings_blob: object, raw_text: object) -> object:
    raw_triggers = safe_report_sequence(safe_report_mapping_get(evidence, "pickle_raw_triggers"), max_items=4)
    opcode_triggers = safe_report_sequence(safe_report_mapping_get(evidence, "pickle_opcode_triggers"), max_items=3)
    hints = [text for text in (safe_report_text(item).strip() for item in raw_triggers) if text]
    opcode_windows = [text for text in (safe_report_text(item).strip() for item in opcode_triggers) if text]
    for pattern in PICKLE_PATTERNS:
        ctx = context_around(strings_blob or raw_text, pattern, radius=30)
        if ctx and ctx not in hints:
            hints.append(ctx)
    return hints, opcode_windows


def add_behavior_rule_lines(context: EvidenceLineContext) -> None:
    for prefix, rule_tags, patterns in EVIDENCE_RULES:
        if not context.tags & rule_tags:
            continue
        ctx = first_regex(
            context.strings_blob or context.raw_text,
            patterns,
            radius=0,
        )
        if not ctx:
            ctx = first_matching_event_context(
                context.ordered,
                rule_tags,
                context.tags,
            )
        add_unique_line(context.lines, context.seen, prefix, ctx, 260)



def first_matching_event_context(ordered: object, rule_tags: object, tags: object) -> object:
    hidden_generic = {"script_execution", "process_exec", "code_execution", "bytecode_exec", "bytecode_eval"}
    for event in safe_report_sequence(ordered, max_items=256):
        if type(event) is dict:
            raw = safe_report_text(safe_report_mapping_get(event, "raw"))
            tag = safe_report_text(safe_report_mapping_get(event, "tag"), limit=120).lower()
        else:
            raw = safe_report_text(event)
            tag = raw.lower()
        normalized = raw.strip().lower()
        if raw and tag in rule_tags and not looks_like_tag_name(raw) and normalized not in tags and normalized not in hidden_generic:
            return raw
    return ""


def add_yara_lines(lines: object, seen: object, result: object, tags: object) -> None:
    yara_hits = safe_report_sequence(safe_report_mapping_get(result, "yara_hits"), max_items=5)
    if yara_hits and (tags & {"yara_match", "yara_malware_hit", "signature_hit"} or yara_hits):
        add_unique_line(lines, seen, "YARA", ", ".join(text for text in (safe_report_text(item, limit=120) for item in yara_hits[:5]) if text), 220)
