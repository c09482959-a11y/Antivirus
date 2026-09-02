"""Canonical reference-URL behavior suppression policy.

This module owns the single implementation used by scanners and detection. It
keeps documentation/source URLs from becoming runtime network/evasion evidence
unless concrete runtime fetch or patch behavior is present.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.scanners.api.pipeline_contracts import scanner_context_regex
from Virus_Scan.utils.text_match import has_any_text as _has_any_text
from Virus_Scan.utils.text_validation import tag_validation_text as _tag_validation_text, text_boundary_value

_SOURCE_LIKE_SUFFIXES = frozenset({".rpy", ".py", ".rpym", ".txt"})
_RUNTIME_NETWORK_ANCHORS = (
    "requests.get",
    "requests.post",
    "urllib.request",
    "urlopen(",
    "urlretrieve(",
    "downloadfile",
    "downloadstring",
    "fetch(",
    "xmlhttprequest",
    "xhr.open",
    "socket.",
    ".connect(",
    "subprocess",
    "os.system",
    "popen(",
    "createprocess",
)
_CONCRETE_EVASION_ANCHORS = (
    "amsiscanbuffer",
    "amsi.dll",
    "amsiinitfailed",
    "etweventwrite",
    "nttraceevent",
    "patch etw",
    "disable etw",
    "bypass etw",
    "patch amsi",
    "disable amsi",
    "virtualprotect",
    "writeprocessmemory",
    "set-mppreference",
    "disableantispyware",
    "wevtutil cl",
    "clear-eventlog",
    "vssadmin delete shadows",
)


def _source_suffix(path: object) -> str:
    path_text = text_boundary_value(path, unsupported="")
    if type(path_text) is not str or path_text == "":
        return ""
    return Path(path_text).suffix.lower()


def suppress_reference_url_false_positives(
    tags: Iterable[object] | None,
    path: object = None,
    strings_blob: object = "",
) -> list[object]:
    """Return tags after deterministic reference-URL behavior suppression."""
    text = _tag_validation_text(strings_blob)
    source_like = _source_suffix(path) in _SOURCE_LIKE_SUFFIXES
    tag_values = no_hook_sequence_items(tags)
    input_tagset = {_tag_validation_text(tag) for tag in tag_values if _tag_validation_text(tag)}
    marker_suppressed = "reference_url_behavior_suppressed" in input_tagset
    has_url = bool(scanner_context_regex(r"\b(?:https?|ftp)://", text)) or bool(
        {"url_present", "reference_url"} & input_tagset
    )
    runtime_net = _has_any_text(text, _RUNTIME_NETWORK_ANCHORS)
    concrete_evasion = _has_any_text(text, _CONCRETE_EVASION_ANCHORS)

    cleaned: list[object] = []
    changed = False
    for tag in tag_values:
        low = _tag_validation_text(tag)
        if source_like and has_url and (marker_suppressed or not runtime_net) and low == "network_activity":
            cleaned.append("reference_url")
            changed = True
            continue
        if source_like and (marker_suppressed or not concrete_evasion) and low in {
            "defense_evasion",
            "etw_bypass_attempt",
            "amsi_bypass_attempt",
        }:
            changed = True
            continue
        cleaned.append(tag)

    if source_like and has_url and (marker_suppressed or not runtime_net):
        cleaned.append("url_present")
        cleaned.append("reference_url")
        if changed or marker_suppressed:
            cleaned.append("reference_url_behavior_suppressed")
    return ordered_unique_tags(cleaned)
