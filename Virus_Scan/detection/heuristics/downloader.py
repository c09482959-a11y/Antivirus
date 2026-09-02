"""Detection-owned downloader/network-payload heuristic ownership."""
from __future__ import annotations

import re

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

DOWNLOADER_PATTERNS = (
    ("url", r"https?://", "url_present"),
    ("download", r"\b(?:downloadstring|downloadfile|invoke-webrequest|curl\s+|wget\s+|urlopen|requests\.(?:get|post)|fetch\s*\(|xmlhttprequest|https?\.request)\b", "network_download"),
    ("socket", r"\b(?:websocket|socket\.create_connection|connect\()\b", "network_activity"),
    ("execute_after_download", r"(?:download|string|file|fetch|xmlhttprequest|https?\.request).{0,120}(?:iex|invoke-expression|eval|function|exec|spawn|start-process|child_process)", "payload_execution"),
)


def _owned_heuristic_text(value: object) -> str:
    if value is None:
        return ""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_downloader_text",
        unsupported_reason="unsafe_downloader_text_rejected",
    )
    return "" if reason else str.lower(text)


def evaluate_downloader_behavior(text: str, *, source: str | None = None) -> dict:
    low = _owned_heuristic_text(text)
    tags: list[str] = []
    families: list[str] = []
    for family, pattern, tag in DOWNLOADER_PATTERNS:
        if re.search(pattern, low, re.IGNORECASE | re.DOTALL):
            families.append(family)
            tags.append(tag)
    if "download" in families and ("execute_after_download" in families or "socket" in families):
        tags += ["remote_payload_download", "process_exec"]
    return {"tags": list(dict.fromkeys(tags)), "families": sorted(set(families)), "source": source}


__all__ = ("DOWNLOADER_PATTERNS", "evaluate_downloader_behavior")
