"""Canonical downloader/network-payload heuristic registry."""
from __future__ import annotations
import re
from Virus_Scan.heuristics.no_hook import heuristic_lower, heuristic_text
DOWNLOADER_PATTERNS=(
    ("url", r"https?://", "url_present"),
    ("download", r"\b(?:downloadstring|downloadfile|invoke-webrequest|curl\s+|wget\s+|urlopen|requests\.(?:get|post)|fetch\s*\(|xmlhttprequest|https?\.request)\b", "network_download"),
    ("socket", r"\b(?:websocket|socket\.create_connection|connect\()\b", "network_activity"),
    ("execute_after_download", r"(?:download|string|file|fetch|xmlhttprequest|https?\.request).{0,120}(?:iex|invoke-expression|eval|function|exec|spawn|start-process|child_process)", "payload_execution"),
)

def evaluate_downloader_behavior(text: str, *, source: str | None=None) -> dict:
    low = heuristic_lower(text); tags=[]; fam=[]
    for f, pat, tag in DOWNLOADER_PATTERNS:
        if re.search(pat, low, re.IGNORECASE | re.DOTALL):
            fam.append(f); tags.append(tag)
    if 'download' in fam and ('execute_after_download' in fam or 'socket' in fam):
        tags += ['remote_payload_download', 'process_exec']
    return {"tags": list(dict.fromkeys(tags)), "families": sorted(set(fam)), "source": heuristic_text(source) or None}
__all__=("DOWNLOADER_PATTERNS", "evaluate_downloader_behavior")
