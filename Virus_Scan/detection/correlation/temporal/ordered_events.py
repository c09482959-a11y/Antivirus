"""Ordered contextual string-event ownership for temporal correlation."""

from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

from Virus_Scan.detection.enrichment.strings.contextual.scan import (
    ContextualTagScanRequest,
    contextual_tag_scan,
)
from Virus_Scan.detection.tags.heuristics.primary_behavior import primary_behavior_for_tag
_TAG_PROBES = MappingProxyType({
    'powershell_exec': ('powershell', 'pwsh'),
    'encoded_powershell': ('encodedcommand', '-enc'),
    'schtasks_create': ('schtasks',),
    'scheduled_task': ('schtasks', 'at.exe'),
    'at_exec': ('at.exe',),
    'network_download': ('downloadstring', 'downloadfile', 'invoke-webrequest'),
    'url_present': ('http://', 'https://'),
    'certutil_exec': ('certutil',),
    'bitsadmin_exec': ('bitsadmin',),
    'mshta_exec': ('mshta',),
    'rundll32_exec': ('rundll32',),
    'regsvr32_exec': ('regsvr32',),
    'wmi_exec': ('wmic', 'win32_process', 'invoke-wmimethod'),
    'memory_write': ('writeprocessmemory', 'rtlmovememory', 'copymemory', 'memcpy'),
    'thread_execution': ('createremotethread', 'ntcreatethreadex', 'createthread', 'queueuserapc'),
    'memory_allocate': ('virtualalloc', 'virtualallocex'),
    'credential_dump_attempt': ('mimikatz', 'sekurlsa', 'minidumpwritedump', 'lsass'),
})


def _first_probe_position(blob: str, blob_l: str, tag: str) -> tuple[int, str]:
    probes = _TAG_PROBES.get(tag, (tag,))
    for needle in probes:
        pos = blob_l.find(needle)
        if pos >= 0:
            return pos, blob[pos:pos + len(needle)]
    return 0, tag


def iter_ordered_string_events(strings_blob: object) -> object:
    """Yield ordered string events without invoking caller-owned text hooks."""
    blob, blob_reason = no_hook_text(
        strings_blob,
        missing_reason='missing_timeline_string_blob',
        unsupported_reason='timeline_string_blob_rejected',
    )
    if blob_reason or blob == '':
        return
    blob_l = blob.lower()
    for tag in contextual_tag_scan(
        ContextualTagScanRequest(strings_blob=blob, source="timeline")
    ):
        tag_text, tag_reason = no_hook_text(
            tag,
            missing_reason='missing_timeline_tag',
            unsupported_reason='timeline_tag_rejected',
        )
        if tag_reason or tag_text == '':
            continue
        tag_l = tag_text.lower()
        pos, raw = _first_probe_position(blob, blob_l, tag_l)
        yield (
            pos,
            {
                'kind': 'string',
                'raw': raw,
                'tag': tag_text,
                'behavior': primary_behavior_for_tag(tag_text),
                'source': 'contextual_strings',
            },
        )


__all__ = (
    'iter_ordered_string_events',
)
