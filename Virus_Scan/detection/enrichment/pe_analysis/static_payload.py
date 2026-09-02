"""Static payload anomaly scanner owner."""

from Virus_Scan.detection.evidence.static_bytes import find_known_eof_offset, stage_read_bytes
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.utils.entropy import shannon_entropy_bytes
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.contracts.string_predicates import ascii_visibility_ratio
from Virus_Scan.detection.contracts.string_predicates import looks_like_base64_payload
from Virus_Scan.detection.contracts.binary_predicates import xor_blob_signal


PLR2004N2048 = 2048
PLR2004N256 = 256
PLR2004N4096 = 4096
PLR2004N7_2 = 7.2


def scan_static_payload_anomalies(path: object, data: object=None, strings_blob: object='') -> object:
    """Static detector for overlays, high entropy, encoded blobs, API chains, and payload chains."""
    tags = []
    try:
        if data is None:
            data = stage_read_bytes(path, max_size=64 * 1024 * 1024)
        if not data:
            return []
        low_text = (strings_blob or '').lower()
        eof, eof_kind = find_known_eof_offset(data)
        if eof is not None and eof < len(data):
            overlay = data[eof:]
            nonzero = overlay.strip(b'\x00\r\n\t ')
            if len(nonzero) >= PLR2004N256:
                tags += ['overlay_payload_after_eof', eof_kind or 'known_eof_overlay']
                ent = shannon_entropy_bytes(nonzero[:min(len(nonzero), 2 * 1024 * 1024)])
                if ent >= PLR2004N7_2:
                    tags += ['high_entropy_overlay', 'possible_packed_or_encrypted_overlay']
                if any((x in nonzero[:4096].lower() for x in [b'mz', b'pk\x03\x04', b'\x1f\x8b', b'powershell', b'cmd.exe', b'http://', b'https://'])):
                    tags += ['embedded_payload_after_eof', 'overlay_contains_executable_or_command']
        if len(data) >= PLR2004N4096:
            high_windows = 0
            for off in range(0, min(len(data), 4 * 1024 * 1024), 4096):
                chunk = data[off:off + 4096]
                if len(chunk) < PLR2004N2048:
                    continue
                if shannon_entropy_bytes(chunk) >= 7.45 and ascii_visibility_ratio(chunk) < 0.55:
                    high_windows += 1
            if high_windows >= 2:
                tags += ['high_entropy_sections', 'possible_packed_or_encrypted_blob']
        if looks_like_base64_payload(low_text):
            tags += ['embedded_base64_payload', 'payload_decode_candidate']
        if b'\x1f\x8b\x08' in data or 'gzipstream' in low_text or 'gzipexpand' in low_text:
            tags += ['embedded_gzip_payload', 'compressed_payload']
        if xor_blob_signal(data) and any((x in low_text for x in ['xor', '^=', 'frombase64string', 'virtualalloc', 'writeprocessmemory', 'shellcode'])):
            tags += ['possible_xor_encoded_blob', 'encoded_payload_candidate']
        has_alloc = any((x in low_text for x in ['virtualalloc', 'virtualallocex', 'ntallocatevirtualmemory']))
        has_write = any((x in low_text for x in ['writeprocessmemory', 'rtlmovememory', 'copymemory']))
        has_protect = any((x in low_text for x in ['virtualprotect', 'virtualprotectex', 'ntprotectvirtualmemory']))
        has_thread = any((x in low_text for x in ['createremotethread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext']))
        if (has_alloc and has_write and (has_thread or has_protect)) or (has_write and has_thread):
            tags += ['memory_allocate', 'memory_write', 'thread_execution', 'process_injection', 'in_memory_execution']
        if any((x in low_text for x in ['assembly.load', 'load(byte[]', 'frombase64string', 'reflective', 'shellcode', 'invoke-reflectivepeinjection'])):
            if any((x in low_text for x in ['virtualalloc', 'virtualprotect', 'writeprocessmemory', 'createremotethread', 'iex', 'invoke-expression'])):
                tags += ['in_memory_execution', 'fileless_execution', 'embedded_base64_payload']
        has_fetch = any((x in low_text for x in ['downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'curl ', 'wget ', 'certutil', 'bitsadmin', 'urlopen', 'internetopenurl', 'winhttpopenrequest']))
        has_url = any((x in low_text for x in ['http://', 'https://', 'ftp://']))
        has_write_file = any((x in low_text for x in ['writefile', 'createfile', 'out-file', 'set-content', '> %temp%', '$env:temp', 'temp\\']))
        has_execute = any((x in low_text for x in ['start-process', 'createprocess', 'shellexecute', 'cmd /c', 'powershell', 'rundll32', 'regsvr32', 'mshta', '.exe', '.dll', '.ps1', '.hta']))
        if has_fetch and has_url and (has_write_file or has_execute):
            tags += ['downloader_pattern', 'network_download', 'file_write', 'process_exec']
            if any((x in low_text for x in ['certutil', 'bitsadmin', 'mshta', 'regsvr32', 'rundll32', 'powershell'])):
                tags += ['lolbin_download']
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        tags.extend(failure_tags_for_stage("static_payload_anomaly_scan", e, context=path))
    finally:
        pass
    return normalize_tags(tags)
