"""Scanner-owned JPEG segment metadata checks for image scanning."""

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join


PLR2004N224 = 224
PLR2004N239 = 239
PLR2004N254 = 254
PLR2004N255 = 255
PLR2004N4096 = 4096


def _scan_jpeg_segments(data: object, tags: object) -> object:
    """Conservative JPEG APP/comment checks.

    URL/base64 strings in metadata are weak references, not confirmed payloads.
    Only command/executable/script indicators emit suspicious_jpeg_metadata_payload.
    """
    suspicious = False
    try:
        if not data.startswith(b'\xff\xd8'):
            return False
        pos = 2
        app_total = 0
        comment_total = 0
        segment_payload = b''
        while pos + 4 <= len(data):
            if data[pos] != PLR2004N255:
                pos += 1
                continue
            while pos < len(data) and data[pos] == PLR2004N255:
                pos += 1
            if pos >= len(data):
                break
            marker = data[pos]
            pos += 1
            if marker in (217, 218):
                break
            if marker in tuple(range(208, 216)) or marker == 1:
                continue
            if pos + 2 > len(data):
                break
            seg_len = int.from_bytes(data[pos:pos + 2], 'big')
            if seg_len < 2 or pos + seg_len > len(data):
                tags += ['jpeg_malformed_segment', 'stego_candidate_observation']
                return True
            payload = data[pos + 2:pos + seg_len]
            if PLR2004N224 <= marker <= PLR2004N239:
                app_total += len(payload)
                segment_payload += payload[:4096]
            elif marker == PLR2004N254:
                comment_total += len(payload)
                segment_payload += payload[:4096]
            pos += seg_len
        if app_total >= 64 * 1024:
            tags += ['large_jpeg_app_segments', 'stego_candidate_observation']
            suspicious = True
        if comment_total >= PLR2004N4096:
            tags += ['large_jpeg_comment', 'stego_candidate_observation']
            suspicious = True
        low = segment_payload.lower()
        if any((x in low for x in [b'http://', b'https://'])):
            tags += ['image_metadata_url_reference']
            suspicious = True
        if any((x in low for x in [b'base64', b'frombase64string'])):
            tags += ['image_metadata_encoded_reference', 'encoded_data_context']
            suspicious = True
        if any((x in low for x in [b'powershell', b'cmd.exe', b'mimikatz', b'certutil', b'bitsadmin', b'/bin/sh', b'<script'])):
            tags += ['suspicious_jpeg_metadata_payload', 'embedded_command_or_url', 'stego_candidate_observation']
            suspicious = True
    except SCAN_CONTENT_ERRORS as e:
        log_error(scanner_contract_join('JPEG segment stego scan failed: ', scanner_contract_error_message(e)))
    return suspicious


__all__ = ('_scan_jpeg_segments',)
