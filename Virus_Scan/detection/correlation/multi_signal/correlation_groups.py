"""Detection-owned correlation group classification."""

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text

CORRELATION_GROUP_KEYWORDS = (
    ('powershell_encoded', ('powershell', 'encodedcommand', 'encoded_powershell', '-enc')),
    ('base64_decode', ('base64', 'frombase64', 'decoded_base64', 'encoded_payload')),
    ('process_execution', ('process_exec', 'script_execution', 'shell_exec', 'wscript', 'mshta', 'rundll32')),
    ('credential_access', ('credential', 'lsass', 'token', 'password', 'cookie', 'stealer')),
    ('network_transfer', ('network', 'download', 'http', 'url', 'c2', 'exfil')),
    ('persistence', ('persistence', 'run_key', 'scheduled', 'service')),
    ('packing_obfuscation', ('packed', 'packer', 'obfus', 'xor', 'crypt', 'entropy')),
)


def infer_correlation_group(signal: object, tags: object=None) -> object:
    """Return a stable metadata group for related evidence signals."""
    try:
        signal_text, signal_reason = no_hook_text(
            signal,
            missing_reason='missing_correlation_signal',
            unsupported_reason='unsafe_correlation_signal_rejected',
        )
        tag_texts = []
        for tag in no_hook_sequence_items(tags):
            tag_text, tag_reason = no_hook_text(
                tag,
                missing_reason='missing_correlation_tag',
                unsupported_reason='unsafe_correlation_tag_rejected',
            )
            if tag_reason == '' and tag_text != '':
                tag_texts.append(tag_text)
        joined = (signal_text if signal_reason == '' else '') + ' ' + ' '.join(tag_texts)
        joined = joined.lower()
        for group, keys in CORRELATION_GROUP_KEYWORDS:
            if any(key in joined for key in keys):
                return group
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return 'correlation_group_failure_evidence_recorded'
    return 'generic_behavior'


__all__ = ('CORRELATION_GROUP_KEYWORDS', 'infer_correlation_group')
