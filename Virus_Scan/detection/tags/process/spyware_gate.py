"""Detection-owned spyware collection/exfiltration gate."""

from Virus_Scan.detection.contracts.string_predicates import has_any_text
from Virus_Scan.utils.tagging import norm_lower_set, ordered_unique_tags
from Virus_Scan.utils.text_validation import tag_validation_text


def _has_confirmed_exfil_proof(text: object, tagset: object) -> object:
    return bool(
        tagset & {'network_exfiltration', 'token_exfiltration', 'http_upload', 'dns_tunneling'}
        or (
            has_any_text(text, ['uploadfile', 'uploadstring', 'multipart/form-data', 'webhook', 'discord.com/api/webhooks', 'api.telegram.org', 'ftp://', 'http post', 'postasync', 'requests.post', 'socket.send'])
            and has_any_text(text, ['password', 'credential', 'token', 'cookie', 'wallet', 'screenshot', 'clipboard', 'keylog', 'login data', 'cookies.sqlite'])
        )
    )


def gate_spyware_collection_chains(tags: object, path: object=None, strings_blob: object='') -> object:
    """Remove spyware/exfil chains unless collection, sensitive target, and transmit proof are present."""
    del path  # Explicitly unused contract parameters.
    tagset = norm_lower_set(tags)
    text = tag_validation_text(strings_blob)
    has_input_or_collection = bool(tagset & {'keylogging_behavior', 'input_capture', 'clipboard_access', 'screenshot_capture', 'screen_capture', 'file_collection'})
    has_sensitive = bool(tagset & {'credential_access', 'credential_dump_attempt', 'browser_credential_access', 'token_secret_access', 'token_exfiltration'}) or has_any_text(text, ['password', 'credential', 'token', 'cookie', 'wallet', 'seed phrase', 'private key', 'login data', 'cookies.sqlite'])
    has_exfil = _has_confirmed_exfil_proof(text, tagset)
    allow_spyware_chain = has_input_or_collection and has_sensitive and has_exfil
    cleaned = []
    removed = False
    for tag in ordered_unique_tags(tags):
        low = tag.lower()
        if low in {'spyware_behavior', 'exfiltration', 'network_exfiltration', 'http_upload'} and not allow_spyware_chain:
            removed = True
            continue
        if low == 'user_activity_monitoring' and not allow_spyware_chain:
            cleaned.append('input_event_handling')
            removed = True
            continue
        cleaned.append(tag)
    if removed:
        cleaned.append('spyware_chain_intent_gate_suppressed')
    return ordered_unique_tags(cleaned)


__all__ = ('gate_spyware_collection_chains',)
