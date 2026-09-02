"""Scanner-owned API extraction and ordered sequence evidence."""

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags
from Virus_Scan.scanners.text_api_policy import API_REGEX
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text, no_hook_type_name


def _stage_token(stage: object, *, default: object = 'api') -> object:
    text, reason = no_hook_text(
        stage,
        missing_reason="missing_text_api_stage",
        unsupported_reason="unsafe_text_api_stage_rejected",
    )
    return default if reason or not text else text


def _text_api_failure_tags(stage: object, error: object, extra_tags: object = ()) -> object:
    stage_text = _stage_token(stage)
    base_tags = ['text_api_extract_failed', stage_text + '_scan_error']
    for tag in no_hook_sequence_items(extra_tags):
        if type(tag) is str and tag not in base_tags:
            base_tags.append(tag)
    return scanner_failure_evidence_tags(
        'text',
        stage_text,
        error,
        base_tags,
        state='degraded',
        error_category='text_api_extraction_failure',
        error_source='text.' + stage_text,
        file_type='text',
    )


def _exact_scanner_text(value: object, *, stage: object) -> object:
    stage_text = _stage_token(stage)
    text, reason = no_hook_text(
        value,
        missing_reason='missing_' + stage_text + '_text',
        unsupported_reason='unsafe_' + stage_text + '_text_rejected',
    )
    return text, reason


def _extract_matches_from_text(text: object, *, api_regex: object) -> object:
    return [m.group(0) for m in api_regex.finditer(text)]


def api_ngrams(seq: object, n: object = 3) -> object:
    if len(seq) < n:
        return []
    return [tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)]


def extract_api_calls(strings_blob: object, *, api_regex: object = API_REGEX, logger: object = log_error) -> object:
    """Extract deduplicated API calls while preserving first-seen order."""
    text, reason = _exact_scanner_text(strings_blob, stage='api_extract')
    if reason:
        if reason.startswith('unsafe_'):
            return _text_api_failure_tags('api_extract', reason, (reason,))
        return []
    if text == '':
        return []
    try:
        matches = _extract_matches_from_text(text, api_regex=api_regex)
        return list(dict.fromkeys(matches))
    except SCAN_CONTENT_ERRORS as e:
        logger('API extract failed: ' + no_hook_type_name(e))
        return _text_api_failure_tags('api_extract', e)


def extract_api_sequence_from_blob(strings_blob: object, *, api_regex: object = API_REGEX, logger: object = log_error) -> object:
    """Return every API occurrence in first-seen order, including repeats."""
    text, reason = _exact_scanner_text(strings_blob, stage='api_sequence_extract')
    if reason:
        if reason.startswith('unsafe_'):
            return _text_api_failure_tags('api_sequence_extract', reason, (reason,))
        return []
    if text == '':
        return []
    try:
        return _extract_matches_from_text(text, api_regex=api_regex)
    except SCAN_CONTENT_ERRORS as e:
        logger('API sequence extract failed: ' + no_hook_type_name(e))
        return _text_api_failure_tags('api_sequence_extract', e)


def build_api_sequence(log_lines: object = None, strings_blob: object = '', *, api_regex: object = API_REGEX, logger: object = log_error) -> object:
    """Build an ordered API sequence from logs first, then string content."""
    seq = []
    for line in no_hook_sequence_items(log_lines):
        line_text, line_reason = _exact_scanner_text(line, stage='api_log_sequence_extract')
        if line_reason:
            if line_reason.startswith('unsafe_'):
                return _text_api_failure_tags('api_log_sequence_extract', line_reason, (line_reason,))
            continue
        try:
            seq.extend(_extract_matches_from_text(line_text, api_regex=api_regex))
        except SCAN_CONTENT_ERRORS as e:
            logger('API log sequence extract failed: ' + no_hook_type_name(e))
            return _text_api_failure_tags('api_log_sequence_extract', e)
    if seq:
        return seq
    return extract_api_sequence_from_blob(strings_blob, api_regex=api_regex, logger=logger)


__all__ = (
    'API_REGEX',
    'api_ngrams',
    'build_api_sequence',
    'extract_api_calls',
    'extract_api_sequence_from_blob',
)
