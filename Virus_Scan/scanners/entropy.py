from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from collections import Counter
import math
from Virus_Scan.scanners.binary_entropy_helpers import shannon_entropy_bytes as _shannon_entropy_bytes
from Virus_Scan.scanners.binary_io import read_binary_file_bytes, binary_log_message
from Virus_Scan.scanners.binary_integrity import binary_degraded_scan_integrity
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_contract_text, scanner_failure_evidence_tags, scanner_failure_evidence_record
from Virus_Scan.scanners.binary_numeric import safe_clamp
from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot

PLR2004N126 = 126
PLR2004N32 = 32

_BINARY_POLICY = load_binary_policy_snapshot()


def _exact_scanner_tag_values(tags: object) -> object:
    if tags is None:
        return ()
    if type(tags) not in (tuple, list, set, frozenset):
        return ()
    values = []
    for tag in tags:
        if type(tag) is not str:
            return ()
        values.append(str.__str__(tag))
    return tuple(values)


def _counter_value_tuple(counts: object) -> object:
    if type(counts) is not Counter:
        return ()
    return tuple(dict.values(counts))


def tag_entropy(tags: object) -> object:
    tag_values = _exact_scanner_tag_values(tags)
    if len(tag_values) == 0:
        return 0.0
    counts = Counter(tag_values)
    total = len(tag_values)
    entropy = 0.0
    for c in _counter_value_tuple(counts):
        p = c / total
        entropy -= p * math.log2(p + 1e-09)
    return entropy


def _strict_fast_entropy(data: object) -> object:
    """Return strict-fast entropy without hiding helper failures.

    Callers pass bounded bytes read through scanner-owned IO.  Any unexpected
    malformed object or helper failure must remain visible to the caller instead
    of being converted into a high-entropy default that changes scan routing
    without evidence.
    """
    return byte_entropy(data)


def byte_entropy(data: object) -> object:
    return _shannon_entropy_bytes(data)


def entropy_bytes(data: object) -> object:
    return byte_entropy(data)


def _entropy_failure_result(path: object, category: object, error: object, base_tags: object, reason: object, error_category: object) -> object:
    evidence_tags = scanner_failure_evidence_tags(
        'entropy',
        category,
        error,
        [*list(base_tags), 'entropy_final_json_must_record'],
        input_path=path,
        state='degraded',
        error_category=error_category,
        error_source='entropy.detect_packer_entropy_anomaly',
        file_type='binary',
    )
    evidence = scanner_failure_evidence_record(
        'entropy',
        category,
        error,
        input_path=path,
        state='degraded',
        error_category=error_category,
        error_source='entropy.detect_packer_entropy_anomaly',
        file_type='binary',
    )
    return {
        'score': 0.0,
        'tags': evidence_tags,
        'reasons': [reason],
        'scanner_failure_evidence': [evidence],
        'scan_integrity': binary_degraded_scan_integrity(error, scanner='entropy', scanner_failure_evidence=[evidence], final_json_must_record=True),
    }


def _entropy_empty_input_result(path: object) -> object:
    return _entropy_failure_result(
        path,
        'entropy_empty_input',
        'empty entropy input',
        ['entropy_scan_empty_input'],
        'empty input',
        'empty_binary_input',
    )


def _entropy_exception_result(path: object, exc: object) -> object:
    return _entropy_failure_result(
        path,
        'entropy_read_or_analysis',
        exc,
        ['entropy_scan_error'],
        scanner_contract_error_message(exc),
        'binary_entropy_read_or_analysis_failure',
    )


def _entropy_score_for_data(data: object) -> object:
    entropy_value = byte_entropy(data)
    printable_ratio = _printable_ratio(data)
    tags, reasons, score = _entropy_threshold_tags(entropy_value, printable_ratio)
    marker_result = _packer_marker_result(data)
    tags.extend(marker_result['tags'])
    reasons.extend(marker_result['reasons'])
    score += marker_result['score']
    return {
        'score': safe_clamp(score, 0.0, 1.0),
        'entropy': entropy_value,
        'printable_ratio': printable_ratio,
        'tags': sorted(set(tags)),
        'reasons': reasons,
    }


def _printable_ratio(data: object) -> object:
    printable = sum(1 for byte in data if PLR2004N32 <= byte <= PLR2004N126)
    return printable / max(1, len(data))


def _entropy_threshold_tags(entropy_value: object, printable_ratio: object) -> object:
    tags, reasons, score = [], [], 0.0
    if entropy_value >= _BINARY_POLICY.entropy_high_threshold:
        score += _BINARY_POLICY.entropy_high_score
        tags.append('high_entropy_packed')
        reasons.append(scanner_contract_join('high entropy ', format(entropy_value, '.2f')))
    if entropy_value >= _BINARY_POLICY.entropy_very_high_threshold:
        score += _BINARY_POLICY.entropy_very_high_score
        tags.append('very_high_entropy')
        reasons.append(scanner_contract_join('very high entropy ', format(entropy_value, '.2f')))
    if entropy_value >= _BINARY_POLICY.entropy_low_visibility_threshold and printable_ratio < _BINARY_POLICY.entropy_low_visibility_printable_ratio:
        score += _BINARY_POLICY.entropy_low_visibility_score
        tags.append('low_string_visibility')
        reasons.append('high entropy with low printable strings')
    return tags, reasons, score


def _packer_marker_result(data: object) -> object:
    lower = data.lower()
    markers = tuple(scanner_contract_text(marker, replacement='').encode('latin1', errors='ignore') for marker in _BINARY_POLICY.entropy_packer_markers)
    for marker in markers:
        if marker and marker in lower:
            return {
                'score': _BINARY_POLICY.entropy_packer_score,
                'tags': ['packer_marker'],
                'reasons': [scanner_contract_join("packer marker ", marker.decode(errors='ignore'))],
            }
    return {'score': 0.0, 'tags': [], 'reasons': []}


def detect_packer_entropy_anomaly(path: object) -> object:
    """Return bounded entropy anomaly evidence without hidden clean fallbacks."""
    try:
        data = read_binary_file_bytes(path, max_size=_BINARY_POLICY.entropy_read_max_bytes)
        if len(data) == 0:
            return _entropy_empty_input_result(path)
        return _entropy_score_for_data(data)
    except SCAN_CONTENT_ERRORS as exc:
        binary_log_message(scanner_contract_join('packer entropy anomaly failed: ', scanner_contract_error_message(exc)))
        return _entropy_exception_result(path, exc)


__all__ = ('byte_entropy', 'detect_packer_entropy_anomaly', 'entropy_bytes', 'tag_entropy')
