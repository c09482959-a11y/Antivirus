from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.utils.text_validation import text_boundary_value
from Virus_Scan.runtime.api import log_error, read_file_bytes, record_detector_error
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.heuristics import evaluate_game_engine_threats
from Virus_Scan.scanners.config.loader import load_engine_policy_snapshot

_ENGINE_POLICY = load_engine_policy_snapshot()


def _unity_extension_text(ext: object) -> object:
    text = text_boundary_value(ext, unsupported=None)
    if type(text) is not str:
        return ''
    return str.__str__(text).strip().lower()


def _is_unity_container_asset_extension(ext: object) -> object:
    return _unity_extension_text(ext) in _ENGINE_POLICY.unity_container_asset_extensions


def detect_unity_runtime_behavior(text: object) -> object:
    tags = set()
    text_value = text_boundary_value(text, unsupported='')
    text = str.__str__(text_value) if type(text_value) is str else ''
    for hook in _ENGINE_POLICY.unity_lifecycle_hooks:
        hook_text = str.__str__(hook) if type(hook) is str else ''
        if scanner_contract_join('void ', hook_text) in text or scanner_contract_join(hook_text, '(') in text:
            tags.add('unity_lifecycle')
    for needle, tag in _ENGINE_POLICY.unity_runtime_checks:
        if needle in text:
            tags.add(tag)
    return tags

def scan_unity_file(path: object, *, read_bytes: object = read_file_bytes, engine_threat_evaluator: object = evaluate_game_engine_threats) -> object:
    """Scan Unity files with both runtime markers and semantic threat heuristics.

    Stage 41 forensic audit finding: the synthetic validation exercised
    evaluate_game_engine_threats() directly, while the public Unity scanner only
    returned container/runtime markers.  That made full scanner execution weaker
    than the detection harness.  The scanner now owns the same semantic path so
    Unity full scans produce the intended malicious-chain tags.
    """
    tags = ['unity']
    try:
        data = read_bytes(path)
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        log_error(scanner_contract_join('scan_unity_file input read failed: ', scanner_contract_error_message(exc)))
        return ordered_unique_tags(scanner_failure_tags('scan_unity_file.read', exc, tags))
    low_data = data.lower()
    text = data.decode('latin1', errors='ignore')
    if b'il2cpp' in low_data:
        tags.append('il2cpp')
    if b'mono' in low_data:
        tags.append('mono_runtime')
    if b'assembly-csharp' in low_data:
        tags.append('unity_managed')
    try:
        tags.extend(sorted(detect_unity_runtime_behavior(text)))
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        record_detector_error('unity_runtime_behavior', exc, path=path)
        tags.extend(scanner_failure_tags('scan_unity_file.runtime_behavior', exc, tags))
    try:
        verdict = engine_threat_evaluator(text, path=str(path), engine='unity')
        tags.extend(verdict.get('tags') or [])
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        record_detector_error('unity_game_engine_threats', exc, path=path)
        tags.extend(scanner_failure_tags('scan_unity_file.game_engine_threats', exc, tags))
    return ordered_unique_tags(tags)
