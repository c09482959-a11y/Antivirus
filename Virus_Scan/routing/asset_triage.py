from pathlib import Path

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import deep_scan_auto_enabled, ensure_graph_node, log_error, record_suppressed_failure, report_scan_stage_progress, scan_strings
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.utils.stages import MEDIA_AUDIO_EXTENSIONS, MEDIA_VIDEO_EXTENSIONS, get_scan_extension, sanitize_tag_part as _umige_sanitize_tag_part
from Virus_Scan.core.logging import _sample_file_prefix_suffix
from Virus_Scan.core.path_utils import core_path_text
from Virus_Scan.contracts.detection_observation import artifact_observations_for_path_tags
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.routing.magic import expected_magic_mismatch, sniff_file_identity
from Virus_Scan.scanners.api.binary_contracts import validated_embedded_payload_hits as _validated_embedded_payload_hits
from Virus_Scan.scanners.api.entropy_contracts import byte_entropy
from Virus_Scan.detection.api.routing_contracts import (
    emit_stage_event,
    finalize_tag_evidence_generation,
    remember_scan_evidence as _remember_scan_evidence,
)
from Virus_Scan.routing.extension_outcome import RouteScanOutcome

PLR2004N0_08 = 0.08
PLR2004N126 = 126
PLR2004N3 = 3
PLR2004N32 = 32
PLR2004N7_75 = 7.75
PLR2004N8192 = 8192

MEDIA_SUSPICIOUS_STRINGS = (b'<script', b'powershell', b'cmd.exe', b'http://', b'https://', b'base64', b'eval(')
EMBEDDED_PAYLOAD_SIGNATURES = ((b'MZ', 'embedded_pe_signature'), (b'PK\x03\x04', 'embedded_zip_signature'), (b"7z\xbc\xaf'\x1c", 'embedded_7z_signature'), (b'Rar!\x1a\x07', 'embedded_rar_signature'))


def _asset_exception_text(prefix: object, exc: object) -> object:
    return str.__add__(prefix, no_hook_type_name(exc))


def _asset_bytes(value: object) -> object:
    if type(value) is bytes:
        return value
    if type(value) is bytearray:
        return bytes(value)
    if type(value) is memoryview:
        return bytes(value)
    return b''


def _asset_size(value: object) -> object:
    size, reason = no_hook_exact_nonnegative_int(value, default=0)
    return 0 if reason else size


def _asset_identity_snapshot(identity: object) -> object:
    if identity is None:
        return {}
    items = no_hook_mapping_items(identity)
    if items is None:
        return {
            'identity_unavailable_reason': 'asset_identity_rejected',
            'value_type': no_hook_type_name(identity),
        }
    return dict(items)


def _asset_identity_text(identity: object, key: object, default: object) -> object:
    value = dict.get(identity, key) if type(identity) is dict else None
    text, reason = no_hook_text(value, unsupported_reason=str.__add__(key, '_rejected'))
    if reason or text == '':
        return default
    return text


def _asset_identity_tag_values(identity: object) -> object:
    values = dict.get(identity, 'tags') if type(identity) is dict else None
    items = no_hook_sequence_items(values)
    if values is not None and not items and type(values) not in (tuple, list, set, frozenset):
        return ()
    return items


def _asset_ext_tag(prefix: object, ext: object) -> object:
    text, reason = no_hook_text(ext, unsupported_reason='asset_extension_rejected')
    suffix = 'unknown' if reason else _umige_sanitize_tag_part(text)
    return str.__add__(prefix, suffix)


def _record_suppressed_runtime(exc: BaseException) -> None:
    try:
        record_suppressed_failure('suppressed_exception', exc, domain='runtime')
    except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
        _ = _umige_reporting_exc


def _remember_asset_evidence(path: object, *, sample: object, strings_blob: object=None) -> None:
    try:
        kwargs = {'raw_sample': sample, 'triage_sampled': True}
        if strings_blob is not None:
            kwargs['strings_blob'] = strings_blob
        _remember_scan_evidence(path, **kwargs)
    except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
        _record_suppressed_runtime(_umige_suppressed_exc)


def _asset_identity_tags(identity: object, prefixes: object, exact: object=()) -> None:
    exact_set = set(exact or ())
    for tag in _asset_identity_tag_values(identity):
        text, reason = no_hook_text(tag, unsupported_reason='asset_identity_tag_rejected')
        if reason:
            continue
        if text.startswith(prefixes) or text in exact_set:  # small immutable filter, no state retained
            yield text


def _sample_bytes(path: object, *, prefix_size: object=None, suffix_size: object=None) -> object:
    if prefix_size is None and suffix_size is None:
        prefix, suffix, size = _sample_file_prefix_suffix(path)
    else:
        prefix, suffix, size = _sample_file_prefix_suffix(path, prefix_size=prefix_size, suffix_size=suffix_size)
    prefix_bytes = _asset_bytes(prefix)
    suffix_bytes = _asset_bytes(suffix)
    size_value = _asset_size(size)
    report_scan_stage_progress('media_sample' if prefix_size is None else 'font_sample', bytes_delta=size_value)
    return prefix_bytes + suffix_bytes, prefix_bytes, suffix_bytes, size_value


def _embedded_payload_flags(sample: object, tags: object, *, score: object=None) -> object:
    del score  # Explicitly unused contract parameters.
    suspicious = False
    for _offset, tag in _validated_embedded_payload_hits(sample, min_offset=32):
        tags += [tag, 'asset_embedded_payload_signature', 'asset_deep_scan_escalated']
        suspicious = True
    if any((marker in sample.lower() for marker in MEDIA_SUSPICIOUS_STRINGS)):
        tags += ['asset_embedded_script_or_url', 'embedded_command_or_url', 'asset_deep_scan_escalated']
        suspicious = True
    return suspicious


def scan_media_asset_file(path: object, identity: object=None) -> object:
    """Progressive media scan: cheap validation for every media file, deep escalation only on concrete red flags."""
    report_scan_stage_progress('media_triage_start')
    ext = get_scan_extension(path)
    identity = _asset_identity_snapshot(sniff_file_identity(path) if identity is None else identity)
    magic_type = _asset_identity_text(identity, 'magic_type', 'unknown').lower()
    id_tags = set(_asset_identity_tag_values(identity))
    tags = ['media_asset', 'asset_fast_triage', _asset_ext_tag('media_ext_', ext)]
    tags.extend(_asset_identity_tags(identity, ('magic_rpgm', 'rpgm_', 'filetype_'), {'rpgm', 'rpgm_resource', 'image_file', 'audio_file', 'media_file'}))
    suspicious = False
    escalate = False
    if ext in MEDIA_AUDIO_EXTENSIONS or 'rpgm_encrypted_audio' in id_tags:
        tags.append('audio_asset')
    elif ext in MEDIA_VIDEO_EXTENSIONS:
        tags.append('video_asset')
    elif 'rpgm_encrypted_image' in id_tags:
        tags.append('image_asset')
    rpgm_encrypted_passive = 'rpgm_encrypted_asset' in id_tags and ('rpgm_encrypted_image' in id_tags or 'rpgm_encrypted_audio' in id_tags)
    if not rpgm_encrypted_passive and (expected_magic_mismatch(ext, magic_type) or 'extension_mismatch' in id_tags):
        tags += ['asset_extension_magic_mismatch', 'asset_deep_scan_escalated']
        suspicious = True
        escalate = True
    else:
        tags.append('asset_magic_valid')
    sample, _prefix, suffix, _size = _sample_bytes(path)
    if rpgm_encrypted_passive:
        tags.append('rpgm_ciphertext_text_scan_suppressed')
    else:
        if _embedded_payload_flags(sample, tags):
            suspicious = True
            escalate = True
        if suffix and len(suffix) >= PLR2004N8192:
            printable = sum((1 for b in suffix if b in b'\r\n\t' or PLR2004N32 <= b <= PLR2004N126)) / float(max(1, len(suffix)))
            if printable < PLR2004N0_08 and byte_entropy(suffix) >= PLR2004N7_75:
                tags += ['asset_high_entropy_tail', 'possible_appended_payload', 'asset_deep_scan_escalated']
                suspicious = True
                escalate = True
    if escalate:
        if deep_scan_auto_enabled():
            tags.append('deep_scan_auto_escalated')
        _remember_asset_evidence(path, sample=sample, strings_blob=sample.decode('latin1', errors='ignore'))
    else:
        tags.append('asset_fast_triage_clean')
        report_scan_stage_progress('media_fast_clean')
        _remember_asset_evidence(path, sample=sample)
    return RouteScanOutcome(
        normalize_tags(tags),
        suspicious,
        _asset_identity_snapshot(identity),
        finalize_tag_evidence_generation(
            artifact_observations_for_path_tags(
                tags, producer_id="media_asset_triage", stage_id="scanner_output",
                path=path, modality="static_structure",
            ),
            path=path, source="media_asset_triage",
        ).evidence,
    )


def scan_passive_font_asset_file(path: object, identity: object=None) -> object:
    """Cheap passive font triage for game asset folders."""
    report_scan_stage_progress('font_triage_start')
    ext = get_scan_extension(path)
    identity = _asset_identity_snapshot(sniff_file_identity(path) if identity is None else identity)
    magic_type = _asset_identity_text(identity, 'magic_type', 'unknown').lower()
    id_tags = set(_asset_identity_tag_values(identity))
    tags = ['font_asset', 'asset_fast_triage', _asset_ext_tag('font_ext_', ext)]
    tags.extend(_asset_identity_tags(identity, ('magic_', 'filetype_', 'extension_', 'actual_stage_', 'claimed_stage_', 'magic_type_', 'observed_stage_')))
    suspicious = False
    escalate = False
    if expected_magic_mismatch(ext, magic_type) or 'extension_mismatch' in id_tags:
        tags += ['asset_extension_magic_mismatch', 'asset_deep_scan_escalated']
        suspicious = True
        escalate = True
    else:
        tags.append('asset_magic_valid')
    sample, _prefix, _suffix, _size = _sample_bytes(path, prefix_size=65536, suffix_size=65536)
    if _embedded_payload_flags(sample, tags):
        suspicious = True
        escalate = True
    if escalate:
        _remember_asset_evidence(path, sample=sample, strings_blob=sample.decode('latin1', errors='ignore'))
    else:
        tags += ['font_fast_triage_clean', 'passive_asset_fast_triage_clean', 'asset_fast_triage_clean']
        report_scan_stage_progress('font_fast_clean')
        _remember_asset_evidence(path, sample=sample)
    return RouteScanOutcome(
        normalize_tags(tags),
        suspicious,
        _asset_identity_snapshot(identity),
        finalize_tag_evidence_generation(
            artifact_observations_for_path_tags(
                tags, producer_id="font_asset_triage", stage_id="scanner_output",
                path=path, modality="static_structure",
            ),
            path=path, source="font_asset_triage",
        ).evidence,
    )


def _unity_sample(file: object, sampled: object) -> object:
    if sampled is None:
        prefix, suffix, size = _sample_file_prefix_suffix(file, prefix_size=262144, suffix_size=262144)
        return _asset_bytes(prefix), _asset_bytes(suffix), _asset_size(size)
    result = (b'', b'', 0)
    try:
        items = no_hook_sequence_items(sampled)
        if len(items) >= PLR2004N3:
            prefix, suffix, size = items[:3]
            result = (_asset_bytes(prefix), _asset_bytes(suffix), _asset_size(size))
    except RECOVERABLE_RUNTIME_ERRORS:
        result = (b'', b'', 0)
    return result


def _add_unity_header_tags(tags: object, prefix: object) -> None:
    if prefix.startswith((b'UnityFS', b'UnityRaw', b'UnityWeb')):
        tags.add('unity_assetbundle_header')
    if prefix.startswith(b'UnityWebData1.0'):
        tags.add('unity_webdata_header')
    if prefix.startswith(b'CAB-') or b'CAB-' in prefix[:128]:
        tags.add('unity_cab_serialized_asset')


def _add_unity_payload_flags(tags: object, sample: object) -> object:
    score = 0.0
    escalate = False
    low = sample.lower()
    for sig, tag in EMBEDDED_PAYLOAD_SIGNATURES:
        off = sample.find(sig)
        if off > PLR2004N32:
            tags.update({tag, 'asset_embedded_payload_signature', 'asset_deep_scan_escalated'})
            score += 10.0
            escalate = True
    if any((marker in low for marker in MEDIA_SUSPICIOUS_STRINGS)):
        tags.update({'asset_embedded_script_or_url', 'embedded_command_or_url', 'asset_deep_scan_escalated'})
        score += 6.0
        escalate = True
    return score, escalate


def _add_unity_entropy_tag(tags: object, sample: object) -> object:
    try:
        sample_entropy = byte_entropy(sample) if sample else 0.0
        if sample_entropy >= PLR2004N7_75:
            tags.add('high_entropy_asset_container')
            return 1.0
    except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
        _record_suppressed_runtime(_umige_suppressed_exc)
    return 0.0


def scan_unity_asset_file(file: object, identity: object=None, sampled: object=None) -> object:
    """Progressive Unity asset/container triage."""
    ensure_graph_node(file)
    tags = {'unity_asset', 'unity_container_asset', 'asset_container_fast_triage'}
    score = 0.0
    file_text, file_reason = core_path_text(file, field_name='unity_asset_path', allow_empty=True)
    ext = Path(file_text).suffix.lower() if not file_reason and file_text else ''
    if ext:
        tags.add(_asset_ext_tag('unity_asset_ext_', ext))
    if identity is None:
        try:
            identity = sniff_file_identity(file)
        except RECOVERABLE_RUNTIME_ERRORS:
            identity = {'tags': [], 'magic_type': 'unknown'}
    identity = _asset_identity_snapshot(identity)
    id_tags = set(_asset_identity_tag_values(identity))
    tags.update(_asset_identity_tags(identity, ('magic_unity', 'filetype_', 'extension_', 'actual_stage_', 'claimed_stage_', 'magic_type_', 'observed_stage_')))
    prefix, suffix, _size = _unity_sample(file, sampled)
    sample = prefix + suffix
    _add_unity_header_tags(tags, prefix)
    if expected_magic_mismatch(ext, _asset_identity_text(identity, 'magic_type', 'unknown')) or 'extension_mismatch' in id_tags:
        tags.update({'asset_extension_magic_mismatch', 'asset_deep_scan_escalated'})
        score += 8.0
        escalate = True
    else:
        escalate = False
    payload_score, payload_escalate = _add_unity_payload_flags(tags, sample)
    score += payload_score
    escalate = escalate or payload_escalate
    score += _add_unity_entropy_tag(tags, sample)
    if escalate:
        try:
            text = sample.decode('latin1', errors='ignore')
            tags.update(scan_strings(text, path=file))
            tags.add('asset_sample_strings_scanned')
            _remember_asset_evidence(file, sample=sample, strings_blob=text)
        except RECOVERABLE_RUNTIME_ERRORS as e:
            log_error(_asset_exception_text('handled exception in unity asset triage string scan: ', e))
    else:
        tags.add('unity_container_fast_triage_clean')
        tags.add('asset_fast_triage_clean')
        _remember_asset_evidence(file, sample=sample)
    tags = set(normalize_tags(tags))
    emit_stage_event(file, 'asset', list(tags))
    return (list(tags), float(score))
