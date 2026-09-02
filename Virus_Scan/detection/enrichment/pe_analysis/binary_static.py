"""Canonical detection classification owner for binary static tag extraction."""

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.enrichment.strings.contextual.scan import (
    ContextualTagScanRequest,
    contextual_tag_scan,
)
from Virus_Scan.detection.enrichment.pe_analysis.static_payload import scan_static_payload_anomalies
from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.contracts.progress import stage_progress as report_scan_stage_progress, has_any_tag
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage


def _finish_binary_tags(tags: object, path: object, combined_text: object, finalize: object) -> object:
    if finalize:
        generation = finalize_tag_evidence_generation(
            tags, path=path, strings_blob=combined_text, source='binary',
        )
        return list(generation.evidence.tags)
    return list(tags or [])


def scan_binary(path: object, *, artifact_read_snapshot: object, finalize: object=True) -> object:
    """
    Static byte/string scanner with concrete evidence preservation.

    The canonical artifact snapshot is the only byte-acquisition owner.
    finalize=False is used by stage-parallel collectors so this function
    returns raw evidence tags only. The central router/analyzer remains the
    only owner of final tag finalization, behavior timeline construction,
    graph/Markov/temporal/vector/cluster/profile updates, and scoring.
    """
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    tags = []
    combined_text = ""
    try:
        report_scan_stage_progress('binary_scan_start')
        if not snapshot.complete:
            tags.extend(failure_tags_for_stage(
                'binary_static_scan', 'binary_input_unavailable', context=path,
            ))
            return _finish_binary_tags(tags, path, combined_text, finalize)
        size = min(snapshot.size, 10 * 1024 * 1024)
        if size <= 0:
            tags.extend(failure_tags_for_stage('binary_static_scan', 'binary_input_empty', context=path))
            return _finish_binary_tags(tags, path, combined_text, finalize)
        data = snapshot.read_prefix(size)
        if len(data) != size:
            tags.extend(failure_tags_for_stage('binary_static_scan', 'binary_snapshot_view_incomplete', context=path))
            return _finish_binary_tags(tags, path, combined_text, finalize)
        try:
            text_latin = data.decode('latin1', errors='ignore').lower()
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
            tags.extend(failure_tags_for_stage('binary_latin1_decode', e, context=path))
            text_latin = ''
        finally:
            pass
        try:
            text_utf16 = data.decode('utf-16le', errors='ignore').lower()
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
            tags.extend(failure_tags_for_stage('binary_utf16_decode', e, context=path))
            text_utf16 = ''
        finally:
            pass
        combined_text = text_latin + '\n' + text_utf16
        tags.extend(contextual_tag_scan(ContextualTagScanRequest(
            strings_blob=combined_text,
            path=path,
            source="binary",
            data=data,
            finalize=False,
        )))
        tags.extend(scan_static_payload_anomalies(path, data=data, strings_blob=combined_text))
        if data.startswith(b'MZ'):
            tags.append('pe_file')
            if {'remote_command_channel', 'network_c2'} & set(tags) and {'network_activity', 'backdoor_or_c2', 'c2_beacon'} & set(tags):
                tags.append('confirmed_pe_command_channel_evidence')
            if 'powershell_exec' in set(tags) and ('http://' in combined_text or 'https://' in combined_text or 'url_present' in set(tags) or 'network_activity' in set(tags)):
                tags.append('confirmed_pe_powershell_network_evidence')
        ext = get_scan_extension(path)
        if ext == '.exe':
            tags.append('pe_exe')
        elif ext == '.dll':
            tags.append('pe_dll')
            tags.append('dll_file')
        if 'writeprocessmemory' in combined_text:
            tags += ['memory_write']
        if 'virtualprotect' in combined_text:
            tags += ['memory_protect']
        if 'virtualalloc' in combined_text:
            tags += ['memory_allocate']
        if 'createremotethread' in combined_text or 'ntcreatethreadex' in combined_text:
            tags += ['thread_execution']
        if has_any_tag(tags, 'memory_write') and has_any_tag(tags, 'thread_execution'):
            tags.append('process_injection')
        elif has_any_tag(tags, 'memory_write') and has_any_tag(tags, 'memory_protect') and has_any_tag(tags, 'thread_execution'):
            tags.append('process_injection')
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        tags.extend(failure_tags_for_stage('binary_static_scan', e, context=path))
    finally:
        pass
    return _finish_binary_tags(tags, path, combined_text, finalize)
