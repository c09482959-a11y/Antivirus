from __future__ import annotations

from pathlib import Path
import re
from types import MappingProxyType

from Virus_Scan.contracts.detection_observation import artifact_observations_for_path_tags
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.contracts.unity_behavior import detect_unity_runtime_behavior
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.api.tag_evidence_contracts import normalize_tag_evidence
from Virus_Scan.utils.entropy import shannon_entropy_bytes
from Virus_Scan.models.graph.common import (
    safe_graph_text,
    safe_graph_text_with_reason,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.method_graph import add_method_node, build_method_graph, extract_calls, extract_methods
from Virus_Scan.models.graph.stage import emit_stage_event
from Virus_Scan.models.graph.state import add_graph_edge, ensure_graph_node
from Virus_Scan.runtime.graph_state import update_graph_node_owned

PLR2004N6_5 = 6.5
PLR2004N7_8 = 7.8

_CS_GRAPH_REGEX_TAGS = MappingProxyType({
    'process_exec': r'\b(?:Process\.Start|System\.Diagnostics\.Process)\b',
    'network_download': r'\b(?:WebClient|HttpClient|DownloadString|DownloadData|UnityWebRequest)\b',
    'native_interop': r'\b(?:DllImport|LoadLibrary|GetProcAddress)\b',
    'registry_modification': r'\b(?:RegistryKey|Microsoft\.Win32\.Registry)\b',
    'reflection': r'\b(?:GetMethod|InvokeMember|Activator\.CreateInstance)\b',
})

def _ordered_graph_tags(tags: object) -> object:
    ordered = []
    for tag in tags:
        text, reason = safe_graph_text_with_reason(tag, 'graph_tag_unavailable')
        if reason == '' and text != '':
            ordered.append(text)
    return sorted(ordered)

def _scan_path_input(value: object) -> object:
    if isinstance(value, Path):
        return value, str(value), ''
    text, reason = safe_graph_text_with_reason(value, 'graph_cs_path_unavailable')
    if reason != '':
        return None, '', reason
    try:
        return Path(text), text, ''
    except RECOVERABLE_RUNTIME_ERRORS:
        return None, '', 'graph_cs_path_unavailable'

def _graph_regex_matches(pattern: object, text: object) -> bool:
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(
            graph_exception_message(
                'graph regex tag evaluation failed without synthetic substitute: ',
                exc,
            )
        )
        return False


def _regex_graph_tags(text: object) -> object:
    tags = set()
    items = no_hook_mapping_items(_CS_GRAPH_REGEX_TAGS)
    if items is None:
        return tags
    for tag, pattern in items:
        if _graph_regex_matches(pattern, text):
            tags.add(tag)
    return tags

def scan_cs(file: object) -> object:
    source_path, file_text, path_reason = _scan_path_input(file)
    if path_reason != '' or source_path is None:
        return ['graph_cs_scan_unavailable']
    ensure_graph_node(file_text)
    try:
        raw_source = source_path.read_bytes()
        text = raw_source.decode(errors='ignore')
    except RECOVERABLE_RUNTIME_ERRORS as e:
        log_error(graph_exception_message('graph analysis step failed without synthetic substitute: ', e))
        return ['graph_cs_scan_unavailable']
    tags = _regex_graph_tags(text)
    if 'eval(' in text or 'exec(' in text:
        tags.add('dynamic_code')
    if 'FromBase64String' in text or 'Convert.FromBase64String' in text:
        tags.add('base64')
    if 'Assembly.Load' in text and ('byte[]' in text or 'FromBase64String' in text):
        tags.add('memory_dll_loader')
        tags.add('assembly_load')
    tags.update(detect_unity_runtime_behavior(text))
    entropy_score = shannon_entropy_bytes(raw_source)
    if entropy_score > PLR2004N7_8:
        tags.add('high_entropy_code')
    elif entropy_score > PLR2004N6_5:
        tags.add('medium_entropy_code')
    observations = artifact_observations_for_path_tags(
        sorted(tags),
        producer_id="graph_scan",
        stage_id="csharp",
        path=file_text,
        strings_blob=text,
        modality="static_structure",
    )
    tag_evidence = normalize_tag_evidence(
        observations, source_detector='graph_scan', source_stage='csharp', derive=False,
    )
    ordered_tags = _ordered_graph_tags(tag_evidence.tags)
    update_graph_node_owned(file_text, tag_evidence_records=tag_evidence.records)
    for t in ordered_tags:
        try:
            add_graph_edge(file_text, t, edge_type='tag', weight=1.0)
        except TypeError:
            add_graph_edge(file_text, t)
        except RECOVERABLE_RUNTIME_ERRORS as e:
            log_error(graph_exception_message('graph analysis step failed without synthetic substitute: ', e))
            continue
    methods = extract_methods(text)
    method_items = no_hook_mapping_items(methods)
    if method_items is None:
        method_items = ()
    for mname, body in method_items:
        fid = file_text + '::' + safe_graph_text(mname)
        calls = extract_calls(body)
        update_graph_node_owned(fid, tag_evidence_records=tag_evidence.records)
        add_method_node(fid, ordered_tags, calls)
    if methods:
        build_method_graph(file_text, methods)
    emit_stage_event(file_text, 'cs', ordered_tags)
    return ordered_tags

__all__ = ('scan_cs',)
