from pathlib import Path

from Virus_Scan.contracts.unity_behavior import detect_unity_runtime_behavior
from Virus_Scan.models.graph import scan_cs
from Virus_Scan.runtime.api import detect_unity_runtime_behavior as runtime_unity_behavior


def test_neutral_unity_behavior_contract_is_canonical_semantic_owner():
    text = 'void Awake() { Process.Start("cmd.exe"); DownloadString(url); }'
    assert detect_unity_runtime_behavior(text) == (
        'network_download',
        'process_exec',
        'unity_lifecycle',
    )
    assert runtime_unity_behavior(text) == detect_unity_runtime_behavior(text)


def test_model_graph_uses_unity_contract_without_runtime_scan_dependency_import():
    graph_source = '\n'.join(path.read_text(encoding='utf-8') for path in sorted(Path('Virus_Scan/models/graph').glob('*.py')))
    assert 'detect_unity_runtime_behavior' in graph_source
    assert 'from Virus_Scan.runtime.scan_dependencies import' not in graph_source
    assert 'from Virus_Scan.contracts.telemetry import log_error, record_detector_error' in graph_source
    assert 'from Virus_Scan.contracts.unity_behavior import detect_unity_runtime_behavior' in graph_source
    assert 'detect_unity_runtime_behavior,' not in graph_source


def test_graph_scan_cs_preserves_unity_behavior_tags_through_contract(tmp_path):
    sample = tmp_path / 'Sample.cs'
    sample.write_text('public class Sample { void Awake() { Process.Start("cmd.exe"); } }', encoding='utf-8')
    result = scan_cs(sample)
    tags = set(result if isinstance(result, list) else result.get('tags', []))
    assert 'unity_lifecycle' in tags
    assert 'process_exec' in tags
