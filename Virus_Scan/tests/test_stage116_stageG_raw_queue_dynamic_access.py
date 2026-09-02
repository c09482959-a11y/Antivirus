from dataclasses import replace
import ast
import inspect

from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as rq
from Virus_Scan.scheduler.queue import issue_reporting as queue_support
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.scanners.text_contextual_tags import contextual_tag_scan
from Virus_Scan.scheduler.workers import inmemory_raw_scan as imrs
from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.context.inmemory_raw_dependency_factory import inmemory_raw_scan_dependencies
from Virus_Scan.scanners import raw_chunk_collectors as rcp


def test_stage116_canonical_raw_dependency_factory_dynamic_access_removed():
    src = inspect.getsource(rq)
    tree = ast.parse(src)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'globals', 'locals'}:
            line = src.splitlines()[node.lineno - 1].strip()
            if 'from_namespace(globals())' in line:
                continue
            if line.startswith('bind_process_queue_state_runtime(globals())'):
                continue
            if line.startswith('bind_worker_policy_runtime(globals())'):
                continue
            offenders.append((node.lineno, line))
    assert offenders == []

def test_stage116_raw_queue_explicit_dependencies_available():
    for name in (
        'explicit_missed_family_tag_scan', 'umige_js_execution_model_tags',
        'yara_scan_with_optional_zip', 'yara_scan', 'yara_parallel_group_count',
        'global_raw_pe_api_header', 'global_raw_pure_pe_header', 'scan_dotnet_file',
        'scan_rpgm_file', 'detect_python_pickle_opcode_exec', 'sniff_file_identity',
        'normalize_stage', 'choose_effective_stage', '_global_raw_file_id',
        '_raw_stage_cache_key', 'raw_stage_cache_allowed',
    ):
        assert hasattr(raw_deps, name), name



def test_stage116_bytecode_collector_uses_explicit_pickle_dependency(tmp_path):
    f = tmp_path / 'sample.py'
    f.write_text('pickle.loads(data)', encoding='utf-8')
    out = rcp.bytecode_chunk(
        rcp.BytecodeChunkRequest(
            str(f),
            0,
            4096,
            raw_deps._global_raw_read_range_text,
            get_scan_extension,
            lambda text, ext=None: ['stage116_pickle_called'],
            lambda text: False,
            contextual_tag_scan,
            lambda tags, collector, exc, **kw: raw_deps._raw_collector_context_failure_impl(tags, collector, exc, **kw),
            queue_support._stage113_record_process_queue_suppressed,
            RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        )
    )
    assert 'stage116_pickle_called' in out['tags']


def test_stage116_inmemory_raw_uses_explicit_routing_dependencies(tmp_path):
    f = tmp_path / 'sample.bin'
    f.write_bytes(b'MZ' + b'X' * 128)
    calls = []
    deps = replace(
        inmemory_raw_scan_dependencies(),
        sniff_file_identity=lambda path: calls.append('sniff') or {'tags': ['identity_called']},
        choose_effective_stage=lambda ext_stage, identity: calls.append('choose') or 'binary',
        build_raw_stage_jobs=lambda *a, **k: [],
    )
    assert imrs.scan_file_inmemory_raw(str(f), pretriage_suspicious=True, deps=deps) is None
    assert calls == ['sniff', 'choose']
