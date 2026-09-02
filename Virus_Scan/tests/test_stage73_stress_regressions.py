from Virus_Scan.routing.asset_triage import scan_media_asset_file
from Virus_Scan.scheduler.execution.raw_work_executor import execute_raw_callable
from Virus_Scan.scanners.strings import ScanStringsRequest, scan_strings
from Virus_Scan.runtime.runtime_economics_ledger import observe_runtime_economics, get_runtime_economics_ledger
from Virus_Scan.scanners.pickle_scan import detect_python_pickle_opcode_exec
from Virus_Scan.routing.magic import sniff_file_identity

def test_direct_import_media_asset_triage_helpers(tmp_path):
    p = tmp_path / 'asset.dat'
    p.write_bytes(b'abc')
    tags, suspicious = scan_media_asset_file(str(p))
    assert 'media_asset' in tags
    assert suspicious is False


def test_raw_work_executor_allows_scanner_path_kwarg(tmp_path):
    p = tmp_path / 'a.txt'
    p.write_text('hello http://example.com')
    env = execute_raw_callable(str(p), 'stress', scan_strings, ScanStringsRequest(p.read_text(), path=str(p), finalize=False))
    assert env.ok is True
    assert not isinstance(env.result, dict)
    assert tuple(env.result['result'])


def test_runtime_economics_ledger_records_direct_observation():
    before = get_runtime_economics_ledger().snapshot().get('execution_cost', 0.0)
    after = observe_runtime_economics('execution_cost', 1.25)
    assert after == before + 1.25


def test_renpy_pickle_scan_direct_import_defaults(tmp_path):
    payload = b'\x80\x04cos\nsystem\nX\x04\x00\x00\x00calc\x85R.'
    tags = detect_python_pickle_opcode_exec(payload, ext='.rpyc')
    assert tags is not None


def test_routing_magic_direct_import_renpy_bytecode(tmp_path):
    p = tmp_path / 'script.rpyc'
    p.write_bytes(b'RENPY RPC2\x00\x00')
    ident = sniff_file_identity(str(p))
    assert ident['magic_type'] == 'renpy_rpyc'
    assert 'renpy_bytecode' in ident['tags']
