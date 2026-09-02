from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives, pickle_scan
from Virus_Scan.scanners.ci.pickle_boundary_audit import run_pickle_boundary_audit


def test_phase8_pickle_boundary_audit_is_clean():
    result = run_pickle_boundary_audit(Path('.'))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 30


def test_pickle_scan_is_public_facade_without_function_ownership():
    assert pickle_scan.__all__
    assert 'pickle_fast_escalation_prefilter' in pickle_scan.__all__
    assert not [name for name, value in vars(pickle_scan).items() if callable(value) and getattr(value, '__module__', '') == pickle_scan.__name__]


def test_archive_package_replaces_oversized_archive_module(tmp_path):
    assert not Path('Virus_Scan/scanners/archives.py').exists()
    assert Path('Virus_Scan/scanners/archives').is_dir()
    sample = tmp_path / 'sample.zip'
    with zipfile.ZipFile(sample, 'w') as archive:
        archive.writestr('payload.dll', b'MZ' + (b'\x00' * 128))
    tags, suspicious = archives.scan_archive_file(str(sample))
    assert suspicious
    assert 'zip_archive' in tags
    assert any(str(tag).startswith('archive_inner:') for tag in tags)


def test_rpa_scanner_boundary_still_reports_pickle_payload(tmp_path):
    sample = tmp_path / 'sample.rpa'
    sample.write_bytes(b'RPA-3.0 00000010 00000000\nrenpy pickle python exec(')
    tags, suspicious = archives.scan_rpa_file(str(sample))
    assert suspicious
    assert 'rpa_archive' in tags
    assert 'renpy_python_payload_reference' in tags
