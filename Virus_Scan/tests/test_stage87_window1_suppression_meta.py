import json
from pathlib import Path

from Virus_Scan.core import jsonio


def test_yara_download_meta_corruption_is_quarantined(tmp_path):
    dest = tmp_path / "rules.zip"
    meta = tmp_path / "rules.zip.meta.json"
    meta.write_text('{bad json', encoding='utf-8')
    data = jsonio._read_download_meta(str(dest), download_meta_path=lambda d: str(meta))

    assert data == {}
    assert not meta.exists()
    quarantined = list(tmp_path.glob('rules.zip.meta.json.corrupt*'))
    assert quarantined, 'corrupt metadata should be preserved as quarantine evidence'


def test_write_download_meta_returns_false_on_atomic_failure(tmp_path):
    dest = tmp_path / "rules.zip"
    meta = tmp_path / "rules.zip.meta.json"
    assert jsonio._write_download_meta(
        str(dest),
        {'checked_at': 1},
        download_meta_path=lambda d: str(meta),
        atomic_json_save_func=lambda *a, **k: (_ for _ in ()).throw(OSError('sync failed')),
    ) is False


def test_write_download_meta_returns_true_on_success(tmp_path):
    dest = tmp_path / "rules.zip"
    meta = tmp_path / "rules.zip.meta.json"
    assert jsonio._write_download_meta(str(dest), {'checked_at': 1}, download_meta_path=lambda d: str(meta)) is True
    data = json.loads(meta.read_text(encoding='utf-8'))
    assert int(data['checked_at']) == 1
    assert 'updated' in data
