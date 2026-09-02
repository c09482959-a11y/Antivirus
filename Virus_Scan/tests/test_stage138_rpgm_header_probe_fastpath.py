import json
from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.scheduler.queue.admission import classify_workload
from Virus_Scan.scheduler.queue.workload_identity import _sniff_workload_identity
from Virus_Scan.routing.magic import sniff_file_identity
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.utils.fast_assets import probe_rpgm_encrypted_header


def _encrypted_rpgm_asset(root: Path, rel: str, plain_header: bytes, key_hex: str = "00112233445566778899aabbccddeeff") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "data" / "System.json").write_text(json.dumps({"encryptionKey": key_hex}), encoding="utf-8")
    key = bytes.fromhex(key_hex)
    plain = plain_header[:16].ljust(16, b"\0")
    enc = bytes(b ^ key[i] for i, b in enumerate(plain))
    p.write_bytes(b"RPGMV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + enc + b"payload")
    return p


def test_rpgm_header_probe_recovers_png_without_full_decrypt(tmp_path):
    p = _encrypted_rpgm_asset(tmp_path, "img/characters/Hero.png_", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    header = p.read_bytes()[:64]
    probe = probe_rpgm_encrypted_header(p, header, ext=".png_")
    assert probe["is_rpgm_encrypted"] is True
    assert probe["key_found"] is True
    assert probe["recovered_type"] == "png"
    assert probe["recovered_header"].startswith(b"\x89PNG\r\n\x1a\n")


def test_rpgm_encrypted_png_routes_image_fast_not_generic(tmp_path):
    p = _encrypted_rpgm_asset(tmp_path, "img/pictures/Scene.png_", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    ident = _sniff_workload_identity(p)
    assert ident["magic_type"] == "rpgm_mv_encrypted_asset"
    assert "rpgm_recovered_magic_png" in ident["tags"]
    assert classify_workload(p) == "image"


def test_rpgm_encrypted_image_without_key_still_fast_passive(tmp_path):
    p = tmp_path / "img" / "characters" / "NoKey.png_"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"RPGMV\x00\x00\x00" + b"x" * 64)
    ident = sniff_file_identity(p)
    assert ident["magic_stage"] == "asset"
    assert "rpgm_header_recovery_key_missing" in ident["tags"]
    assert "rpgm_encrypted_image" in ident["tags"]
    assert classify_workload(p) == "image"


def test_rpgm_encrypted_scan_file_by_type_terminal_fast_path(tmp_path):
    p = _encrypted_rpgm_asset(tmp_path, "img/characters/Hero.png_", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    tags, suspicious = scan_file_by_type(str(p), scan_session_snapshot=scan_session_snapshot_fixture(), artifact_read_snapshot=artifact_read_snapshot_fixture(p))
    tagset = set(tags)
    assert suspicious is False
    assert "asset_fast_triage" in tagset
    assert "asset_fast_triage_clean" in tagset or "image_fast_triage_clean" in tagset
    assert "binary_failover_scan" not in tagset
    assert "asset_extension_magic_mismatch" not in tagset
