from pathlib import Path

from Virus_Scan.routing.magic import sniff_file_identity
from Virus_Scan.scanners.rpgm import scan_rpgm_file
from Virus_Scan.utils.fast_assets import recover_rpgm_encrypted_sample


def _write_rpgm_asset(root: Path, name: str, plaintext: bytes, key_hex: str) -> Path:
    key = bytes.fromhex(key_hex)
    system = root / "www" / "data" / "System.json"
    system.parent.mkdir(parents=True)
    system.write_text('{"encryptionKey":"' + key_hex + '"}', encoding="utf-8")
    encrypted_head = bytes(plaintext[i] ^ key[i] for i in range(16))
    path = root / "www" / "img" / "pictures" / name
    path.parent.mkdir(parents=True)
    path.write_bytes(b"RPGMV" + b"\x00" * 11 + encrypted_head + plaintext[16:])
    return path


def test_rpgm_encrypted_media_decrypted_sample_exposes_payload_evidence(tmp_path: Path):
    key = "00112233445566778899aabbccddeeff"
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"IEND\xaeB`\x82" + b" powershell -enc AAAA cmd.exe certutil http://evil/payload"
    p = _write_rpgm_asset(tmp_path, "evil.rpgmvp", png, key)

    recovered = recover_rpgm_encrypted_sample(p, header=p.read_bytes()[:64], ext=".rpgmvp")
    assert recovered["sample"].startswith(b"\x89PNG\r\n\x1a\n")
    assert "rpgm_decrypted_sample_available" in recovered["tags"]

    tags = set(scan_rpgm_file(str(p)))
    assert "rpgm_decrypted_media_suspicious_string" in tags
    assert "rpgm_decrypted_media_url_reference" in tags
    assert "embedded_command_or_url" in tags


def test_mislabeled_rpgm_encrypted_asset_uses_magic_identity_not_suffix(tmp_path: Path):
    key = "00112233445566778899aabbccddeeff"
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    p = _write_rpgm_asset(tmp_path, "sprite.bin", png, key)

    ident = sniff_file_identity(str(p))
    assert ident["magic_type"] == "rpgm_mv_encrypted_asset"
    assert "magic_rpgm_encrypted_asset" in ident["tags"]
    assert "rpgm_recovered_magic_png" in ident["tags"]
