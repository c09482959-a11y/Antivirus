from pathlib import Path
import pickle
import zlib

from Virus_Scan.scanners.pickle import payload_compressed_records, payload_literal_records, payload_opcode_records, payload_records
from Virus_Scan.scanners.pickle import rpyc_chunks, rpyc_compression, rpyc_emit, rpyc_views


def test_phase8_rpyc_view_facade_delegates_to_bounded_modules():
    assert rpyc_views._iter_renpy_rpc_chunks is rpyc_chunks._iter_renpy_rpc_chunks
    assert rpyc_views._iter_pickle_compressed_views is rpyc_compression._iter_pickle_compressed_views
    assert rpyc_views._pickle_container_magic_present is rpyc_chunks._pickle_container_magic_present
    assert rpyc_views._pickle_view_emit is rpyc_emit._pickle_view_emit


def test_phase8_payload_record_facade_delegates_to_bounded_modules():
    assert payload_records._try_decode_pickle_literal is payload_literal_records._try_decode_pickle_literal
    assert payload_records._iter_pickle_payload_records is payload_opcode_records._iter_pickle_payload_records
    assert payload_records._iter_raw_compressed_payload_records is payload_compressed_records._iter_raw_compressed_payload_records


def test_phase8_split_modules_preserve_payload_and_rpyc_behavior():
    raw_pickle = pickle.dumps(b"powershell cmd.exe")
    opcode_records = list(payload_records._iter_pickle_payload_records(raw_pickle))
    assert opcode_records
    assert any("powershell" in str(record.get("text", "")).lower() for record in opcode_records)

    compressed = zlib.compress(raw_pickle)
    views = list(rpyc_views._iter_pickle_compressed_views(compressed, kind_prefix="stage865"))
    assert views
    assert any(bytes(payload).startswith(b"\x80") for _kind, payload in views)


def test_phase8_remaining_pickle_modules_are_bounded_after_split():
    max_lines = {
        "Virus_Scan/scanners/pickle/rpyc_views.py": 130,
        "Virus_Scan/scanners/pickle/payload_records.py": 40,
        "Virus_Scan/scanners/pickle/payload_literal_records.py": 110,
        "Virus_Scan/scanners/pickle/payload_opcode_records.py": 90,
        "Virus_Scan/scanners/pickle/payload_compressed_records.py": 70,
        "Virus_Scan/scanners/pickle/rpyc_chunks.py": 90,
        "Virus_Scan/scanners/pickle/rpyc_compression.py": 90,
        "Virus_Scan/scanners/pickle/rpyc_emit.py": 70,
    }
    for rel, limit in max_lines.items():
        assert len(Path(rel).read_text(encoding="utf-8").splitlines()) <= limit, rel


def test_phase8_pickle_opcode_iteration_has_single_scanner_owned_authority():
    allowed = {
        Path("Virus_Scan/scanners/pickle/opcode_analysis.py"),
        Path("Virus_Scan/scanners/pickle/payload_opcode_records.py"),
    }
    offenders = []
    for path in Path("Virus_Scan/scanners").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "pickletools.genops" in text and path not in allowed:
            offenders.append(path.as_posix())
    assert offenders == []
