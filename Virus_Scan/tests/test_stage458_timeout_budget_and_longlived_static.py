from Virus_Scan.scanners.binary_raw_escalation import _umige_raw_should_escalate_after_triage_inmemory
from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


def test_inmemory_raw_escalation_has_static_anchor_owner(tmp_path):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"MZ" + b"0" * 128)
    result = _umige_raw_should_escalate_after_triage_inmemory(
        str(target),
        ["ordinary_binary_context"],
        False,
        {},
        "binary",
    )
    assert result is False


def test_large_image_header_increases_timeout_budget(tmp_path):
    large = tmp_path / "large.png"
    large.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + (8000).to_bytes(4, "big")
        + (6000).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"0" * 32
    )
    small = tmp_path / "small.png"
    small.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + (32).to_bytes(4, "big")
        + (32).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"0" * 32
    )
    large_budget = compute_timeout_budget(large, configured_timeout_seconds=20)
    small_budget = compute_timeout_budget(small, configured_timeout_seconds=20)
    assert large_budget.image_pixels == 48_000_000
    assert large_budget.hard_timeout_seconds > small_budget.hard_timeout_seconds
