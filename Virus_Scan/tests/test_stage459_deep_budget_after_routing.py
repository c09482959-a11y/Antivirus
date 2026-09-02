from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


def _write_png_header(path, width=32, height=32):
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + (13).to_bytes(4, "big")
        + b"IHDR"
        + int(width).to_bytes(4, "big")
        + int(height).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"0" * 32
    )


def test_deep_image_budget_exceeds_fast_triage_budget(tmp_path):
    target = tmp_path / "payload.png"
    _write_png_header(target)
    fast = compute_timeout_budget(target, configured_timeout_seconds=20, method="routing_triage")
    deep = compute_timeout_budget(
        target,
        configured_timeout_seconds=20,
        method="deep_image_scan",
        tags=["asset_embedded_payload_signature", "possible_appended_payload"],
        deep_scan=True,
    )
    assert fast.workload_class == "image_fast_triage"
    assert deep.workload_class == "deep_image_scan"
    assert deep.hard_timeout_seconds > fast.hard_timeout_seconds
    assert deep.stall_timeout_seconds > fast.stall_timeout_seconds
