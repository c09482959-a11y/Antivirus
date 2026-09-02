from __future__ import annotations

from contextlib import contextmanager, ExitStack
from types import ModuleType
from typing import Any, Iterator

import Virus_Scan.scanners.image_jpeg_segments as jpeg_segments_module
import Virus_Scan.scanners.image_lsb as lsb_module
import Virus_Scan.scanners.image_lsb_payload as lsb_payload_module
import Virus_Scan.scanners.image_png_chunks as png_chunks_module
import Virus_Scan.scanners.image_scan as image_scan_module
import Virus_Scan.scanners.image_stego as image_stego_module
from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.scanners.ilspy import unity_ilspy_should_run
from Virus_Scan.scanners.image_asset_suffix import normalize_game_asset_suffix_extension
from Virus_Scan.scanners.image_jpeg_segments import _scan_jpeg_segments
from Virus_Scan.scanners.image_lsb import extract_lsb_payload_gated, scan_pillow_lsb
from Virus_Scan.scanners.image_lsb_payload import decoded_lsb_payload_behavior_tags
from Virus_Scan.scanners.image_malformed import fast_image_sample_malformed_status
from Virus_Scan.scanners.image_png_chunks import scan_png_chunks
from Virus_Scan.scanners.image_scan import _fast_path_image_scan, scan_image_file
from Virus_Scan.scanners.image_stego import scan_image_stego


@contextmanager
def _temporary_attr(module: ModuleType, name: str, value: Any) -> Iterator[None]:
    original = getattr(module, name)
    setattr(module, name, value)
    try:
        yield
    finally:
        setattr(module, name, original)


class HostileText:
    def __bool__(self):  # pragma: no cover - should never be called
        raise AssertionError("bool hook executed")

    def __str__(self):  # pragma: no cover - should never be called
        raise AssertionError("str hook executed")

    def __format__(self, spec):  # pragma: no cover - should never be called
        raise AssertionError("format hook executed")


class HostileMapping:
    def __bool__(self):  # pragma: no cover - should never be called
        raise AssertionError("mapping bool hook executed")

    def __iter__(self):  # pragma: no cover - should never be called
        raise AssertionError("mapping iter hook executed")

    def items(self):  # pragma: no cover - should never be called
        raise AssertionError("mapping items hook executed")

    def get(self, key, default=None):  # pragma: no cover - should never be called
        raise AssertionError("mapping get hook executed")


class HostileBool:
    def __bool__(self):  # pragma: no cover - should never be called
        raise AssertionError("bool hook executed")


class HostileRuntimeError(RuntimeError):
    def __str__(self):  # pragma: no cover - should never be called
        raise AssertionError("exception str hook executed")

    def __format__(self, spec):  # pragma: no cover - should never be called
        raise AssertionError("exception format hook executed")


class ExplodingData:
    def startswith(self, prefix):
        raise HostileRuntimeError("hidden")


class FakeImage:
    size = (64, 64)
    mode = HostileText()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def copy(self):
        return self

    def thumbnail(self, size):
        return None

    def convert(self, mode):
        return self

    def getdata(self):
        return [(0, 0, 0)] * 16


class FakeImageModule:
    def open(self, path):
        return FakeImage()


def test_ilspy_rejects_hostile_context_mapping_and_use_flag_without_hooks():
    def engine_context_inferer(tags, *, file_structure, strings_blob):
        assert tags == []
        return HostileMapping()

    should, ctx = unity_ilspy_should_run(
        HostileText(),
        tags=HostileText(),
        strings_blob=HostileText(),
        read_bytes=lambda path, max_size: b"managed metadata",
        get_extension=lambda path: ".dll",
        metadata_detector=lambda blob: True,
        engine_context_inferer=engine_context_inferer,
        use_ilspy=True,
    )

    assert should is True
    assert ctx["is_dotnet"] is True
    assert ctx["reason"] == "engine_context_unsupported"

    should, ctx = unity_ilspy_should_run(
        "sample.dll",
        tags=[],
        strings_blob="managed metadata",
        read_bytes=lambda path, max_size: b"managed metadata",
        get_extension=lambda path: ".dll",
        metadata_detector=lambda blob: True,
        engine_context_inferer=lambda *args, **kwargs: {"source": "owned"},
        use_ilspy=HostileBool(),
    )

    assert should is False
    assert ctx["source"] == "owned"
    assert ctx["reason"] == "ilspy_disabled"


def test_image_asset_suffix_and_malformed_path_reject_hostile_text_without_hooks():
    assert normalize_game_asset_suffix_extension("sprite.PNG_") == ".png"
    assert normalize_game_asset_suffix_extension(HostileText()) is None
    assert fast_image_sample_malformed_status(HostileText(), b"\x89PNG\r\n\x1a\nbody") == "empty_or_unchecked"


def test_image_segment_log_messages_do_not_format_hostile_exceptions():
    jpeg_messages = []
    png_messages = []
    with ExitStack() as stack:
        stack.enter_context(_temporary_attr(jpeg_segments_module, "log_error", jpeg_messages.append))
        stack.enter_context(_temporary_attr(png_chunks_module, "log_error", png_messages.append))
        assert _scan_jpeg_segments(ExplodingData(), []) is False
        assert scan_png_chunks(ExplodingData(), []) is True

    assert jpeg_messages == ["JPEG segment stego scan failed: exception:HostileRuntimeError"]
    assert png_messages == ["PNG chunk stego scan failed: exception:HostileRuntimeError"]


def test_lsb_mode_and_log_messages_do_not_materialize_hostile_objects():
    messages = []
    with ExitStack() as stack:
        stack.enter_context(_temporary_attr(lsb_module, "Image", FakeImageModule()))
        stack.enter_context(_temporary_attr(lsb_module, "_image_is_jpeg", lambda **kwargs: False))
        stack.enter_context(_temporary_attr(lsb_module, "log_error", messages.append))

        tags: list[str] = []
        assert scan_pillow_lsb(HostileText(), tags, data=b"not-jpeg") is False
        assert "image_mode_unknown" in tags

        stack.enter_context(_temporary_attr(lsb_module, "_image_is_jpeg", lambda **kwargs: (_ for _ in ()).throw(HostileRuntimeError("hidden"))))
        assert scan_pillow_lsb(HostileText(), [], data=b"not-jpeg") is False
        assert extract_lsb_payload_gated(HostileText(), [], data=b"not-jpeg") is False

    assert messages == [
        "Pillow LSB stego scan failed for : exception:HostileRuntimeError",
        "gated LSB extraction failed for : exception:HostileRuntimeError",
    ]


def test_lsb_payload_decoding_uses_owned_text_and_sanitized_magic_tags():
    class HostileRecord(dict):
        def get(self, key, default=None):  # pragma: no cover - should never be called
            raise AssertionError("hostile record get hook executed")

    with ExitStack() as stack:
        stack.enter_context(_temporary_attr(
            lsb_payload_module,
            "safe_decode_payloads",
            lambda text: [HostileRecord(binary_magic="MZ"), {"binary_magic": HostileText()}, {"binary_magic": "PE"}],
        ))
        stack.enter_context(_temporary_attr(
            lsb_payload_module,
            "decoded_payload_behavior_tags",
            lambda rec, tags: [],
        ))
        assert decoded_lsb_payload_behavior_tags(b"AAAA") == [
            "payload_decode_candidate",
            "decoded_binary_payload",
            "decoded_pe_payload",
        ]
        assert decoded_lsb_payload_behavior_tags(bytearray(b"AAAA")) == []


def test_image_scan_and_stego_logging_rejects_hostile_bool_and_exceptions(tmp_path):
    image_messages = []
    stego_messages = []
    with ExitStack() as stack:
        stack.enter_context(_temporary_attr(image_scan_module, "scan_image_file_fast_triage", lambda path, artifact_read_snapshot: ([], HostileBool(), b"sample")))
        stack.enter_context(_temporary_attr(image_scan_module, "scan_appended_payload", lambda sample, tags: False))
        stack.enter_context(_temporary_attr(image_scan_module, "fast_image_sample_malformed_status", lambda path, sample: "empty_or_unchecked"))
        stack.enter_context(_temporary_attr(image_scan_module, "rewrite_stego_tags", lambda tags, data, path: tags))
        stack.enter_context(_temporary_attr(image_scan_module, "log_error", image_messages.append))
        stack.enter_context(_temporary_attr(image_scan_module, "scan_image_stego", lambda path, data=None: ([], False)))
        stack.enter_context(_temporary_attr(image_scan_module, "deep_scan_fast_assets_enabled", lambda: True))
        stack.enter_context(_temporary_attr(image_scan_module, "deep_scan_thorough_enabled", lambda: False))
        assert _fast_path_image_scan(HostileText(), object()) == ([], False, True)

        def raising_fast_scan(path, *, artifact_read_snapshot):
            del path, artifact_read_snapshot
            raise HostileRuntimeError("hidden")

        stack.enter_context(_temporary_attr(image_scan_module, "scan_image_file_fast_triage", raising_fast_scan))
        sample = tmp_path / "sample.png"
        sample.write_bytes(b"sample")
        assert scan_image_file(
            sample, artifact_read_snapshot=artifact_read_snapshot_fixture(sample),
        ) == (["image"], False)

    assert image_messages == ["scan_image_file_fast_triage failed for : exception:HostileRuntimeError"]

    with ExitStack() as stack:
        stack.enter_context(_temporary_attr(image_stego_module.Path, "exists", lambda self: (_ for _ in ()).throw(HostileRuntimeError("hidden"))))
        stack.enter_context(_temporary_attr(image_stego_module, "log_error", stego_messages.append))
        tags, suspicious = scan_image_stego("sample.png", data=b"abc")

    assert suspicious is False
    assert "image_stego_scan_error" in tags
    assert stego_messages == ["scan_image_stego failed: exception:HostileRuntimeError"]
