from Virus_Scan.routing.passive_assets import _is_font_asset_extension, _is_media_asset_extension
from Virus_Scan.routing.extension_scan_handlers import is_unity_container_asset_extension
from Virus_Scan.scanners.unity import _is_unity_container_asset_extension as scanner_unity_extension
from Virus_Scan.scanners.unity import detect_unity_runtime_behavior
from Virus_Scan.utils.stages import (
    extract_router_stage,
    normalize_game_asset_suffix_extension,
    normalize_stage,
    resolve_content_evidence_stage,
    sanitize_tag_part,
)


class HostileStageText:
    touched_bool = 0
    touched_str = 0
    touched_repr = 0
    touched_format = 0
    touched_iter = 0

    def __bool__(self):
        type(self).touched_bool += 1
        raise RuntimeError("stage boundary must not call __bool__")

    def __str__(self):
        type(self).touched_str += 1
        raise RuntimeError("stage boundary must not call __str__")

    def __repr__(self):
        type(self).touched_repr += 1
        raise RuntimeError("stage boundary must not call __repr__")

    def __format__(self, spec):
        type(self).touched_format += 1
        raise RuntimeError("stage boundary must not call __format__")

    def __iter__(self):
        type(self).touched_iter += 1
        raise RuntimeError("stage boundary must not call __iter__")


class HostileStageTags(HostileStageText):
    pass


def _reset_hostile(cls=HostileStageText):
    cls.touched_bool = 0
    cls.touched_str = 0
    cls.touched_repr = 0
    cls.touched_format = 0
    cls.touched_iter = 0


def _assert_untouched(cls=HostileStageText):
    assert cls.touched_bool == 0
    assert cls.touched_str == 0
    assert cls.touched_repr == 0
    assert cls.touched_format == 0
    assert cls.touched_iter == 0


def test_stage1673_asset_extension_helpers_reject_hostile_extension_without_hooks():
    _reset_hostile()
    hostile = HostileStageText()

    assert _is_font_asset_extension(hostile) is False
    assert _is_media_asset_extension(hostile) is False
    assert is_unity_container_asset_extension(hostile) is False
    assert scanner_unity_extension(hostile) is False

    _assert_untouched()


def test_stage1673_asset_extension_helpers_preserve_exact_primitive_extensions():
    assert _is_font_asset_extension(".TTF") is True
    assert _is_media_asset_extension(".PNG") is True
    assert is_unity_container_asset_extension(".BUNDLE") is True
    assert scanner_unity_extension(".BUNDLE") is True
    assert _is_font_asset_extension(".exe") is False


def test_stage1673_stage_utils_reject_hostile_values_without_text_hooks():
    _reset_hostile()
    hostile = HostileStageText()

    assert sanitize_tag_part(hostile) == "unknown"
    assert normalize_stage(hostile) == "unknown"
    assert normalize_game_asset_suffix_extension(hostile) is None
    assert detect_unity_runtime_behavior(hostile) == set()

    _assert_untouched()


def test_stage1673_stage_tag_sequences_reject_hostile_containers_and_items_without_hooks():
    _reset_hostile(HostileStageTags)
    tags = HostileStageTags()

    assert extract_router_stage(tags) == "unknown"
    assert resolve_content_evidence_stage("asset", tags) == "asset"
    _assert_untouched(HostileStageTags)

    _reset_hostile()
    hostile_item = HostileStageText()
    assert extract_router_stage([hostile_item, "router_stage_runtime"]) == "runtime"
    assert resolve_content_evidence_stage("asset", [hostile_item, "powershell_exec"]) == "runtime"
    _assert_untouched()
