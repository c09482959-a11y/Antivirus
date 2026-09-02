from pathlib import Path

from Virus_Scan.models.profiles import DEFAULT_ENGINES, infer_profile_engine
from Virus_Scan.routing.engine_detect import (
    engine_confidence_report,
    infer_engine_context,
    select_active_profile_engine,
)
from Virus_Scan.scanners.text import _engine_hint_to_context
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.models.api.profile_persistence import ensure_authoritative_engine_profiles
from Virus_Scan.storage import authoritative_model_state, sqlite_lifecycle


def test_media_is_first_class_default_engine():
    assert "media" in DEFAULT_ENGINES


def test_standalone_media_extension_selects_media_profile():
    ctx = infer_engine_context(["media_asset", "image_asset"], file_structure="sample.png")
    assert ctx["media"] >= 0.8
    assert select_active_profile_engine(ctx) == "media"
    engine, profile_ctx = infer_profile_engine(["media_asset", "image_asset"], file_structure="sample.png")
    assert engine == "media"
    assert profile_ctx["media"] >= 0.8


def test_media_cli_hint_has_own_context():
    ctx = _engine_hint_to_context("media")
    assert ctx == {"unity": 0.0, "renpy": 0.0, "rpgm": 0.0, "media": 1.0, "unknown": 0.0}


def test_media_profile_created_in_authoritative_database(tmp_path):
    profiles_dir = tmp_path / "profiles"
    configure_profiles_dir(str(profiles_dir))
    result = ensure_authoritative_engine_profiles()
    assert result["ok"] is True
    assert authoritative_model_state().read_profile("media")["engine"] == "media"
    assert (profiles_dir / "model_state.sqlite3").exists()
    assert not tuple(profiles_dir.glob("*.json"))
    sqlite_lifecycle().close()


def test_media_engine_confidence_reason():
    report = engine_confidence_report({"media": 1.0}, path="audio/theme.ogg", tags=["media_asset", "audio_asset"])
    assert report["active_profile"] == "media"
    assert report["baseline_suppression_allowed"] is True
    assert any("media" in reason for reason in report["reasons"])
