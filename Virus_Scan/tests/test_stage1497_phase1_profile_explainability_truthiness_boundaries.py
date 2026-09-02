"""Stage 1497 Phase 1 model/profile explainability truthiness boundary tests."""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.detection.profiles.engine_context import (
    engine_confidence_report,
    infer_engine_context,
    select_active_profile_engine,
)
from Virus_Scan.detection.profiles.selection import build_detection_profile_context
from Virus_Scan.detection.scoring.explainability.score_components import (
    build_reproducible_score_explanation,
)


class HostileBoolMapping(Mapping):
    def __init__(self, values):
        self._values = dict(values)
        self.bool_calls = 0

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return self._values.keys()

    def get(self, key, default=None):
        return self._values.get(key, default)

    def items(self):
        return self._values.items()

    def __bool__(self):  # pragma: no cover - failure path only
        self.bool_calls += 1
        raise AssertionError("hostile mapping truthiness was probed")


class HostileBoolIterable:
    def __init__(self, values):
        self._values = tuple(values)
        self.bool_calls = 0

    def __iter__(self):
        return iter(self._values)

    def __bool__(self):  # pragma: no cover - failure path only
        self.bool_calls += 1
        raise AssertionError("hostile iterable truthiness was probed")


def test_stage1497_profile_engine_context_rejects_unknown_mapping_without_truthiness() -> None:
    context = HostileBoolMapping({"unity": 1.0, "renpy": 0.0, "rpgm": 0.0, "media": 0.0})

    assert select_active_profile_engine(context) == "other"
    report = engine_confidence_report(context, path="GameAssembly.dll", tags=("unity",))
    built = build_detection_profile_context(
        engine_context=context,
        path="GameAssembly.dll",
        tags=("unity",),
        strings_blob="UnityPlayer",
    )

    assert report["active_profile"] == "other"
    assert built.active_profile == "other"
    assert context.bool_calls == 0


def test_stage1497_profile_engine_inference_rejects_unknown_iterable_without_truthiness() -> None:
    tags = HostileBoolIterable(("media_asset", "audio_asset"))

    context = infer_engine_context(tags, file_structure="audio/theme.ogg", strings_blob="vorbis")

    assert context["media"] >= 0.5
    assert tags.bool_calls == 0


def test_stage1497_profile_engine_inference_preserves_exact_builtin_tag_sequences() -> None:
    context = infer_engine_context(("media_asset", "audio_asset"), file_structure="audio/theme.ogg", strings_blob="vorbis")

    assert context["media"] >= 0.8


def test_stage1497_score_explanation_does_not_probe_explanation_truthiness() -> None:
    hits = HostileBoolIterable(("scanner:evidence",))
    explanation = HostileBoolMapping(
        {
            "layers": HostileBoolMapping(
                {
                    "layer_1_static": HostileBoolMapping(
                        {"score": 10.0, "name": "static", "hits": hits}
                    )
                }
            ),
            "weights": HostileBoolMapping({"layer_1_static": 2.0}),
            "caps": (
                HostileBoolMapping(
                    {
                        "name": "cap_guard",
                        "old_score": 25.0,
                        "new_score": 20.0,
                        "reason": "bounded cap",
                    }
                ),
            ),
            "active_layers": 1,
        }
    )

    rebuilt = build_reproducible_score_explanation(
        final_score=15.0,
        explanation=explanation,
        path="sample.rpy",
        active_profile="renpy",
    )

    assert rebuilt["score_reproducibility"]["matches_emitted_score"] is True
    assert any(component["score_source"] == "layer:layer_1_static" for component in rebuilt["score_components"])
    assert any(component["score_source"] == "cap:cap_guard" for component in rebuilt["score_components"])
    assert explanation.bool_calls == 0
    assert hits.bool_calls == 0


def test_stage1497_repaired_sources_do_not_restore_truthiness_fallbacks() -> None:
    paths = (
        "Virus_Scan/detection/profiles/engine_context.py",
        "Virus_Scan/detection/profiles/selection.py",
        "Virus_Scan/detection/scoring/explainability/score_components.py",
        "Virus_Scan/detection/scoring/explainability/score_component_builders.py",
    )
    forbidden = (
        "engine_context or {}",
        "engine_context or {\"other\": 1.0}",
        "tags or ()",
        "tags or []",
        "strings_blob or",
        "file_structure or",
        "explanation or {}",
        "layers = explanation_record.get(\"layers\") or {}",
        "weights = explanation_record.get(\"weights\") or {}",
        "layer = layers.get(layer_name) or {}",
        "layer.get(\"hits\") or ()",
        "cap.get(\"name\") or",
    )
    for path in paths:
        source = open(path, encoding="utf-8").read()
        for token in forbidden:
            assert token not in source, f"{token!r} restored in {path}"

from Virus_Scan.detection.scoring.weighting.context_confidence import (
    compute_context_confidence_amplifier,
)


def test_stage1497_context_confidence_does_not_probe_model_mapping_truthiness() -> None:
    tags = HostileBoolIterable(("process_exec", "network_download"))
    layers = HostileBoolMapping(
        {
            "graph": HostileBoolMapping({}),
            "layer_3_graph_score": HostileBoolMapping({"score": 90.0}),
            "intel": HostileBoolMapping({"score": 80.0}),
        }
    )
    adaptive_learning = HostileBoolMapping(
        {
            "markov": HostileBoolMapping({"markov_anomaly": 0.5}),
            "cluster": HostileBoolMapping({"unavailable_reason": "cluster_snapshot_unavailable"}),
        }
    )

    result = compute_context_confidence_amplifier(
        node="sample.exe",
        tags=tags,
        
        layers=layers,
        adaptive_learning=adaptive_learning,
        pre_context_score=55.0,
    )

    assert result["graph_score"] == 0.0
    assert result["intel_score"] == 0.0
    assert result["markov_signal"] == 0.0
    assert result["applied_bonus"] == 0.0
    assert result["context_unavailable_reasons"] == {}
    assert tags.bool_calls == 0
    assert layers.bool_calls == 0
    assert adaptive_learning.bool_calls == 0
