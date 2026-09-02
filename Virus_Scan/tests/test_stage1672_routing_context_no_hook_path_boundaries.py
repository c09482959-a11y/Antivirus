from pathlib import Path

from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record, classify_engine_context
from Virus_Scan.routing.engine_fingerprints import fingerprint_container, score_engine_for_path
from Virus_Scan.routing.file_identity import sniff_file_identity


class HostileRoutingPath:
    touched_bool = 0
    touched_str = 0
    touched_fspath = 0
    touched_iter = 0

    def __bool__(self):
        type(self).touched_bool += 1
        raise RuntimeError("routing boundary must not call __bool__")

    def __str__(self):
        type(self).touched_str += 1
        raise RuntimeError("routing boundary must not call __str__")

    def __fspath__(self):
        type(self).touched_fspath += 1
        raise RuntimeError("routing boundary must not call __fspath__")

    def __iter__(self):
        type(self).touched_iter += 1
        raise RuntimeError("routing boundary must not call __iter__")


def _reset_hostile_path():
    HostileRoutingPath.touched_bool = 0
    HostileRoutingPath.touched_str = 0
    HostileRoutingPath.touched_fspath = 0
    HostileRoutingPath.touched_iter = 0


def _assert_hostile_path_untouched():
    assert HostileRoutingPath.touched_bool == 0
    assert HostileRoutingPath.touched_str == 0
    assert HostileRoutingPath.touched_fspath == 0
    assert HostileRoutingPath.touched_iter == 0


def test_stage1672_routing_context_rejects_hostile_container_root_without_hooks(tmp_path):
    _reset_hostile_path()
    sample = tmp_path / "game.exe"
    sample.write_bytes(b"")
    context = classify_engine_context(sample, container_root=HostileRoutingPath())

    _assert_hostile_path_untouched()
    assert context.container_engine in {"other", "media", "renpy", "rpgm", "unity"}
    assert isinstance(context.fingerprint_evidence, tuple)


def test_stage1672_attach_routing_evidence_rejects_hostile_container_root_without_hooks(tmp_path):
    _reset_hostile_path()
    sample = tmp_path / "game.exe"
    sample.write_bytes(b"")
    record = attach_routing_evidence_to_record({"tags": []}, sample, container_root=HostileRoutingPath())

    _assert_hostile_path_untouched()
    assert "container_engine" in record
    assert "baseline_key" in record
    assert "fingerprint_evidence" in record


def test_stage1672_routing_path_scoring_rejects_hostile_path_and_root_without_hooks():
    _reset_hostile_path()
    hostile = HostileRoutingPath()

    identity = sniff_file_identity(hostile)
    score = score_engine_for_path(hostile, root=hostile)
    container = fingerprint_container(hostile)
    evidence_context = RoutingEvidenceContext.build(hostile)

    _assert_hostile_path_untouched()
    assert identity.evidence == ("unsafe_file_path_rejected",)
    assert set(score) == {"other"}
    assert container.evidence == ("unsafe_container_root_rejected",)
    assert evidence_context.container_root is None
    assert evidence_context.root_fingerprint is None


def test_stage1672_valid_routing_paths_still_produce_context_identity(tmp_path):
    root = tmp_path / "GameRoot"
    renpy_dir = root / "renpy"
    renpy_dir.mkdir(parents=True)
    sample = root / "script.rpy"
    sample.write_text("label start:\n    return\n", encoding="utf-8")

    context = classify_engine_context(sample, container_root=root)

    assert context.declared_extension == ".rpy"
    assert context.artifact_engine in {"renpy", "other"}
    assert isinstance(context.fingerprint_evidence, tuple)
