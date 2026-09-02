from Virus_Scan.scanners import text_behavior, text_validation_gates


class HostileText:
    touched = 0

    def __str__(self):
        HostileText.touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        HostileText.touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, _spec):
        HostileText.touched += 1
        raise RuntimeError("do not format")


class HostileTags:
    touched = 0

    def __iter__(self):
        HostileTags.touched += 1
        raise RuntimeError("do not iterate tags")

    def __bool__(self):
        HostileTags.touched += 1
        raise RuntimeError("do not bool tags")


class HostileScore:
    touched = 0

    def __float__(self):
        HostileScore.touched += 1
        raise RuntimeError("do not float score")

    def __bool__(self):
        HostileScore.touched += 1
        raise RuntimeError("do not bool score")


class HostilePath:
    touched = 0

    def __str__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not stringify path")

    def __repr__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not repr path")

    def __format__(self, _spec):
        HostilePath.touched += 1
        raise RuntimeError("do not format path")

    def __fspath__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not fspath path")


class HostileYaraHits:
    touched = 0

    def __bool__(self):
        HostileYaraHits.touched += 1
        raise RuntimeError("do not bool yara hits")

    def __len__(self):
        HostileYaraHits.touched += 1
        raise RuntimeError("do not len yara hits")

    def __iter__(self):
        HostileYaraHits.touched += 1
        raise RuntimeError("do not iterate yara hits")


def _reset():
    HostileText.touched = 0
    HostileTags.touched = 0
    HostileScore.touched = 0
    HostilePath.touched = 0
    HostileYaraHits.touched = 0


def test_stage1596_scanner_group_and_hard_proof_reject_hostile_inputs_without_hooks():
    _reset()

    group = text_validation_gates.infer_correlation_group(HostileText(), tags=HostileTags())
    status, has_proof = text_validation_gates.library_baseline_hard_proof_status(tags=HostileTags(), strings_blob="powershell -enc")

    assert group == "scanner_validation_input_rejected"
    assert (status, has_proof) == ("tag_input_rejected", False)
    assert HostileText.touched == 0
    assert HostileTags.touched == 0


def test_stage1596_reference_url_cap_rejects_hostile_score_path_and_tags_without_hooks():
    _reset()

    score, evidence = text_validation_gates.reference_url_only_score_cap(
        HostileScore(),
        tags=("reference_url",),
        path="game/script.rpy",
        strings_blob="requests.get('https://example.invalid/payload')",
    )
    assert score == 100.0
    assert "unsafe_scanner_score_rejected" in evidence

    score, evidence = text_validation_gates.reference_url_only_score_cap(
        33.0,
        tags=("reference_url",),
        path=HostilePath(),
        strings_blob="requests.get('https://example.invalid/payload')",
    )
    assert score == 33.0
    assert "unsafe_scanner_path_rejected" in evidence

    score, evidence = text_validation_gates.reference_url_only_score_cap(
        33.0,
        tags=HostileTags(),
        path="game/script.rpy",
        strings_blob="requests.get('https://example.invalid/payload')",
    )
    assert score == 33.0
    assert "unsafe_scanner_tags_rejected" in evidence

    assert HostileScore.touched == 0
    assert HostilePath.touched == 0
    assert HostileTags.touched == 0


def test_stage1596_high_risk_tag_and_renpy_path_reject_hostile_objects_without_hooks():
    _reset()

    assert text_validation_gates.validate_high_risk_tag(HostileText(), strings_blob=HostileText(), path=HostilePath()) is False
    assert text_behavior._renpy_bytecode_path_status(HostilePath()) == "probe_error"
    assert text_behavior._is_renpy_bytecode_path(HostilePath()) is False

    assert HostileText.touched == 0
    assert HostilePath.touched == 0


def test_stage1596_existing_scanner_validation_behavior_is_preserved_for_valid_inputs():
    score, evidence = text_validation_gates.reference_url_only_score_cap(
        55.0,
        tags=("reference_url",),
        path="game/script.rpy",
        strings_blob="documentation mentions https://example.invalid only",
    )
    assert score == 18.0
    assert evidence == ["reference_url_only_cap"]

    assert text_validation_gates.validate_high_risk_tag(
        "renpy_pickle_exec",
        strings_blob="pickle GLOBAL REDUCE os.system subprocess powershell exec(",
        path="game/script.rpy",
    ) is True
    assert text_behavior._renpy_bytecode_path_status("game/renpy/module.rpyc") == "renpy_bytecode_path"
