from __future__ import annotations

from Virus_Scan.runtime.config import ArchiveScanLimits, PersistenceConfig, RuntimeConfig, StageConcurrencyLimits


class HostileArgs:
    touched = 0

    @property
    def output(self):  # pragma: no cover - failure proves descriptor traversal
        type(self).touched += 1
        raise AssertionError("output property touched")

    @property
    def vt_output(self):  # pragma: no cover - failure proves descriptor traversal
        type(self).touched += 1
        raise AssertionError("vt_output property touched")

    @property
    def preserve_scan_results(self):  # pragma: no cover - failure proves descriptor traversal
        type(self).touched += 1
        raise AssertionError("preserve property touched")

    @property
    def preserve_virustotal_results(self):  # pragma: no cover - failure proves descriptor traversal
        type(self).touched += 1
        raise AssertionError("preserve vt property touched")


class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves unsafe stringification
        type(self).touched += 1
        raise AssertionError("hostile text stringified")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr
        type(self).touched += 1
        raise AssertionError("hostile text repr")


class HostileBool:
    touched = 0

    def __bool__(self):  # pragma: no cover - failure proves unsafe truthiness
        type(self).touched += 1
        raise AssertionError("hostile bool touched")




class HostileMeta(type):
    touched = 0

    def __getattribute__(cls, name):  # pragma: no cover - failure proves metaclass traversal
        if name == "__getattribute__":
            type.__setattr__(cls, "touched", type.__getattribute__(cls, "touched") + 1)
            raise AssertionError("metaclass hook touched")
        return type.__getattribute__(cls, name)


class HostileMetaArgs(metaclass=HostileMeta):
    pass


class HostileSection:
    touched = 0

    def as_mapping(self):  # pragma: no cover - failure proves unsafe as_mapping
        type(self).touched += 1
        raise AssertionError("as_mapping touched")

    def as_dict(self):  # pragma: no cover - failure proves unsafe as_dict
        type(self).touched += 1
        raise AssertionError("as_dict touched")

    def env_mapping(self):  # pragma: no cover - failure proves unsafe env_mapping
        type(self).touched += 1
        raise AssertionError("env_mapping touched")

    def __iter__(self):  # pragma: no cover - failure proves unsafe iteration
        type(self).touched += 1
        raise AssertionError("iter touched")

    def __str__(self):  # pragma: no cover - failure proves unsafe stringification
        type(self).touched += 1
        raise AssertionError("section str touched")

    def __repr__(self):  # pragma: no cover - failure proves unsafe repr
        type(self).touched += 1
        raise AssertionError("section repr touched")


def _valid_persistence_args() -> object:
    args = type("PlainArgs", (), {})()
    args.scan_log_root = "/tmp/Scan Logs"
    args.scan_id = "stage1593"
    args.scan_log_staging_path = "/tmp/Scan Logs/.staging/stage1593"
    args.scan_log_run_path = "/tmp/Scan Logs/runs/stage1593"
    args.output = "/tmp/Scan Logs/.staging/stage1593/scan_results.json"
    args.log = "/tmp/Scan Logs/.staging/stage1593/scanlog"
    args.preserve_scan_results = False
    return args


def test_stage1593_persistence_config_does_not_touch_hostile_arg_properties() -> None:
    HostileArgs.touched = 0
    try:
        PersistenceConfig.from_args(HostileArgs())
    except ValueError as exc:
        assert str(exc) == "runtime_scan_log_output_plan_missing"
    else:
        raise AssertionError("missing canonical output plan accepted")
    assert HostileArgs.touched == 0


def test_stage1593_persistence_config_rejects_hostile_arg_values_without_hooks() -> None:
    HostileText.touched = 0
    HostileBool.touched = 0
    args = _valid_persistence_args()
    args.output = HostileText()
    args.preserve_scan_results = HostileBool()
    try:
        PersistenceConfig.from_args(args)
    except ValueError as exc:
        assert str(exc) == "runtime_scan_log_output_plan_missing"
    else:
        raise AssertionError("hostile output plan accepted")
    assert HostileText.touched == 0
    assert HostileBool.touched == 0


def test_stage1593_persistence_config_accepts_one_complete_scan_log_generation() -> None:
    cfg = PersistenceConfig.from_args(_valid_persistence_args())
    assert cfg.scan_id == "stage1593"
    assert cfg.output_path.endswith("/Scan Logs/.staging/stage1593/scan_results.json")
    assert cfg.scanlog_path is not None and cfg.scanlog_path.endswith("/Scan Logs/.staging/stage1593/scanlog")
    assert not hasattr(cfg, "vt_output_path")
    assert cfg.preserve_scan_results is False
    assert not hasattr(cfg, "preserve_virustotal_results")


def test_stage1593_runtime_config_as_mapping_does_not_call_unknown_section_hooks() -> None:
    HostileSection.touched = 0
    hostile = HostileSection()
    cfg = RuntimeConfig(
        archive_limits=ArchiveScanLimits(),
        stage_limits=StageConcurrencyLimits(),
        economics=hostile,
        persistence=hostile,
    )

    mapped = cfg.as_mapping()
    env = cfg.env_mapping()

    assert HostileSection.touched == 0
    assert mapped["economics"]["unavailable_reason"] == "non_materializable_runtime_value"
    assert mapped["persistence"]["unavailable_reason"] == "non_materializable_runtime_value"
    assert "UMIGE_MAX_WORKLOAD_COST" not in env


def test_stage1593_runtime_limit_env_mapping_rejects_hostile_field_values_without_hooks() -> None:
    HostileText.touched = 0
    archive_limits = ArchiveScanLimits(max_depth=HostileText())
    stage_limits = StageConcurrencyLimits(raw=HostileText())

    archive_env = archive_limits.env_mapping()
    stage_env = stage_limits.env_mapping()

    assert HostileText.touched == 0
    assert archive_env["UMIGE_ARCHIVE_MAX_DEPTH"] == "2"
    assert stage_env["UMIGE_STAGE_LIMIT_RAW"] == "1"


def test_stage1593_persistence_config_does_not_touch_hostile_arg_metaclass_hooks() -> None:
    HostileMetaArgs.touched = 0

    try:
        PersistenceConfig.from_args(HostileMetaArgs())
    except ValueError as exc:
        assert str(exc) == "runtime_scan_log_output_plan_missing"
    else:
        raise AssertionError("missing canonical output plan accepted")

    assert HostileMetaArgs.touched == 0
