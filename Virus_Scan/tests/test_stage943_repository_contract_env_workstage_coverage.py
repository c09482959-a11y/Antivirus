import os
from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.contracts.work_stage import (
    CAPACITY_CLASSES,
    WorkStageCapacityClass,
    capacity_for_stage,
    stage_code,
    stage_name_from_code,
)


class _temporary_env:
    def __init__(self, **updates: str):
        self._updates = updates
        self._previous = {}

    def __enter__(self):
        for key, value in self._updates.items():
            self._previous[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, exc_type, exc, tb):
        for key, previous in self._previous.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        return False


def test_env_config_int_env_clamps_invalid_low_and_high_values():
    with _temporary_env(UMIGE_STAGE943_INT="not-an-int"):
        assert int_env("UMIGE_STAGE943_INT", 7, minimum=2, maximum=9) == 7

    with _temporary_env(UMIGE_STAGE943_INT="-11"):
        assert int_env("UMIGE_STAGE943_INT", 7, minimum=2, maximum=9) == 2

    with _temporary_env(UMIGE_STAGE943_INT="99"):
        assert int_env("UMIGE_STAGE943_INT", 7, minimum=2, maximum=9) == 9


def test_env_config_float_env_clamps_invalid_low_and_high_values():
    with _temporary_env(UMIGE_STAGE943_FLOAT="bad-float"):
        assert float_env("UMIGE_STAGE943_FLOAT", 0.25, minimum=0.1, maximum=0.9) == 0.25

    with _temporary_env(UMIGE_STAGE943_FLOAT="-3.5"):
        assert float_env("UMIGE_STAGE943_FLOAT", 0.25, minimum=0.1, maximum=0.9) == 0.1

    with _temporary_env(UMIGE_STAGE943_FLOAT="3.5"):
        assert float_env("UMIGE_STAGE943_FLOAT", 0.25, minimum=0.1, maximum=0.9) == 0.9


def test_work_stage_capacity_contract_is_immutable_and_falls_back_to_generic():
    archive = capacity_for_stage("ARCHIVE")
    unknown = capacity_for_stage("unregistered-stage")

    assert archive == WorkStageCapacityClass("archive", 2, 8.0)
    assert unknown == CAPACITY_CLASSES["generic"]

    with pytest.raises(FrozenInstanceError):
        archive.default_limit = 99

    with pytest.raises(TypeError):
        CAPACITY_CLASSES["new-stage"] = WorkStageCapacityClass("new-stage", 1, 1.0)


def test_work_stage_code_mapping_is_stable_for_scheduler_reporting_terms():
    assert stage_code("assign queue claim") == 1
    assert stage_code("budget admission") == 2
    assert stage_code("yaralight prescan") == 10
    assert stage_code("png stego image sample") == 20
    assert stage_code("rpa archive extraction") == 30
    assert stage_code("ilspy dotnet dncil") == 40
    assert stage_code("raw string decode") == 50
    assert stage_code("done complete") == 90
    assert stage_code("ordinary scan") == 60

    assert stage_name_from_code(30) == "archive"
    assert stage_name_from_code(999) == "stage_999"
    assert stage_name_from_code("bad-code") == "scan"
