from Virus_Scan.scheduler.internal.scheduler_config import init_raw_scheduler_defaults
from Virus_Scan.scheduler.runtime.resource_priority import init_scheduler_resources
from Virus_Scan.scheduler.runtime.startup_defaults import init_scheduler_defaults

from pathlib import Path


def test_scheduler_init_parts_package_removed():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (scheduler_root / "init_parts").exists()


def test_scheduler_initializers_owned_by_canonical_modules():

    assert callable(init_raw_scheduler_defaults)
    assert callable(init_scheduler_resources)
    assert callable(init_scheduler_defaults)
