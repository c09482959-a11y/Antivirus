from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import Virus_Scan.detection.registries.detection_constants as detection_constants_init
import Virus_Scan.models.init_parts.model_defaults_init as model_defaults_init
import Virus_Scan.models.init_parts.profile_and_learning_store_init as profile_and_learning_store_init
import Virus_Scan.reporting.init_parts.reporting_defaults_init as reporting_defaults_init
import Virus_Scan.scheduler.runtime.resource_priority
import Virus_Scan.scheduler.runtime.worker_capacity
import Virus_Scan.scheduler.runtime.resource_priority as scheduler_resource_defaults_init
import Virus_Scan.scheduler.runtime.startup_defaults as scheduler_runtime_defaults_init



def test_init_part_exports_reference_canonical_function_names():
    modules = {
        detection_constants_init: "init_detection_constants",
        model_defaults_init: "init_model_defaults",
        profile_and_learning_store_init: "init_profiles",
        reporting_defaults_init: "init_reporting_defaults",
        scheduler_resource_defaults_init: "init_scheduler_resources",
        scheduler_runtime_defaults_init: "init_scheduler_defaults",
    }
    for module, canonical_init in modules.items():
        exported = tuple(getattr(module, "__all__", ()))
        assert canonical_init in exported
        assert "init" not in exported
        assert callable(getattr(module, canonical_init))


def test_chain_family_alias_registry_was_deleted_after_canonical_callsite_update():
    assert not Path("Virus_Scan/detection/registries/chain_family_defaults.py").exists()
    source = read_python_file(Path("Virus_Scan/detection/registries/snapshot.py"))
    assert "chain_family_defaults" not in source

