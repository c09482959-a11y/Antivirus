from types import ModuleType

from Virus_Scan.scheduler.orchestration import inmemory_parent_message


def test_inmemory_parent_message_ownership_manifest_exposes_names_not_modules():
    assert not hasattr(inmemory_parent_message, "_WORKER_MESSAGE_OWNERSHIP_MODULES")
    module_names = inmemory_parent_message._WORKER_MESSAGE_OWNERSHIP_MODULE_NAMES
    assert isinstance(module_names, tuple)
    assert module_names == tuple(sorted(module_names))
    assert module_names == (
        "Virus_Scan.scheduler.workers.inmemory_parent_state",
        "Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message",
    )
    assert all(not isinstance(name, ModuleType) for name in module_names)
