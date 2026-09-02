from collections.abc import Mapping

from Virus_Scan.models.graph import build_method_graph
from Virus_Scan.runtime.graph_state import graph_node_snapshot, reset_graph_state


class HostileMethodMapping(Mapping):
    def __init__(self, values):
        self._values = dict(values)

    def __bool__(self):
        raise RuntimeError("truthiness should not be probed")

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def items(self):
        return self._values.items()


class HostileItemsMapping(Mapping):
    def __bool__(self):
        raise RuntimeError("truthiness should not be probed")

    def __getitem__(self, key):
        raise KeyError(key)

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 1

    def items(self):
        raise RuntimeError("items unavailable")


class HostileMethodName:
    def __bool__(self):
        raise RuntimeError("truthiness should not be probed")

    def __str__(self):
        raise RuntimeError("name unavailable")


def test_build_method_graph_accepts_exact_dict_without_truthiness_probe():
    reset_graph_state()

    methods = {
        "public void Run() {": 'Process.Start("cmd.exe");',
    }

    build_method_graph("sample.cs", methods)

    method_snapshot = graph_node_snapshot("sample.cs::public void Run() {")
    process_snapshot = graph_node_snapshot("process_exec")
    assert method_snapshot is not None
    assert process_snapshot is not None


def test_build_method_graph_handles_unreadable_mapping_without_default_clean_crash():
    reset_graph_state()

    build_method_graph("sample.cs", HostileItemsMapping())

    assert graph_node_snapshot("sample.cs::anything") is None


def test_build_method_graph_rejects_caller_owned_mapping_without_method_hooks():
    reset_graph_state()

    methods = HostileMethodMapping({
        "public void Safe() {": 'Assembly.Load(payload);',
    })

    build_method_graph("sample.cs", methods)

    assert graph_node_snapshot("sample.cs::public void Safe() {") is None
    assert graph_node_snapshot("assembly_load") is None


def test_build_method_graph_skips_unreadable_exact_dict_method_names_without_crashing():
    reset_graph_state()

    methods = {
        HostileMethodName(): 'Process.Start("cmd.exe");',
        "public void Safe() {": 'Assembly.Load(payload);',
    }

    build_method_graph("sample.cs", methods)

    assert graph_node_snapshot("sample.cs::public void Safe() {") is not None
    assert graph_node_snapshot("assembly_load") is not None
