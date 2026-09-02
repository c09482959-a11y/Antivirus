"""Stage 1795: binary graph/evasion boundaries avoid truthiness hooks."""
from __future__ import annotations

from Virus_Scan.scanners.binary_behavior_detectors import detect_evasion_signals
from Virus_Scan.scanners.binary_graph_context import binary_node_edge_status


class _HostileBoolNode:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("node truthiness executed")


class _HostileEdgePayload:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("edge truthiness executed")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("edge length executed")


class _GraphNodeReturningHostileEdge:
    def edges(self):
        return _HostileEdgePayload()


class _HostileTagContainer:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("tag truthiness executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("tag iteration executed")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("tag length executed")


class _HostileYaraContainer(_HostileTagContainer):
    pass


def test_evasion_node_truthiness_is_not_invoked_before_graph_probe() -> None:
    _HostileBoolNode.reset()
    score = detect_evasion_signals(["process_exec"], node=_HostileBoolNode())
    assert score >= 0.0
    assert _HostileBoolNode.touched == 0


def test_graph_edge_payload_truthiness_is_not_invoked() -> None:
    _HostileEdgePayload.reset()
    assert binary_node_edge_status(_GraphNodeReturningHostileEdge()) == ("probe_error", False)
    assert _HostileEdgePayload.touched == 0


def test_evasion_tag_and_yara_container_truthiness_are_not_invoked() -> None:
    _HostileTagContainer.reset()
    _HostileYaraContainer.reset()
    score = detect_evasion_signals(_HostileTagContainer(), node=None)
    assert score >= 0.0
    assert _HostileTagContainer.touched == 0
    assert _HostileYaraContainer.touched == 0
