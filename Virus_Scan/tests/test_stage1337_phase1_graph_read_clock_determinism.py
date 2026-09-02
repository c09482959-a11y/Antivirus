import time
from pathlib import Path

from Virus_Scan.models import graph as graph_model
from Virus_Scan.runtime.graph_state import graph_owner, reset_graph_state


def test_stage1337_graph_read_path_does_not_invent_wall_clock_last_seen():
    reset_graph_state()
    owner = graph_owner()
    owner.graph["legacy_missing_last_seen"] = {
        "edges": set(),
        "edge_time": {},
        "weights": {},
        "types": {},
        "risk": 0.0,
        "attention": 0.0,
        "tags": set(),
    }

    first = graph_model.get_graph_node("legacy_missing_last_seen")
    time.sleep(0.01)
    second = graph_model.get_graph_node("legacy_missing_last_seen")

    assert first is not None
    assert second is not None
    assert first["last_seen"] is None
    assert second["last_seen"] is None


def test_stage1337_graph_model_source_has_no_read_side_wall_clock_default():
    graph_dir = Path(graph_model.__file__).parent
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(graph_dir.glob("*.py")))

    assert "import time" not in source
    assert "time.time()" not in source
    assert "data.get('last_seen', time.time())" not in source
